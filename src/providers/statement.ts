// Statement provider: reads the CSV or text export of any bank or mobile-money
// statement and turns it into normalized transactions.
//
// This is the route that works today for every bank and wallet in Africa,
// without a licence or an aggregator contract: almost every Nigerian, Kenyan,
// Ghanaian and South African bank lets a customer download a statement, and
// M-Pesa and MoMo export one too. Data from here is trust level L1: the subject
// supplied it, so Sooto can check that it is internally consistent
// (verify/statement.ts) but cannot vouch that the bank produced it.
//
// PDF statements are converted to text before they reach this parser; the PDF
// extraction step is a separate module so that this one stays dependency-free.
//
// Nothing parsed here is written to disk. Parsed statements live in memory for
// a limited time (see sooto-tools.ts), in keeping with the rule this code base
// started from: balances and transactions are not stored.
import { createHash } from "node:crypto";
import { round2 } from "../data.ts";
import { inspectUntrusted } from "../guard/injection.ts";
import type { NormalizedTransaction } from "./types.ts";

export interface StatementRow extends NormalizedTransaction {
  /** 1-based line in the source text, so a verifier can point at the exact row. */
  line: number;
}

export interface ParsedStatement {
  rows: StatementRow[];
  currency: string;
  /** Which source column fed which field, for transparency. */
  columns: Record<string, string>;
  /** Balance before the first row, when it can be derived. */
  opening_balance?: number;
  closing_balance?: number;
  from?: string;
  to?: string;
  /** The source listed newest first and was reversed. */
  reversed: boolean;
  /** Lines that looked like data but could not be read. */
  skipped: Array<{ line: number; reason: string }>;
  warnings: string[];
}

export type Field = "date" | "value_date" | "description" | "debit" | "credit" | "amount" | "balance" | "reference" | "direction" | "counterparty";

// Header names seen on African bank and wallet exports, lower-cased. Order matters within a field: the first match wins.
const HEADERS: Record<Field, string[]> = {
  date: ["transaction date", "trans date", "txn date", "trans. date", "tran date", "posting date", "post date", "booking date", "completion time", "date"],
  value_date: ["value date", "val date", "value dt"],
  description: ["narration", "narrative", "description", "transaction details", "details", "particulars", "remarks", "memo", "transaction description"],
  debit: ["debit", "debits", "withdrawal", "withdrawals", "withdrawn", "money out", "paid out", "debit amount", "dr", "debit(₦)", "debit (ngn)", "debit amount (ngn)"],
  credit: ["credit", "credits", "deposit", "deposits", "lodgement", "lodgements", "money in", "paid in", "credit amount", "cr", "credit(₦)", "credit (ngn)", "credit amount (ngn)"],
  amount: ["amount", "transaction amount", "txn amount", "amount (ngn)", "amount(₦)"],
  balance: ["balance", "running balance", "closing balance", "balance after", "available balance", "ledger balance", "balance (ngn)", "balance(₦)"],
  reference: ["reference", "ref", "ref no", "reference number", "receipt no", "receipt no.", "transaction ref", "transaction reference", "session id"],
  direction: ["dr/cr", "cr/dr", "type", "transaction type", "debit/credit"],
  counterparty: ["counterparty", "beneficiary", "sender", "recipient", "payee", "other party", "account name"],
};

const MONTHS: Record<string, number> = { jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6, jul: 7, aug: 8, sep: 9, sept: 9, oct: 10, nov: 11, dec: 12 };

/** Which statement field a header cell names, if any. */
export function headerFieldOf(cell: string): Field | undefined {
  const c = cell.toLowerCase().replace(/\s+/g, " ").trim();
  for (const field of Object.keys(HEADERS) as Field[]) if (HEADERS[field].includes(c)) return field;
  return undefined;
}

/** Splits one delimited line, honouring double quotes. */
export function splitLine(line: string, delimiter: string): string[] {
  const out: string[] = [];
  let cur = "";
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!;
    if (quoted) {
      if (ch === '"' && line[i + 1] === '"') {
        cur += '"';
        i++;
      } else if (ch === '"') quoted = false;
      else cur += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === delimiter) {
      out.push(cur.trim());
      cur = "";
    } else cur += ch;
  }
  out.push(cur.trim());
  return out;
}

function detectDelimiter(lines: string[]): string {
  const candidates = [",", ";", "\t", "|"];
  let best = ",";
  let bestScore = 0;
  for (const d of candidates) {
    const counts = lines.slice(0, 30).map((l) => splitLine(l, d).length);
    const common = counts.filter((c) => c >= 3);
    const score = common.length * (common.length ? Math.min(...common) : 0);
    if (score > bestScore) {
      best = d;
      bestScore = score;
    }
  }
  return best;
}

/** Parses an amount as banks print it: "₦1,250,000.50", "(500.00)", "1 250,00", "500.00 DR", "-", "". */
export function parseAmount(raw: string | undefined): number | undefined {
  if (raw === undefined) return undefined;
  let s = raw.trim();
  if (!s || /^[-–—]$/.test(s) || /^n\/?a$/i.test(s)) return undefined;
  let negative = false;
  if (/^\(.*\)$/.test(s)) {
    negative = true;
    s = s.slice(1, -1);
  }
  if (/\bdr\.?$/i.test(s)) {
    negative = true;
    s = s.replace(/\bdr\.?$/i, "");
  }
  s = s.replace(/\bcr\.?$/i, "");
  s = s.replace(/[₦$€£]|NGN|KES|KSH|GHS|ZAR|UGX|TZS|RWF|XOF|XAF|EGP|USD|EUR|GBP|R(?=\s*\d)/gi, "").replace(/\s+/g, "");
  if (s.startsWith("-")) {
    negative = !negative;
    s = s.slice(1);
  }
  if (s.startsWith("+")) s = s.slice(1);
  // Decimal comma ("1.250,50" or "250,50") versus thousands comma ("1,250.50").
  if (/,\d{1,2}$/.test(s) && !/\.\d{1,2}$/.test(s)) s = s.replace(/\./g, "").replace(",", ".");
  else s = s.replace(/,/g, "");
  if (!/^\d+(\.\d+)?$/.test(s)) return undefined;
  const n = Number(s);
  return Number.isFinite(n) ? round2(negative ? -n : n) : undefined;
}

/** Parses a statement date to ISO (YYYY-MM-DD). Day-first, as African and UK banks print dates. */
export function parseDate(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  const s = raw.trim();
  const pad = (n: number) => String(n).padStart(2, "0");
  const fullYear = (y: number) => (y < 100 ? 2000 + y : y);
  const valid = (y: number, m: number, d: number) => (m >= 1 && m <= 12 && d >= 1 && d <= 31 ? `${y}-${pad(m)}-${pad(d)}` : undefined);
  let m = s.match(/^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})/);
  if (m) return valid(Number(m[1]), Number(m[2]), Number(m[3]));
  m = s.match(/^(\d{1,2})[-/.](\d{1,2})[-/.](\d{2,4})/);
  if (m) return valid(fullYear(Number(m[3])), Number(m[2]), Number(m[1]));
  m = s.match(/^(\d{1,2})[-/. ]([A-Za-z]{3,4})[A-Za-z]*[-/., ]+(\d{2,4})/);
  if (m) {
    const month = MONTHS[m[2]!.toLowerCase()];
    return month ? valid(fullYear(Number(m[3])), month, Number(m[1])) : undefined;
  }
  m = s.match(/^([A-Za-z]{3,4})[A-Za-z]*[ -](\d{1,2}),?[ -](\d{2,4})/);
  if (m) {
    const month = MONTHS[m[1]!.toLowerCase()];
    return month ? valid(fullYear(Number(m[3])), month, Number(m[2])) : undefined;
  }
  return undefined;
}

function matchHeader(cells: string[]): Partial<Record<Field, number>> | undefined {
  const lower = cells.map((c) => c.toLowerCase().replace(/\s+/g, " ").trim());
  const map: Partial<Record<Field, number>> = {};
  const used = new Set<number>();
  for (const field of Object.keys(HEADERS) as Field[]) {
    for (const name of HEADERS[field]) {
      const idx = lower.findIndex((c, i) => !used.has(i) && c === name);
      if (idx !== -1) {
        map[field] = idx;
        used.add(idx);
        break;
      }
    }
  }
  // Some exports have only a value date; use it as the date.
  if (map.date === undefined && map.value_date !== undefined) {
    map.date = map.value_date;
    delete map.value_date;
  }
  const hasMoney = map.amount !== undefined || map.debit !== undefined || map.credit !== undefined;
  return map.date !== undefined && hasMoney ? map : undefined;
}

function rowId(date: string, amount: number, description: string | undefined, balance: number | undefined, line: number): string {
  return createHash("sha256")
    .update([date, amount, description ?? "", balance ?? "", line].join("\u001f"))
    .digest("hex")
    .slice(0, 16);
}

/**
 * Parses statement text. `currency` is what the statement is in (the export rarely says);
 * it defaults to NGN because that is where Sooto starts.
 */
export function parseStatement(text: string, opts: { currency?: string } = {}): ParsedStatement {
  const currency = (opts.currency ?? "NGN").toUpperCase();
  const lines = text.replace(/^﻿/, "").split(/\r?\n/);
  const nonEmpty = lines.filter((l) => l.trim());
  const delimiter = detectDelimiter(nonEmpty);
  const warnings: string[] = [];
  const skipped: ParsedStatement["skipped"] = [];

  let headerLine = -1;
  let map: Partial<Record<Field, number>> | undefined;
  for (let i = 0; i < lines.length && i < 60; i++) {
    const found = matchHeader(splitLine(lines[i]!, delimiter));
    if (found) {
      headerLine = i;
      map = found;
      break;
    }
  }
  if (!map) {
    return {
      rows: [],
      currency,
      columns: {},
      reversed: false,
      skipped: [],
      warnings: ["No header row with a date column and an amount, debit or credit column was found in the first 60 lines."],
    };
  }
  const headerCells = splitLine(lines[headerLine]!, delimiter);
  const columns: Record<string, string> = {};
  for (const [field, idx] of Object.entries(map)) columns[field] = headerCells[idx!]!;

  const rows: StatementRow[] = [];
  for (let i = headerLine + 1; i < lines.length; i++) {
    const raw = lines[i]!;
    if (!raw.trim()) continue;
    const cells = splitLine(raw, delimiter);
    const get = (f: Field) => (map![f] !== undefined ? cells[map![f]!] : undefined);
    const date = parseDate(get("date"));
    if (!date) {
      // Totals, page footers and repeated headers have no date; only report lines that look like data.
      if (cells.filter(Boolean).length >= 3 && /\d/.test(raw) && !/total|opening|closing|brought forward|carried forward|b\/f|c\/f/i.test(raw)) {
        skipped.push({ line: i + 1, reason: "No readable date" });
      }
      continue;
    }
    let amount: number | undefined;
    if (map.debit !== undefined || map.credit !== undefined) {
      const debit = parseAmount(get("debit"));
      const credit = parseAmount(get("credit"));
      if (debit !== undefined && debit !== 0) amount = -Math.abs(debit);
      else if (credit !== undefined && credit !== 0) amount = Math.abs(credit);
      else if (debit === 0 || credit === 0) amount = 0;
    }
    if (amount === undefined && map.amount !== undefined) {
      amount = parseAmount(get("amount"));
      const dir = get("direction")?.trim().toLowerCase();
      if (amount !== undefined && dir) {
        if (/^(dr|d|debit|withdrawal|out)/.test(dir)) amount = -Math.abs(amount);
        else if (/^(cr|c|credit|deposit|in)/.test(dir)) amount = Math.abs(amount);
      }
    }
    if (amount === undefined) {
      skipped.push({ line: i + 1, reason: "No readable amount" });
      continue;
    }
    const balance = parseAmount(get("balance"));
    const desc = inspectUntrusted(get("description"));
    const party = inspectUntrusted(get("counterparty"));
    const flags = [...new Set([...desc.flags, ...party.flags])];
    const valueDate = parseDate(get("value_date"));
    rows.push({
      line: i + 1,
      id: rowId(date, amount, desc.text, balance, i + 1),
      date,
      value_date: valueDate && valueDate !== date ? valueDate : undefined,
      amount,
      currency,
      counterparty: party.text || undefined,
      description: desc.text || undefined,
      status: "BOOK",
      balance_after: balance,
      ...(flags.length ? { untrusted_flags: flags } : {}),
    });
  }

  const reversed = shouldReverse(rows);
  if (reversed) rows.reverse();

  const first = rows[0];
  const last = rows.at(-1);
  const withBalance = rows.filter((r) => r.balance_after !== undefined).length;
  if (rows.length && withBalance === 0) warnings.push("The statement has no balance column, so it cannot be checked for consistency (verify_statement will say unverifiable).");
  else if (rows.length && withBalance < rows.length) warnings.push(`${rows.length - withBalance} of ${rows.length} rows have no balance.`);
  if (skipped.length) warnings.push(`${skipped.length} line(s) looked like data but could not be read; see skipped.`);

  return {
    rows,
    currency,
    columns,
    opening_balance: first?.balance_after !== undefined ? round2(first.balance_after - first.amount) : undefined,
    closing_balance: last?.balance_after,
    from: rows.length ? rows.reduce((a, r) => (r.date < a ? r.date : a), rows[0]!.date) : undefined,
    to: rows.length ? rows.reduce((a, r) => (r.date > a ? r.date : a), rows[0]!.date) : undefined,
    reversed,
    skipped,
    warnings,
  };
}

/** Counts running-balance breaks when the rows are read in the given order. */
export function balanceBreaks(rows: Array<{ amount: number; balance_after?: number }>): number {
  let breaks = 0;
  for (let i = 1; i < rows.length; i++) {
    const prev = rows[i - 1]!.balance_after;
    const cur = rows[i]!.balance_after;
    if (prev === undefined || cur === undefined) continue;
    if (Math.abs(prev + rows[i]!.amount - cur) > 0.011) breaks++;
  }
  return breaks;
}

/**
 * Statements are listed oldest-first or newest-first, and the dates alone do not always tell (many rows share a day).
 * Read both ways and keep the order the running balance agrees with; fall back to the dates.
 */
function shouldReverse(rows: StatementRow[]): boolean {
  if (rows.length < 2) return false;
  const forward = balanceBreaks(rows);
  const backward = balanceBreaks([...rows].reverse());
  if (forward !== backward) return backward < forward;
  return rows[0]!.date > rows.at(-1)!.date;
}
