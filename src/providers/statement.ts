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
  /** Fees and levies charged on this row, already included in `amount`. */
  fees?: number;
}

/** Internal: a row whose direction the statement did not state, with the candidates to choose between. */
interface PendingSign {
  row: StatementRow;
  /** Net effect on the balance if money came in, and if it went out. */
  asCredit: number;
  asDebit: number;
  fromName?: string;
  toName?: string;
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
  /** Lines above the header row (bank, holder, account number, period), as written. Third-party text. */
  preamble: string[];
  /** Rows the statement itself marks as failed, reversed or pending: they moved no money and are left out. */
  excluded: Array<{ line: number; status: string }>;
  warnings: string[];
}

export type Field = "date" | "value_date" | "description" | "debit" | "credit" | "amount" | "balance" | "balance_before" | "fees" | "status" | "reference" | "direction" | "counterparty" | "from_name" | "to_name";

// Header names seen on African bank and wallet exports, lower-cased. Order matters within a field: the first match wins.
const HEADERS: Record<Field, string[]> = {
  date: ["transaction date", "trans date", "txn date", "trans. date", "tran date", "posting date", "post date", "booking date", "completion time", "date & time", "date/time", "transaction time", "date"],
  value_date: ["value date", "val date", "value dt"],
  description: ["narration", "narrative", "description", "transaction details", "details", "particulars", "remarks", "memo", "transaction description"],
  debit: ["debit", "debits", "withdrawal", "withdrawals", "withdrawn", "money out", "paid out", "debit amount", "dr", "debit(₦)", "debit (ngn)", "debit amount (ngn)"],
  credit: ["credit", "credits", "deposit", "deposits", "lodgement", "lodgements", "money in", "paid in", "credit amount", "cr", "credit(₦)", "credit (ngn)", "credit amount (ngn)"],
  amount: ["amount", "transaction amount", "txn amount", "amount (ngn)", "amount(₦)"],
  balance: ["balance", "running balance", "closing balance", "balance after", "bal after", "bal. after", "available balance", "ledger balance", "balance (ngn)", "balance(₦)"],
  balance_before: ["balance before", "bal before", "bal. before", "opening bal", "previous balance"],
  // Every fee-like column is summed (MTN MoMo Ghana shows FEES and E-LEVY separately).
  fees: ["fees", "fee", "charges", "charge", "e-levy", "elevy", "levy", "tax", "transaction cost"],
  // Mobile-money statements list failed and reversed attempts; those rows moved no money.
  status: ["transaction status", "trans. status", "txn status", "status"],
  reference: ["reference", "ref", "ref no", "reference number", "receipt no", "receipt no.", "transaction ref", "transaction reference", "session id", "transaction id", "financial transaction id", "f_id", "trans id", "txn id"],
  direction: ["dr/cr", "cr/dr", "type", "transaction type", "trans. type", "trans type", "debit/credit"],
  counterparty: ["counterparty", "beneficiary", "sender", "recipient", "payee", "other party", "from/to", "from / to", "party", "account name"],
  from_name: ["from name", "sender name"],
  to_name: ["to name", "recipient name", "receiver name", "beneficiary name"],
};

/** Fields that may come from several columns, whose values are added up. */
const MULTI: ReadonlySet<Field> = new Set(["fees"]);
const DEBIT_WORDS = /^(dr|d|debit|withdraw|out|cash[ _-]?out|payment|paid|sent|send|transfer[ _-]?out|purchase|bill|airtime|charge)/;
const CREDIT_WORDS = /^(cr|c|credit|deposit|in\b|cash[ _-]?in|received|receive|transfer[ _-]?in|refund|reversal|interest)/;
const NO_MONEY_MOVED = /^(failed|failure|declined|rejected|reversed|cancell?ed|pending|expired|timed? ?out|unsuccessful|error)/;

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

/** Extra column indices for MULTI fields, keyed by the header map they belong to. */
const extraColumns = new WeakMap<object, Partial<Record<Field, number[]>>>();

function matchHeader(cells: string[]): Partial<Record<Field, number>> | undefined {
  const lower = cells.map((c) => c.toLowerCase().replace(/\s+/g, " ").trim());
  const map: Partial<Record<Field, number>> = {};
  const extra: Partial<Record<Field, number[]>> = {};
  extraColumns.set(map, extra);
  const used = new Set<number>();
  for (const field of Object.keys(HEADERS) as Field[]) {
    if (MULTI.has(field)) {
      const idxs = lower.map((c, i) => (!used.has(i) && HEADERS[field].includes(c) ? i : -1)).filter((i) => i >= 0);
      if (idxs.length) {
        map[field] = idxs[0];
        extra[field] = idxs.slice(1);
        for (const i of idxs) used.add(i);
      }
      continue;
    }
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
      excluded: [],
      preamble: [],
      warnings: ["No header row with a date column and an amount, debit or credit column was found in the first 60 lines."],
    };
  }
  const headerCells = splitLine(lines[headerLine]!, delimiter);
  const columns: Record<string, string> = {};
  for (const [field, idx] of Object.entries(map)) columns[field] = headerCells[idx!]!;

  const rows: StatementRow[] = [];
  const excluded: ParsedStatement["excluded"] = [];
  const pending: PendingSign[] = [];
  let firstBefore: number | undefined;
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
    const status = get("status")?.trim().toLowerCase();
    if (status && NO_MONEY_MOVED.test(status)) {
      excluded.push({ line: i + 1, status: get("status")!.trim() });
      continue;
    }
    const extra = extraColumns.get(map!) ?? {};
    const fees = round2(
      [map.fees, ...(extra.fees ?? [])]
        .filter((idx): idx is number => idx !== undefined)
        .reduce((sum, idx) => sum + Math.abs(parseAmount(cells[idx]) ?? 0), 0),
    );
    let principal: number | undefined;
    let sign: 1 | -1 | 0 = 0;
    if (map.debit !== undefined || map.credit !== undefined) {
      const debit = parseAmount(get("debit"));
      const credit = parseAmount(get("credit"));
      if (debit !== undefined && debit !== 0) [principal, sign] = [Math.abs(debit), -1];
      else if (credit !== undefined && credit !== 0) [principal, sign] = [Math.abs(credit), 1];
      else if (debit === 0 || credit === 0) [principal, sign] = [0, 1];
    }
    if (principal === undefined && map.amount !== undefined) {
      const a = parseAmount(get("amount"));
      if (a !== undefined) {
        principal = Math.abs(a);
        const dir = get("direction")?.trim().toLowerCase();
        if (a < 0) sign = -1;
        else if (dir && DEBIT_WORDS.test(dir)) sign = -1;
        else if (dir && CREDIT_WORDS.test(dir)) sign = 1;
      }
    }
    if (principal === undefined) {
      skipped.push({ line: i + 1, reason: "No readable amount" });
      continue;
    }
    const balance = parseAmount(get("balance"));
    const before = parseAmount(get("balance_before"));
    const asCredit = round2(principal - fees);
    const asDebit = round2(-(principal + fees));
    // Balance before and after on the same row settle the direction outright.
    if (before !== undefined && balance !== undefined) {
      const delta = round2(balance - before);
      if (Math.abs(delta - asCredit) <= 0.011 && Math.abs(delta - asDebit) > 0.011) sign = 1;
      else if (Math.abs(delta - asDebit) <= 0.011) sign = -1;
    }
    const amount = sign === -1 ? asDebit : asCredit;
    const fromName = get("from_name");
    const toName = get("to_name");
    const desc = inspectUntrusted(get("description") ?? [get("direction"), sign === -1 ? toName : fromName].filter(Boolean).join(" "));
    const party = inspectUntrusted(get("counterparty") ?? (sign === -1 ? toName : sign === 1 ? fromName : undefined));
    const flags = [...new Set([...desc.flags, ...party.flags])];
    const valueDate = parseDate(get("value_date"));
    const row: StatementRow = {
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
      ...(fees ? { fees } : {}),
      ...(flags.length ? { untrusted_flags: flags } : {}),
    };
    if (before !== undefined && i === headerLine + 1) firstBefore = before;
    rows.push(row);
    if (sign === 0) pending.push({ row, asCredit, asDebit, fromName, toName });
  }

  if (pending.length) {
    const n = inferDirections(rows, pending);
    if (n) warnings.push(`${n} row(s) did not say whether money came in or went out; the direction was taken from the running balance.`);
  }

  const reversed = shouldReverse(rows);
  if (reversed) rows.reverse();

  const first = rows[0];
  const last = rows.at(-1);
  const withBalance = rows.filter((r) => r.balance_after !== undefined).length;
  if (rows.length && withBalance === 0) warnings.push("The statement has no balance column, so it cannot be checked for consistency (verify_statement will say unverifiable).");
  else if (rows.length && withBalance < rows.length) warnings.push(`${rows.length - withBalance} of ${rows.length} rows have no balance.`);
  if (skipped.length) warnings.push(`${skipped.length} line(s) looked like data but could not be read; see skipped.`);
  if (excluded.length) warnings.push(`${excluded.length} failed, reversed or pending transaction(s) were left out; they moved no money.`);

  return {
    rows,
    currency,
    columns,
    opening_balance: first?.balance_after !== undefined ? round2(first.balance_after - first.amount) : reversed ? undefined : firstBefore,
    closing_balance: last?.balance_after,
    from: rows.length ? rows.reduce((a, r) => (r.date < a ? r.date : a), rows[0]!.date) : undefined,
    to: rows.length ? rows.reduce((a, r) => (r.date > a ? r.date : a), rows[0]!.date) : undefined,
    reversed,
    skipped,
    excluded,
    preamble: lines
      .slice(0, headerLine)
      .map((l) => splitLine(l, delimiter).filter(Boolean).join(" "))
      .filter(Boolean)
      .slice(0, 12),
    warnings,
  };
}

/**
 * For rows that did not say which way the money went, pick the direction the running balance agrees with.
 * The listing order is unknown at this point too (newest or oldest first), so both orders are tried and the
 * one with fewer breaks wins. Returns how many rows were decided.
 */
function inferDirections(rows: StatementRow[], pending: PendingSign[]): number {
  const byRow = new Map(pending.map((p) => [p.row, p]));
  const attempt = (ordered: StatementRow[]) => {
    const choice = new Map<StatementRow, number>();
    let breaks = 0;
    for (let i = 0; i < ordered.length; i++) {
      const r = ordered[i]!;
      const p = byRow.get(r);
      const prev = i > 0 ? ordered[i - 1]!.balance_after : undefined;
      const amountOf = (row: StatementRow) => choice.get(row) ?? row.amount;
      if (p && prev !== undefined && r.balance_after !== undefined) {
        const ok = (a: number) => Math.abs(prev + a - r.balance_after!) <= 0.011;
        choice.set(r, ok(p.asDebit) && !ok(p.asCredit) ? p.asDebit : p.asCredit);
      } else if (p && i === 0 && ordered.length > 1) {
        // The first row has no previous balance; decide it from the next row instead.
        const next = ordered[1]!;
        if (r.balance_after !== undefined && next.balance_after !== undefined && !byRow.has(next)) choice.set(r, p.asCredit);
      }
      if (prev !== undefined && r.balance_after !== undefined && Math.abs(prev + amountOf(r) - r.balance_after) > 0.011) breaks++;
    }
    return { choice, breaks };
  };
  const forward = attempt(rows);
  const backward = attempt([...rows].reverse());
  const best = backward.breaks < forward.breaks ? backward : forward;
  for (const [row, amount] of best.choice) {
    const p = byRow.get(row)!;
    row.amount = amount;
    const party = inspectUntrusted(amount < 0 ? p.toName : p.fromName);
    if (!row.counterparty && party.text) row.counterparty = party.text;
  }
  return best.choice.size;
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
