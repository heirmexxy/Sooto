// Statement verification: is this statement internally consistent, and does it
// show the patterns that edited or padded statements usually show?
//
// Lenders, landlords, universities and consulates all receive bank statements
// they cannot check. The single most reliable cheap test is arithmetic: on a
// real statement, every row's balance equals the previous balance plus the
// row's amount. Editing an amount or a balance in a PDF or spreadsheet almost
// always breaks that chain somewhere, unless the editor recomputes every later
// row, which forgers rarely do and which the other checks then catch.
//
// What this module does NOT claim: that the bank issued the statement. A
// statement that passes is "consistent", trust level L1. Only a live connection
// (L2) or the bank's own signature (L3) says more.
import { round2 } from "../data.ts";
import type { ParsedStatement, StatementRow } from "../providers/statement.ts";

export type Verdict = "consistent" | "inconsistent" | "unverifiable";

export interface Finding {
  check: string;
  severity: "info" | "warning" | "critical";
  message: string;
  lines?: number[];
}

export interface StatementVerification {
  verdict: Verdict;
  trust_level: "L1";
  rows: number;
  period: { from?: string; to?: string };
  opening_balance?: number;
  closing_balance?: number;
  totals: { money_in: number; money_out: number };
  balance_breaks: number;
  findings: Finding[];
  summary: string;
}

/** Tolerance for rounding in printed balances. */
const EPSILON = 0.011;

export function verifyStatement(statement: ParsedStatement, opts: { today?: string } = {}): StatementVerification {
  const { rows } = statement;
  const findings: Finding[] = [];
  const today = opts.today ?? new Date().toISOString().slice(0, 10);

  const moneyIn = round2(rows.filter((r) => r.amount > 0).reduce((s, r) => s + r.amount, 0));
  const moneyOut = round2(rows.filter((r) => r.amount < 0).reduce((s, r) => s + r.amount, 0));

  // 1. Running balance.
  const breakLines: number[] = [];
  let checkedPairs = 0;
  for (let i = 1; i < rows.length; i++) {
    const prev = rows[i - 1]!;
    const cur = rows[i]!;
    if (prev.balance_after === undefined || cur.balance_after === undefined) continue;
    checkedPairs++;
    if (Math.abs(prev.balance_after + cur.amount - cur.balance_after) > EPSILON) breakLines.push(cur.line);
  }
  if (breakLines.length) {
    findings.push({
      check: "running_balance",
      severity: "critical",
      message: `${breakLines.length} row(s) where the balance does not equal the previous balance plus the amount. Edited amounts or balances usually show up here.`,
      lines: breakLines.slice(0, 50),
    });
  } else if (checkedPairs) {
    findings.push({ check: "running_balance", severity: "info", message: `All ${checkedPairs} consecutive balance pairs reconcile.` });
  }

  // 2. Totals against the first and last balance.
  if (statement.opening_balance !== undefined && statement.closing_balance !== undefined && rows.every((r) => r.balance_after !== undefined)) {
    const expected = round2(statement.opening_balance + moneyIn + moneyOut);
    if (Math.abs(expected - statement.closing_balance) > EPSILON) {
      findings.push({
        check: "totals",
        severity: "critical",
        message: `Opening balance plus money in and out is ${expected}, but the closing balance is ${statement.closing_balance}.`,
      });
    }
  }

  // 3. Dates.
  const outOfOrder = rows.filter((r, i) => i > 0 && r.date < rows[i - 1]!.date).map((r) => r.line);
  if (outOfOrder.length) {
    findings.push({ check: "date_order", severity: "warning", message: "Rows are not in date order. Real exports are sorted; inserted rows often are not.", lines: outOfOrder.slice(0, 50) });
  }
  const future = rows.filter((r) => r.date > today).map((r) => r.line);
  if (future.length) findings.push({ check: "future_dates", severity: "critical", message: "Rows are dated after today.", lines: future });

  // 4. Exact duplicates (same date, amount, description and balance) are a copy-paste sign.
  const seen = new Map<string, number>();
  const dupLines: number[] = [];
  for (const r of rows) {
    const key = [r.date, r.amount, r.description ?? "", r.balance_after ?? ""].join("|");
    if (seen.has(key)) dupLines.push(r.line);
    else seen.set(key, r.line);
  }
  if (dupLines.length) findings.push({ check: "duplicates", severity: "warning", message: "Identical rows (same date, amount, description and balance).", lines: dupLines.slice(0, 50) });

  // 5. Padding: money that arrives shortly before the statement ends, or arrives and leaves again quickly.
  findings.push(...paddingFindings(rows));

  // 6. Injection attempts in narrations.
  const injected = rows.filter((r) => r.untrusted_flags?.some((f) => f !== "url")).map((r) => r.line);
  if (injected.length) {
    findings.push({
      check: "instruction_text",
      severity: "warning",
      message: "Narrations contain text that reads like instructions to an AI. Treated as data only; worth a human look.",
      lines: injected,
    });
  }

  if (statement.skipped.length) {
    findings.push({ check: "unreadable_rows", severity: "warning", message: `${statement.skipped.length} row(s) could not be read.`, lines: statement.skipped.map((s) => s.line).slice(0, 50) });
  }

  const critical = findings.some((f) => f.severity === "critical");
  const verdict: Verdict = critical ? "inconsistent" : checkedPairs === 0 ? "unverifiable" : "consistent";
  const summary =
    verdict === "consistent"
      ? "The statement is internally consistent. This does not prove the bank issued it (trust level L1)."
      : verdict === "inconsistent"
        ? "The statement is internally inconsistent. Do not rely on it without the original from the bank."
        : "The statement has no running balance to check, so its consistency cannot be verified.";

  return {
    verdict,
    trust_level: "L1",
    rows: rows.length,
    period: { from: statement.from, to: statement.to },
    opening_balance: statement.opening_balance,
    closing_balance: statement.closing_balance,
    totals: { money_in: moneyIn, money_out: moneyOut },
    balance_breaks: breakLines.length,
    findings,
    summary,
  };
}

/**
 * Patterns visa officers and lenders refuse on:
 *   late_large_credit — a credit in the last 30 days of the statement that is large next to the typical credit
 *                       and makes up much of the closing balance ("funds parked to pass a check")
 *   in_and_out        — a large credit followed within 7 days by debits that take most of it back out
 */
export function paddingFindings(rows: StatementRow[]): Finding[] {
  const findings: Finding[] = [];
  const credits = rows.filter((r) => r.amount > 0);
  if (credits.length < 2) return findings;
  const sorted = credits.map((r) => r.amount).sort((a, b) => a - b);
  const median = sorted[Math.floor(sorted.length / 2)]!;
  const last = rows.at(-1)!;
  const end = Date.parse(last.date);
  const closing = last.balance_after;
  const dayMs = 86_400_000;

  const late = credits.filter(
    (r) => end - Date.parse(r.date) <= 30 * dayMs && r.amount >= 5 * median && (closing === undefined || closing <= 0 || r.amount >= 0.4 * closing),
  );
  if (late.length) {
    findings.push({
      check: "late_large_credit",
      severity: "warning",
      message: "Large credit(s) in the last 30 days of the statement, well above the usual credit size and a big share of the closing balance. Verifiers often treat this as borrowed or parked funds; the source should be explained.",
      lines: late.map((r) => r.line),
    });
  }

  const roundTrips: number[] = [];
  for (const c of credits) {
    if (c.amount < 3 * median) continue;
    const t0 = Date.parse(c.date);
    const outflow = rows
      .filter((r) => r.amount < 0 && Date.parse(r.date) >= t0 && Date.parse(r.date) - t0 <= 7 * dayMs && r.line !== c.line)
      .reduce((s, r) => s - r.amount, 0);
    if (outflow >= 0.8 * c.amount) roundTrips.push(c.line);
  }
  if (roundTrips.length) {
    findings.push({
      check: "in_and_out",
      severity: "warning",
      message: "Large credit(s) followed within 7 days by debits taking most of the money back out.",
      lines: roundTrips,
    });
  }
  return findings;
}
