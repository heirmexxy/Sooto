// Cash-flow metrics computed from normalized transactions. These are the facts
// Open Financial Proof claims are made from. They are computed here, in plain
// deterministic code, never by a language model: a proof must say the same
// thing every time it is computed from the same data.
import { round2 } from "../data.ts";

export interface MetricRow {
  date: string;
  amount: number;
  balance_after?: number;
  counterparty?: string;
  description?: string;
}

export interface MonthFlow {
  month: string;
  money_in: number;
  money_out: number;
  credits: number;
}

export interface CashflowProfile {
  from: string;
  to: string;
  days_covered: number;
  months: MonthFlow[];
  /** Calendar months in the period with at least one credit. */
  active_months: number;
  avg_monthly_inflow: number;
  median_monthly_inflow: number;
  /** Coefficient of variation of monthly inflow: 0 is perfectly steady. Undefined with fewer than 2 months. */
  inflow_variation?: number;
  inflow_consistency: "high" | "medium" | "low" | "insufficient_data";
  distinct_payers: number;
  /** Share of all inflow that came from the single largest payer, 0–1. */
  top_payer_share: number;
  balance?: { min: number; avg: number; max: number; closing: number };
}

const DAY = 86_400_000;
const addDays = (iso: string, n: number) => new Date(Date.parse(iso) + n * DAY).toISOString().slice(0, 10);

/** A name for who paid, from the counterparty or, failing that, the narration with numbers and noise removed. */
export function payerKey(r: MetricRow): string {
  const base = (r.counterparty || r.description || "unknown").toLowerCase();
  return (
    base
      .replace(/\b(trf|transfer|nip|frm|from|to|via|ref|inward|outward|credit|cr|mob|web|ussd|nibss|instant|payment)\b/g, " ")
      .replace(/[^a-z\s]/g, " ")
      .replace(/\s+/g, " ")
      .trim()
      .split(" ")
      .slice(0, 3)
      .join(" ") || "unknown"
  );
}

/**
 * End-of-day balance for every calendar day from `from` to `to`, carrying the last known balance forward over days
 * without transactions. Rows must be in chronological order. Days before the first balance use `opening`.
 */
export function dailyBalances(rows: MetricRow[], from: string, to: string, opening?: number): Map<string, number> {
  const endOfDay = new Map<string, number>();
  for (const r of rows) if (r.balance_after !== undefined) endOfDay.set(r.date, r.balance_after);
  const out = new Map<string, number>();
  let current = opening;
  for (let d = from; d <= to; d = addDays(d, 1)) {
    if (endOfDay.has(d)) current = endOfDay.get(d);
    if (current !== undefined) out.set(d, current);
  }
  return out;
}

/** Lowest end-of-day balance over the `days` days ending on `end` (inclusive), or undefined when any day is unknown. */
export function minBalanceOver(daily: Map<string, number>, end: string, days: number): number | undefined {
  let min = Infinity;
  for (let i = 0; i < days; i++) {
    const v = daily.get(addDays(end, -i));
    if (v === undefined) return undefined;
    min = Math.min(min, v);
  }
  return min;
}

export function cashflowProfile(rows: MetricRow[], opts: { from?: string; to?: string; opening?: number } = {}): CashflowProfile {
  if (!rows.length) throw new Error("No transactions to profile.");
  const from = opts.from ?? rows[0]!.date;
  const to = opts.to ?? rows.at(-1)!.date;
  const inRange = rows.filter((r) => r.date >= from && r.date <= to);

  const months = new Map<string, MonthFlow>();
  for (let d = from.slice(0, 7); d <= to.slice(0, 7); ) {
    months.set(d, { month: d, money_in: 0, money_out: 0, credits: 0 });
    const [y, m] = d.split("-").map(Number) as [number, number];
    d = m === 12 ? `${y + 1}-01` : `${y}-${String(m + 1).padStart(2, "0")}`;
  }
  const payers = new Map<string, number>();
  for (const r of inRange) {
    const m = months.get(r.date.slice(0, 7))!;
    if (r.amount > 0) {
      m.money_in += r.amount;
      m.credits += 1;
      const k = payerKey(r);
      payers.set(k, (payers.get(k) ?? 0) + r.amount);
    } else m.money_out += r.amount;
  }
  const flows = [...months.values()].map((m) => ({ ...m, money_in: round2(m.money_in), money_out: round2(m.money_out) }));
  const inflows = flows.map((m) => m.money_in);
  const total = inflows.reduce((s, v) => s + v, 0);
  const avg = inflows.length ? total / inflows.length : 0;
  const sorted = [...inflows].sort((a, b) => a - b);
  const median = sorted.length ? (sorted.length % 2 ? sorted[(sorted.length - 1) / 2]! : (sorted[sorted.length / 2 - 1]! + sorted[sorted.length / 2]!) / 2) : 0;
  let variation: number | undefined;
  if (inflows.length >= 2 && avg > 0) {
    const sd = Math.sqrt(inflows.reduce((s, v) => s + (v - avg) ** 2, 0) / inflows.length);
    variation = round2(sd / avg);
  }
  const consistency = variation === undefined ? "insufficient_data" : variation <= 0.25 ? "high" : variation <= 0.6 ? "medium" : "low";
  const topPayer = Math.max(0, ...payers.values());

  let balance: CashflowProfile["balance"];
  const daily = dailyBalances(rows, from, to, opts.opening);
  if (daily.size) {
    const values = [...daily.values()];
    balance = {
      min: round2(Math.min(...values)),
      avg: round2(values.reduce((s, v) => s + v, 0) / values.length),
      max: round2(Math.max(...values)),
      closing: round2(values.at(-1)!),
    };
  }

  return {
    from,
    to,
    days_covered: Math.round((Date.parse(to) - Date.parse(from)) / DAY) + 1,
    months: flows,
    active_months: flows.filter((m) => m.credits > 0).length,
    avg_monthly_inflow: round2(avg),
    median_monthly_inflow: round2(median),
    inflow_variation: variation,
    inflow_consistency: consistency,
    distinct_payers: payers.size,
    top_payer_share: total > 0 ? round2(topPayer / total) : 0,
    balance,
  };
}
