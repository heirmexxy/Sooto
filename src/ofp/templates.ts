// Proof templates: what a verifier gets to see for each use case.
//
// The rule every template follows (SPEC §3, minimal disclosure): answer the
// verifier's threshold question with yes/no, and give bands rather than exact
// figures, unless the subject explicitly chooses to disclose exact numbers.
// Risk signals the verifier would care about (padding, borrowed funds) are
// always included: a proof that hid them would be worth less to every verifier,
// and so to every honest subject too.
import { round2 } from "../data.ts";
import type { StatementRow } from "../providers/statement.ts";
import { paddingFindings } from "../verify/statement.ts";
import { cashflowProfile, dailyBalances, minBalanceOver, type CashflowProfile } from "./metrics.ts";

const DAY = 86_400_000;

/** Coarse band for an amount, so a proof can say "about how much" without the exact number. */
export function band(amount: number): string {
  const edges = [0, 50_000, 100_000, 250_000, 500_000, 1_000_000, 2_500_000, 5_000_000, 10_000_000, 25_000_000, 50_000_000, 100_000_000];
  if (amount < 0) return "below 0";
  for (let i = edges.length - 1; i >= 0; i--) {
    if (amount >= edges[i]!) {
      const next = edges[i + 1];
      return next ? `${edges[i]!.toLocaleString("en")}–${next.toLocaleString("en")}` : `${edges[i]!.toLocaleString("en")}+`;
    }
  }
  return "0";
}

export interface CashflowParams {
  currency: string;
  /** Answer "is average monthly inflow at least this much?". */
  min_avg_monthly_inflow?: number;
  /** Include exact figures. Off by default. */
  disclose_exact?: boolean;
}

export function cashflowClaims(rows: StatementRow[], params: CashflowParams, opening?: number): { claims: Record<string, unknown>; profile: CashflowProfile } {
  const profile = cashflowProfile(rows, { opening });
  const claims: Record<string, unknown> = {
    currency: params.currency,
    period: { from: profile.from, to: profile.to },
    months_covered: profile.months.length,
    active_months: profile.active_months,
    avg_monthly_inflow_band: band(profile.avg_monthly_inflow),
    inflow_consistency: profile.inflow_consistency,
    distinct_payers_band: profile.distinct_payers >= 5 ? "5+" : profile.distinct_payers >= 2 ? "2-4" : String(profile.distinct_payers),
    top_payer_share_band: profile.top_payer_share >= 0.8 ? "80%+" : profile.top_payer_share >= 0.5 ? "50-80%" : "under 50%",
  };
  if (params.min_avg_monthly_inflow !== undefined) {
    claims.min_avg_monthly_inflow = params.min_avg_monthly_inflow;
    claims.meets_min_avg_monthly_inflow = profile.avg_monthly_inflow >= params.min_avg_monthly_inflow;
  }
  if (params.disclose_exact) {
    claims.exact = {
      avg_monthly_inflow: profile.avg_monthly_inflow,
      median_monthly_inflow: profile.median_monthly_inflow,
      months: profile.months,
      balance: profile.balance,
    };
  }
  return { claims, profile };
}

export interface FundsHeldParams {
  /** Amount that must have been held, in `currency`. */
  amount: number;
  currency: string;
  /** Consecutive days it must have been held. 28 matches the UK student and skilled-worker rule. */
  days?: number;
  /** Last day of the window, ISO date. Defaults to the last day of the data. */
  end_date?: string;
  /** When the statement currency differs from `currency`: units of `currency` per unit of statement currency, and where the rate came from. */
  fx?: { rate: number; source: string; date: string };
  disclose_exact?: boolean;
}

/**
 * "Did the account hold at least `amount` at the end of every one of the `days` days ending on `end_date`?"
 * The visa proof-of-funds question, and the shape of most "proof of funds" checks.
 */
export function fundsHeldClaims(rows: StatementRow[], statementCurrency: string, params: FundsHeldParams, opening?: number): Record<string, unknown> {
  const days = params.days ?? 28;
  if (!Number.isInteger(days) || days < 1 || days > 366) throw new Error("days must be a whole number from 1 to 366.");
  if (!rows.length) throw new Error("No transactions to prove from.");
  const end = params.end_date ?? rows.at(-1)!.date;
  const start = new Date(Date.parse(end) - (days - 1) * DAY).toISOString().slice(0, 10);
  const dataFrom = rows[0]!.date;
  const dataTo = rows.at(-1)!.date;
  if (end > dataTo) throw new Error(`end_date ${end} is after the last day the data covers (${dataTo}).`);
  if (start < dataFrom && opening === undefined) throw new Error(`The window starts ${start}, before the data begins (${dataFrom}), and the opening balance is unknown.`);

  const sameCurrency = statementCurrency.toUpperCase() === params.currency.toUpperCase();
  if (!sameCurrency && !params.fx) throw new Error(`The statement is in ${statementCurrency}; give an fx rate and its source to prove an amount in ${params.currency}.`);
  const rate = sameCurrency ? 1 : params.fx!.rate;

  const daily = dailyBalances(rows, start < dataFrom ? start : dataFrom, end, opening);
  const min = minBalanceOver(daily, end, days);
  if (min === undefined) throw new Error("Some days in the window have no known balance; the statement needs a balance column.");
  const minConverted = round2(min * rate);

  const windowRows = rows.filter((r) => r.date >= start && r.date <= end);
  const risk = paddingFindings(rows.filter((r) => r.date <= end)).map((f) => f.check);

  const claims: Record<string, unknown> = {
    question: `Held at least ${params.amount} ${params.currency.toUpperCase()} at the end of each of ${days} consecutive days ending ${end}`,
    held: minConverted >= params.amount,
    amount: params.amount,
    currency: params.currency.toUpperCase(),
    days,
    window: { from: start, to: end },
    lowest_balance_band: band(minConverted),
    transactions_in_window: windowRows.length,
    risk_signals: risk,
  };
  if (!sameCurrency) claims.fx = { from: statementCurrency.toUpperCase(), to: params.currency.toUpperCase(), ...params.fx };
  if (params.disclose_exact) claims.exact = { lowest_balance: minConverted };
  return claims;
}
