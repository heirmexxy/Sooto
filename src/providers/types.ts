// The provider layer: every source of financial data Sooto can read, behind one
// interface. Enable Banking (Europe, PSD2) was the only source in the code Sooto
// started from; African coverage needs several, because no single rail reaches
// everyone:
//
//   statement   — CSV or text exports of any bank or wallet statement (works today, everywhere)
//   enablebanking — European banks via PSD2 (kept from the original code)
//   mono, stitch — African open-banking aggregators (adapters to come)
//   nibss_ob    — Nigeria's open-banking APIs via the NIBSS registry (when licensed and live)
//   sms_alerts  — bank SMS alerts forwarded by a companion app, with the user's permission (to come)
//
// Every provider hands back the same normalized shapes, so proofs, verification
// and fraud checks never need to know where the data came from. What does differ
// is how much a verifier should trust it, which is why each source carries an
// OFP trust level.
import type { SimpleTransaction } from "../data.ts";

export type ProviderId = "statement" | "enablebanking" | "mono" | "stitch" | "nibss_ob" | "sms_alerts";

/**
 * How much a verifier can rely on data from a source (Open Financial Proof §4):
 *   L1 — a document the subject supplied, checked for internal consistency only
 *   L2 — read live from the institution over an authenticated, consented connection
 *   L3 — signed by the institution itself
 */
export type TrustLevel = "L1" | "L2" | "L3";

export interface ProviderCapabilities {
  balances: boolean;
  transactions: boolean;
  /** Real-time notifications instead of polling. */
  push: boolean;
  /** Can move money. No Sooto provider does; the field exists so that adding one is a visible decision. */
  payments: false;
  trust_level: TrustLevel;
}

export interface NormalizedAccount {
  /** Stable id within Sooto. */
  uid: string;
  provider: ProviderId;
  institution?: string;
  /** Account number, IBAN or wallet id, as the source reports it. */
  account_ref?: string;
  holder_name?: string;
  currency: string;
}

export interface NormalizedTransaction extends SimpleTransaction {
  /** Pattern ids from the injection guard when the counterparty or description looked like an instruction. */
  untrusted_flags?: string[];
}

export interface FinancialProvider {
  id: ProviderId;
  capabilities: ProviderCapabilities;
  listAccounts(): Promise<NormalizedAccount[]>;
  getTransactions(accountUid: string, range: { from: string; to: string }): Promise<NormalizedTransaction[]>;
}

export const PROVIDER_TRUST: Record<ProviderId, TrustLevel> = {
  statement: "L1",
  sms_alerts: "L1",
  enablebanking: "L2",
  mono: "L2",
  stitch: "L2",
  nibss_ob: "L2",
};
