// Open Financial Proof (OFP) v0.1: the signed envelope.
//
// A proof answers a narrow question about someone's money ("did this account
// hold at least ₦3,000,000 for 28 consecutive days?") for one named verifier
// and one purpose, without handing over the transactions behind the answer.
// The format is specified in docs/ofp/SPEC.md; this file is the reference
// implementation of §5 (envelope), §6 (canonical form) and §7 (verification).
//
// Signing uses the same Ed25519 issuer key as the account attestation that
// this code base started with (attestation.ts), published at
// /.well-known/ofp-issuer. One server, one issuer identity.
import { createHash, createPublicKey, randomUUID, sign, verify, type KeyObject } from "node:crypto";
import type { TrustLevel, ProviderId } from "../providers/types.ts";

export const OFP_VERSION = "0.1";

/** Default and maximum lifetime of a proof. Financial facts go stale; a proof is a snapshot, not a licence. */
export const DEFAULT_TTL_DAYS = 30;
export const MAX_TTL_DAYS = 90;

export type ProofType = "cashflow" | "funds_held";

export interface ProofSource {
  provider: ProviderId;
  /** SHA-256 of the source document or data the claims were computed from, so a verifier holding it can match it. */
  digest?: string;
  /** Result of statement verification for L1 sources. */
  verification?: "consistent" | "inconsistent" | "unverifiable";
  period: { from: string; to: string };
}

export interface Proof {
  ofp: typeof OFP_VERSION;
  id: string;
  type: ProofType;
  issuer: string;
  /** Who the proof is for. A verifier must reject a proof addressed to someone else. */
  verifier: string;
  /** Why it was issued, e.g. "UK student visa application". Binds the proof to one use. */
  purpose: string;
  /** Name the subject gave. Marked as declared: at L1 Sooto has not checked it against an ID. */
  subject?: { declared_name?: string; name_verified: boolean };
  trust_level: TrustLevel;
  source: ProofSource;
  claims: Record<string, unknown>;
  /** Verifier-supplied value, when the verifier asked for one. Prevents replay of an old proof as a fresh answer. */
  nonce?: string;
  issued_at: number;
  expires_at: number;
}

export interface SignedProof {
  proof: Proof;
  /** Ed25519 over canonicalize(proof), base64url. */
  signature: string;
  key_id: string;
  alg: "Ed25519";
}

/**
 * Canonical JSON: object keys sorted by code point at every depth, no whitespace, undefined members dropped.
 * The same idea as RFC 8785 (JCS) for the values a proof contains (strings, finite numbers, booleans, null,
 * arrays, objects). Issuer and verifier must produce identical bytes.
 */
export function canonicalize(value: unknown): string {
  if (value === null || typeof value !== "object") {
    if (typeof value === "number" && !Number.isFinite(value)) throw new Error("Non-finite number in proof.");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((v) => (v === undefined ? "null" : canonicalize(v))).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalize(v)}`).join(",")}}`;
}

export function digest(text: string): string {
  return `sha256:${createHash("sha256").update(text, "utf8").digest("hex")}`;
}

export function newProof(input: Omit<Proof, "ofp" | "id" | "issued_at" | "expires_at"> & { ttl_days?: number; now?: number }): Proof {
  const now = input.now ?? Math.floor(Date.now() / 1000);
  const ttl = Math.min(Math.max(1, input.ttl_days ?? DEFAULT_TTL_DAYS), MAX_TTL_DAYS);
  const { ttl_days: _ttl, now: _now, ...rest } = input;
  return { ofp: OFP_VERSION, id: randomUUID(), ...rest, issued_at: now, expires_at: now + ttl * 86_400 };
}

export function signProof(proof: Proof, signer: { key: KeyObject; id: string }): SignedProof {
  return {
    proof,
    signature: sign(null, Buffer.from(canonicalize(proof), "utf8"), signer.key).toString("base64url"),
    key_id: signer.id,
    alg: "Ed25519",
  };
}

export interface VerifyResult {
  valid: boolean;
  reasons: string[];
}

/**
 * What every verifier must check (SPEC §7). `publicKey` is the issuer's base64url SPKI DER key from its
 * /.well-known/ofp-issuer document. `expectVerifier` is the verifier's own identifier.
 */
export function verifyProof(
  signed: SignedProof,
  publicKey: string,
  opts: { expectVerifier?: string; expectNonce?: string; minTrust?: TrustLevel; now?: number } = {},
): VerifyResult {
  const reasons: string[] = [];
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  const p = signed.proof;
  if (!p || p.ofp !== OFP_VERSION) reasons.push(`Unsupported OFP version ${p?.ofp}.`);
  if (signed.alg !== "Ed25519") reasons.push(`Unsupported algorithm ${signed.alg}.`);
  if (p && p.expires_at <= now) reasons.push("Proof has expired.");
  if (p && p.issued_at > now + 60) reasons.push("Proof is issued in the future.");
  if (p && opts.expectVerifier !== undefined && p.verifier !== opts.expectVerifier) reasons.push(`Proof is addressed to "${p.verifier}", not to this verifier.`);
  if (p && opts.expectNonce !== undefined && p.nonce !== opts.expectNonce) reasons.push("Nonce does not match the request.");
  if (p && opts.minTrust && p.trust_level < opts.minTrust) reasons.push(`Trust level ${p.trust_level} is below the required ${opts.minTrust}.`);
  if (p && p.source?.verification === "inconsistent") reasons.push("The source statement failed consistency checks.");
  try {
    const key = createPublicKey({ key: Buffer.from(publicKey, "base64url"), format: "der", type: "spki" });
    if (!verify(null, Buffer.from(canonicalize(p), "utf8"), key, Buffer.from(signed.signature, "base64url"))) reasons.push("Signature does not match the proof.");
  } catch (err) {
    reasons.push(`Signature could not be checked: ${(err as Error).message}`);
  }
  return { valid: reasons.length === 0, reasons };
}
