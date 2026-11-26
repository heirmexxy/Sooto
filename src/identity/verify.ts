// Identity verification against Nigeria's BVN and NIN registries, through a
// licensed KYC provider (Dojah or Prembly). This lets a proof say "the account
// holder's name matches a government identity record" instead of "the
// subject says their name is…".
//
// Rules this module keeps:
//   - Only the owner's own identity, with their explicit consent (verify_identity insists on consent: true).
//   - The BVN or NIN itself is never stored or returned. Only a keyed hash is kept, so the server can tell
//     the same number was used again without being able to reveal it.
//   - Of everything the registry returns (photo, phone numbers, address, date of birth), only the names are
//     kept. Date of birth is used for an optional check and then dropped.
//   - Verification does not raise the trust level of statement data: a verified name on an L1 statement is
//     still an L1 proof, with `name_verified: true`.
import { createHmac, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { config } from "../config.ts";

export type IdType = "bvn" | "nin";

export interface RegistryRecord {
  first_name: string;
  middle_name?: string;
  last_name: string;
  date_of_birth?: string;
}

export interface IdentityProvider {
  name: "dojah" | "prembly";
  lookup(idType: IdType, number: string): Promise<RegistryRecord>;
}

export class IdentityError extends Error {
  readonly code: "not_configured" | "invalid_number" | "not_found" | "provider_error" | "consent_required";
  constructor(message: string, code: IdentityError["code"]) {
    super(message);
    this.code = code;
  }
}

type Fetch = typeof fetch;
const pick = (o: Record<string, unknown> | undefined, ...keys: string[]) => {
  for (const k of keys) {
    const v = o?.[k];
    if (typeof v === "string" && v.trim()) return v.trim();
  }
  return undefined;
};

/** Dojah: GET /api/v1/kyc/bvn/full?bvn= and /api/v1/kyc/nin?nin=, headers AppId and Authorization (secret key). */
export function dojah(opts: { appId: string; secretKey: string; baseUrl?: string; fetch?: Fetch }): IdentityProvider {
  const base = (opts.baseUrl ?? "https://api.dojah.io").replace(/\/+$/, "");
  const f = opts.fetch ?? fetch;
  return {
    name: "dojah",
    async lookup(idType, number) {
      const url = idType === "bvn" ? `${base}/api/v1/kyc/bvn/full?bvn=${encodeURIComponent(number)}` : `${base}/api/v1/kyc/nin?nin=${encodeURIComponent(number)}`;
      const res = await f(url, { headers: { AppId: opts.appId, Authorization: opts.secretKey, Accept: "application/json" }, signal: AbortSignal.timeout(20_000) });
      const body = (await res.json().catch(() => ({}))) as { entity?: Record<string, unknown>; error?: string };
      if (res.status === 404 || (res.ok && !body.entity)) throw new IdentityError(`No ${idType.toUpperCase()} record was found for that number.`, "not_found");
      if (!res.ok) throw new IdentityError(`The identity provider refused the lookup (${res.status}${body.error ? `: ${body.error}` : ""}).`, "provider_error");
      const e = body.entity!;
      const first = pick(e, "first_name", "firstname", "firstName");
      const last = pick(e, "last_name", "surname", "lastname", "lastName");
      if (!first || !last) throw new IdentityError("The identity record came back without a name.", "provider_error");
      return { first_name: first, middle_name: pick(e, "middle_name", "middlename", "middleName"), last_name: last, date_of_birth: pick(e, "date_of_birth", "birthdate", "dateOfBirth") };
    },
  };
}

/** Prembly Identitypass: POST /identitypass/verification/{bvn|nin}, headers x-api-key and app-id, body {number}. */
export function prembly(opts: { appId: string; apiKey: string; baseUrl?: string; fetch?: Fetch }): IdentityProvider {
  const base = (opts.baseUrl ?? "https://api.prembly.com").replace(/\/+$/, "");
  const f = opts.fetch ?? fetch;
  return {
    name: "prembly",
    async lookup(idType, number) {
      const res = await f(`${base}/identitypass/verification/${idType}`, {
        method: "POST",
        headers: { "x-api-key": opts.apiKey, "app-id": opts.appId, "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify(idType === "bvn" ? { number } : { number, number_nin: number }),
        signal: AbortSignal.timeout(20_000),
      });
      const body = (await res.json().catch(() => ({}))) as { status?: boolean; detail?: string; data?: Record<string, unknown>; nin_data?: Record<string, unknown> };
      const d = body.data ?? body.nin_data;
      if (!res.ok || body.status === false || !d) {
        if (res.ok || res.status === 404) throw new IdentityError(body.detail ?? `No ${idType.toUpperCase()} record was found for that number.`, "not_found");
        throw new IdentityError(`The identity provider refused the lookup (${res.status}${body.detail ? `: ${body.detail}` : ""}).`, "provider_error");
      }
      const first = pick(d, "firstName", "firstname", "first_name");
      const last = pick(d, "lastName", "surname", "lastname", "last_name");
      if (!first || !last) throw new IdentityError("The identity record came back without a name.", "provider_error");
      return { first_name: first, middle_name: pick(d, "middleName", "middlename", "middle_name"), last_name: last, date_of_birth: pick(d, "dateOfBirth", "birthdate", "date_of_birth") };
    },
  };
}

/** The provider configured by environment variables, if any. */
export function configuredProvider(): IdentityProvider | undefined {
  const env = process.env;
  const choice = (env.SOOTO_ID_PROVIDER ?? (env.DOJAH_APP_ID ? "dojah" : env.PREMBLY_APP_ID ? "prembly" : "")).toLowerCase();
  if (choice === "dojah" && env.DOJAH_APP_ID && env.DOJAH_SECRET_KEY) return dojah({ appId: env.DOJAH_APP_ID, secretKey: env.DOJAH_SECRET_KEY, baseUrl: env.DOJAH_BASE_URL });
  if (choice === "prembly" && env.PREMBLY_APP_ID && env.PREMBLY_API_KEY) return prembly({ appId: env.PREMBLY_APP_ID, apiKey: env.PREMBLY_API_KEY, baseUrl: env.PREMBLY_BASE_URL });
  return undefined;
}

// ---------- What is kept ----------

export interface VerifiedIdentity {
  id_type: IdType;
  /** HMAC-SHA256 of the number under a server secret. Not reversible without the secret. */
  id_hash: string;
  /** Last 3 digits, so the owner can tell which number it was. */
  id_hint: string;
  first_name: string;
  middle_name?: string;
  last_name: string;
  full_name: string;
  provider: IdentityProvider["name"];
  verified_at: string;
  /** Result of the optional date-of-birth check; the date itself is not kept. */
  dob_checked?: boolean;
}

const file = () => join(config.dataDir, "identity.json");
const secretFile = () => join(config.dataDir, "identity.secret");

function secret(): Buffer {
  mkdirSync(config.dataDir, { recursive: true });
  if (!existsSync(secretFile())) writeFileSync(secretFile(), randomBytes(32).toString("base64"), { mode: 0o600 });
  return Buffer.from(readFileSync(secretFile(), "utf8").trim(), "base64");
}

export function verifiedIdentity(): VerifiedIdentity | undefined {
  try {
    return (JSON.parse(readFileSync(file(), "utf8")) as VerifiedIdentity | null) ?? undefined;
  } catch {
    return undefined;
  }
}

function save(v: VerifiedIdentity | undefined): void {
  mkdirSync(config.dataDir, { recursive: true });
  const tmp = `${file()}.tmp`;
  writeFileSync(tmp, JSON.stringify(v ?? null), { mode: 0o600 });
  renameSync(tmp, file());
}

export function forgetIdentity(): void {
  save(undefined);
}

/** Looks up the owner's BVN or NIN and keeps only the verified names. */
export async function verifyIdentity(input: { id_type: IdType; number: string; consent: boolean; date_of_birth?: string }, provider = configuredProvider()): Promise<VerifiedIdentity> {
  if (!input.consent) throw new IdentityError("The owner must consent to an identity lookup of their own BVN or NIN.", "consent_required");
  const number = input.number.replace(/\s+/g, "");
  if (!/^\d{11}$/.test(number)) throw new IdentityError(`A ${input.id_type.toUpperCase()} is 11 digits.`, "invalid_number");
  if (!provider) {
    throw new IdentityError("No identity provider is configured. Set DOJAH_APP_ID and DOJAH_SECRET_KEY, or PREMBLY_APP_ID and PREMBLY_API_KEY, on the server.", "not_configured");
  }
  const rec = await provider.lookup(input.id_type, number);
  let dobChecked: boolean | undefined;
  if (input.date_of_birth && rec.date_of_birth) dobChecked = rec.date_of_birth.slice(0, 10) === input.date_of_birth.slice(0, 10);
  const titled = (s?: string) => s?.toLowerCase().replace(/\b\w/g, (c) => c.toUpperCase());
  const v: VerifiedIdentity = {
    id_type: input.id_type,
    id_hash: createHmac("sha256", secret()).update(`${input.id_type}:${number}`).digest("base64url"),
    id_hint: number.slice(-3),
    first_name: titled(rec.first_name)!,
    middle_name: titled(rec.middle_name),
    last_name: titled(rec.last_name)!,
    full_name: [rec.first_name, rec.middle_name, rec.last_name].filter(Boolean).map(titled).join(" "),
    provider: provider.name,
    verified_at: new Date().toISOString(),
    ...(dobChecked !== undefined ? { dob_checked: dobChecked } : {}),
  };
  if (dobChecked === false) throw new IdentityError("The date of birth does not match the identity record. Nothing was saved.", "not_found");
  save(v);
  return v;
}
