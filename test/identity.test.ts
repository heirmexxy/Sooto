import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), "sooto-identity-"));
const { matchNames, holderNameFrom, nameTokens } = await import("../src/identity/names.ts");
const { dojah, prembly, verifyIdentity, verifiedIdentity, forgetIdentity, IdentityError } = await import("../src/identity/verify.ts");

test("names match across order, titles, business words and spelling slips", () => {
  assert.equal(matchNames("Ada Chioma Obi", "OBI ADA").match, "strong");
  assert.equal(matchNames("Adeola Michael Ayo", "MR AYO ADEOLA MICHEAL").match, "exact");
  assert.equal(matchNames("Muhammad Sani Bello", "ALHAJI MOHAMMED BELLO").match, "strong");
  assert.equal(matchNames("Ada Obi", "ADA OBI ENTERPRISES").match, "exact");
  assert.equal(matchNames("Ada Obi", "Ada Nwosu", { surname: "Obi" }).match, "partial", "same first name, different surname");
  assert.equal(matchNames("Ada Obi", "Kemi Bello").match, "none");
  assert.deepEqual(nameTokens("Chief (Dr.) Emeka Nwachinemere"), ["emeka", "nwachinemere"]);
});

test("the account holder is found in labelled statement headers", () => {
  assert.equal(holderNameFrom(["FIRST EXAMPLE BANK PLC - STATEMENT OF ACCOUNT", "Customer: ADA OBI ENTERPRISES    Account: 0123456789    Currency: NGN"]), "ADA OBI ENTERPRISES");
  assert.equal(holderNameFrom(["M-PESA STATEMENT", "Customer Name: WANJIKU KAMAU", "Mobile Number: 2547XXXXX123"]), "WANJIKU KAMAU");
  assert.equal(holderNameFrom(["Account Name: Ada Obi, Account Number: 0123"]), "Ada Obi");
  assert.equal(holderNameFrom(["Statement period 01-Jun-2026 to 30-Sep-2026"]), undefined);
});

const fakeFetch = (status: number, body: unknown) => (async () => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } })) as unknown as typeof fetch;

test("Dojah BVN lookup keeps only names; the number is never stored", async () => {
  let seen: { url?: string; headers?: Record<string, string> } = {};
  const f = (async (url: string, init: { headers: Record<string, string> }) => {
    seen = { url, headers: init.headers };
    return new Response(JSON.stringify({ entity: { bvn: "223*****240", first_name: "ADEOLA", last_name: "AYO", middle_name: "MICHEAL", date_of_birth: "1972-02-19", phone_number1: "08099434292", image: "base64…" } }), { status: 200 });
  }) as unknown as typeof fetch;
  const provider = dojah({ appId: "app", secretKey: "sk", baseUrl: "https://sandbox.dojah.io", fetch: f });
  const v = await verifyIdentity({ id_type: "bvn", number: "22222222222", consent: true, date_of_birth: "1972-02-19" }, provider);
  assert.equal(seen.url, "https://sandbox.dojah.io/api/v1/kyc/bvn/full?bvn=22222222222");
  assert.equal(seen.headers?.AppId, "app");
  assert.equal(seen.headers?.Authorization, "sk");
  assert.equal(v.full_name, "Adeola Micheal Ayo");
  assert.equal(v.dob_checked, true);
  const stored = readFileSync(join(process.env.DATA_DIR!, "identity.json"), "utf8");
  assert.ok(!stored.includes("22222222222"), "raw BVN is not stored");
  assert.ok(!/0809|1972|base64/.test(stored), "phone, date of birth and photo are not stored");
  assert.equal(verifiedIdentity()?.id_hint, "222");
  forgetIdentity();
  assert.equal(verifiedIdentity(), undefined);
});

test("lookups refuse without consent, with a bad number, or on a date-of-birth mismatch", async () => {
  const provider = dojah({ appId: "a", secretKey: "s", fetch: fakeFetch(200, { entity: { first_name: "ADA", last_name: "OBI", date_of_birth: "1990-01-01" } }) });
  await assert.rejects(verifyIdentity({ id_type: "bvn", number: "22222222222", consent: false }, provider), (e: unknown) => e instanceof IdentityError && e.code === "consent_required");
  await assert.rejects(verifyIdentity({ id_type: "bvn", number: "1234", consent: true }, provider), (e: unknown) => e instanceof IdentityError && e.code === "invalid_number");
  await assert.rejects(verifyIdentity({ id_type: "bvn", number: "22222222222", consent: true, date_of_birth: "1991-01-01" }, provider), /date of birth/);
  assert.equal(verifiedIdentity(), undefined, "nothing saved on mismatch");
  await assert.rejects(verifyIdentity({ id_type: "bvn", number: "22222222222", consent: true }, undefined), (e: unknown) => e instanceof IdentityError && e.code === "not_configured");
});

test("Prembly response shape is read too", async () => {
  const provider = prembly({ appId: "a", apiKey: "k", fetch: fakeFetch(200, { status: true, detail: "Verification Successful", data: { firstName: "test", lastName: "user", middleName: "middle" } }) });
  const v = await verifyIdentity({ id_type: "bvn", number: "10101010101", consent: true }, provider);
  assert.equal(v.full_name, "Test Middle User");
  assert.equal(v.provider, "prembly");
  const missing = prembly({ appId: "a", apiKey: "k", fetch: fakeFetch(200, { status: false, detail: "BVN not found" }) });
  await assert.rejects(verifyIdentity({ id_type: "bvn", number: "10101010101", consent: true }, missing), /BVN not found/);
});
