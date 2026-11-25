import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash, createPublicKey, generateKeyPairSync } from "node:crypto";
import { parseStatement } from "../src/providers/statement.ts";
import { canonicalize, digest, newProof, signProof, verifyProof } from "../src/ofp/proof.ts";
import { band, cashflowClaims, fundsHeldClaims } from "../src/ofp/templates.ts";
import { cashflowProfile } from "../src/ofp/metrics.ts";

const fixture = readFileSync(new URL("./fixtures/statement-ng.csv", import.meta.url), "utf8");
const statement = parseStatement(fixture);
const { privateKey } = generateKeyPairSync("ed25519");
const pub = createPublicKey(privateKey).export({ type: "spki", format: "der" }).toString("base64url");
const signer = { key: privateKey, id: createHash("sha256").update(pub).digest("base64url").slice(0, 16) };

test("canonical form sorts keys at every depth and drops undefined", () => {
  assert.equal(canonicalize({ b: 1, a: { d: [1, { z: 1, y: 2 }], c: undefined } }), '{"a":{"d":[1,{"y":2,"z":1}]},"b":1}');
});

test("cash-flow profile of the fixture", () => {
  const p = cashflowProfile(statement.rows, { opening: statement.opening_balance });
  assert.equal(p.months.length, 4);
  assert.ok(p.avg_monthly_inflow > 400_000);
  assert.ok(p.distinct_payers >= 2);
  assert.equal(p.balance?.closing, 1359200);
});

test("funds-held answers the 28-day question from end-of-day balances", () => {
  const yes = fundsHeldClaims(statement.rows, "NGN", { amount: 900_000, currency: "NGN", days: 28 }, statement.opening_balance);
  assert.equal(yes.held, true);
  const no = fundsHeldClaims(statement.rows, "NGN", { amount: 1_000_000, currency: "NGN", days: 28 }, statement.opening_balance);
  assert.equal(no.held, false);
  assert.equal((yes as any).exact, undefined, "exact figures are not disclosed by default");
});

test("funds-held refuses a different currency without a stated rate", () => {
  assert.throws(() => fundsHeldClaims(statement.rows, "NGN", { amount: 1000, currency: "GBP" }, statement.opening_balance), /fx rate/);
  const c = fundsHeldClaims(statement.rows, "NGN", { amount: 400, currency: "GBP", fx: { rate: 0.0005, source: "CBN official rate", date: "2026-09-26" } }, statement.opening_balance);
  assert.equal(c.held, true);
  assert.deepEqual((c as any).fx.source, "CBN official rate");
});

test("a signed proof verifies, and any change to it does not", () => {
  const { claims } = cashflowClaims(statement.rows, { currency: "NGN", min_avg_monthly_inflow: 300_000 }, statement.opening_balance);
  assert.equal(claims.meets_min_avg_monthly_inflow, true);
  const proof = newProof({
    type: "cashflow",
    issuer: "https://sooto.example",
    verifier: "lender.example",
    purpose: "Working-capital loan application",
    trust_level: "L1",
    source: { provider: "statement", digest: digest(fixture), verification: "consistent", period: { from: statement.from!, to: statement.to! } },
    claims,
  });
  const signed = signProof(proof, signer);
  assert.deepEqual(verifyProof(signed, pub, { expectVerifier: "lender.example" }), { valid: true, reasons: [] });

  const tampered = structuredClone(signed);
  (tampered.proof.claims as any).meets_min_avg_monthly_inflow = false;
  assert.equal(verifyProof(tampered, pub).valid, false);

  assert.equal(verifyProof(signed, pub, { expectVerifier: "someone-else.example" }).valid, false);
  assert.equal(verifyProof(signed, pub, { minTrust: "L2" }).valid, false);
  assert.equal(verifyProof(signed, pub, { now: proof.expires_at + 1 }).valid, false);
});

test("bands hide exact amounts", () => {
  assert.equal(band(1_359_200), "1,000,000–2,500,000");
  assert.equal(band(120_000_000), "100,000,000+");
});
