import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseStatement } from "../src/providers/statement.ts";
import { verifyStatement } from "../src/verify/statement.ts";

const load = (name: string, currency: string) => parseStatement(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), "utf8"), { currency });
const consistent = (s: ReturnType<typeof load>) => assert.equal(verifyStatement(s, { today: "2026-11-26" }).verdict, "consistent");

test("M-Pesa full statement: newest first, negative Withdrawn, failed rows left out", () => {
  const s = load("statement-mpesa.csv", "KES");
  assert.equal(s.reversed, true);
  assert.equal(s.rows.length, 5);
  assert.deepEqual(s.excluded, [{ line: 9, status: "Failed" }]);
  assert.deepEqual(s.rows.map((r) => r.amount), [7000, -2267, 5000, -23, -1500]);
  assert.equal(s.closing_balance, 8210);
  assert.equal(s.currency, "KES");
  consistent(s);
});

test("MTN MoMo (Ghana layout): balance before/after settles direction, fees and E-levy are summed", () => {
  const s = load("statement-momo-gh.csv", "GHS");
  assert.deepEqual(s.rows.map((r) => r.amount), [-200, 450, -307.5]);
  assert.equal(s.rows[2]!.fees, 7.5);
  assert.equal(s.rows[0]!.counterparty, "AMA SERWAA", "debits name the recipient");
  assert.equal(s.rows[1]!.counterparty, "YAW BOATENG", "credits name the sender");
  assert.equal(s.opening_balance, 1000);
  consistent(s);
});

test("MTN MoMo (Uganda layout): direction not stated, taken from the running balance", () => {
  const s = load("statement-momo-ug.csv", "UGX");
  assert.deepEqual(s.rows.map((r) => r.amount), [50000, -30500, -40000, 120000]);
  assert.equal(s.excluded.length, 1);
  assert.equal(s.rows[0]!.counterparty, "NAKATO SARAH");
  assert.ok(s.warnings.some((w) => /direction was taken from the running balance/.test(w)));
  consistent(s);
});

test("an edited mobile-money amount still breaks the chain", () => {
  const text = readFileSync(new URL("./fixtures/statement-momo-ug.csv", import.meta.url), "utf8").replace("120000,0,299500", "220000,0,299500");
  assert.equal(verifyStatement(parseStatement(text, { currency: "UGX" }), { today: "2026-11-26" }).verdict, "inconsistent");
});
