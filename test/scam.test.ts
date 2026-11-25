import { test } from "node:test";
import assert from "node:assert/strict";
import { assessMessage, assessPayee } from "../src/shield/scam.ts";

test("a classic BVN/OTP message is high risk", () => {
  const r = assessMessage("Dear customer, your BVN has been suspended by CBN. Send the OTP you receive now to reactivate within 30 minutes.");
  assert.equal(r.risk, "high");
  assert.ok(r.signals.some((s) => s.id === "credential_request"));
  assert.ok(r.signals.some((s) => s.id === "authority_impersonation"));
});

test("a wrong-transfer request is flagged", () => {
  const r = assessMessage("Good evening, I mistakenly transferred 50,000 to your account. Please send it back urgently, my child is in hospital.");
  assert.notEqual(r.risk, "low");
  assert.ok(r.signals.some((s) => s.id === "wrong_transfer_reversal"));
});

test("an ordinary message is low risk", () => {
  assert.equal(assessMessage("Hi, the bags of rice will be delivered on Thursday. Pay on delivery as usual.").risk, "low");
});

test("payee checks: first-time payee, unusual amount, name mismatch", () => {
  const history = [
    { date: "2026-06-01", amount: -150000, description: "TRF TO LANDLORD ADEBAYO/RENT" },
    { date: "2026-07-01", amount: -150000, description: "TRF TO LANDLORD ADEBAYO/RENT" },
    { date: "2026-07-05", amount: -8000, description: "POS PURCHASE SHOPRITE" },
  ];
  assert.equal(assessPayee({ payee: "Landlord Adebayo", amount: 150000, history }).risk, "low");
  const fresh = assessPayee({ payee: "Musa Quick Loans", amount: 900000, history });
  assert.ok(fresh.signals.some((s) => s.id === "first_time_payee"));
  assert.ok(fresh.signals.some((s) => s.id === "unusual_amount"));
  const mismatch = assessPayee({ payee: "Landlord Adebayo", amount: 150000, history, expectedName: "Adebayo Ogunleye", nameOnAccount: "Chukwu Emmanuel" });
  assert.equal(mismatch.risk, "high");
});
