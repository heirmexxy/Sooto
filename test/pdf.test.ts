import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { extractText, PdfError, rc4 } from "../src/providers/pdf.ts";
import { readPdfStatement } from "../src/providers/pdf-table.ts";
import { parseStatement } from "../src/providers/statement.ts";
import { verifyStatement } from "../src/verify/statement.ts";

const fixture = (name: string) => readFileSync(new URL(`./fixtures/${name}`, import.meta.url));
const csv = parseStatement(fixture("statement-ng.csv").toString("utf8"));
const sum = (rows: Array<{ amount: number }>) => Math.round(rows.reduce((s, r) => s + r.amount, 0) * 100) / 100;

function expectSameAsCsv(name: string, password?: string) {
  const r = readPdfStatement(fixture(name), password);
  const s = parseStatement(r.csv);
  assert.equal(s.rows.length, csv.rows.length, `${name}: row count`);
  assert.equal(s.closing_balance, csv.closing_balance, `${name}: closing balance`);
  assert.equal(sum(s.rows), sum(csv.rows), `${name}: net movement`);
  assert.deepEqual(s.rows.map((x) => x.date), csv.rows.map((x) => x.date), `${name}: dates`);
  assert.equal(verifyStatement(s, { today: "2026-11-25" }).verdict, "consistent", `${name}: verdict`);
  return { r, s };
}

test("report-style PDF (standard fonts, right-aligned amounts, two pages with repeated headers and footers)", () => {
  const { r, s } = expectSameAsCsv("statement-ng-report.pdf");
  assert.equal(r.pages, 2);
  assert.match(r.preamble.join(" "), /ADA OBI ENTERPRISES/);
  const wrapped = s.rows.find((x) => x.description?.startsWith("TRF FROM ACME FOODS LTD/SALARY SEPTEMBER"));
  assert.ok(wrapped?.description?.includes("VIA NIP INWARD TRANSFER"), "wrapped narration is rejoined");
  assert.ok(!s.rows.some((x) => /computer generated|Total debits/.test(x.description ?? "")), "footers stay out of narrations");
});

test("browser-printed PDF (embedded Identity-H fonts, dates wrapping inside cells)", () => {
  expectSameAsCsv("statement-ng-chrome.pdf");
});

test("compressed object streams", () => {
  expectSameAsCsv("statement-ng-report-objstm.pdf");
});

test("password-protected PDFs: RC4 128-bit, AES-128 and AES-256", () => {
  for (const name of ["statement-ng-report-rc4.pdf", "statement-ng-report-aes128.pdf", "statement-ng-report-aes256.pdf"]) {
    const { r } = expectSameAsCsv(name, "0123");
    assert.equal(r.encrypted, true);
  }
});

test("missing and wrong passwords give clear, distinct errors", () => {
  assert.throws(() => extractText(fixture("statement-ng-report-aes256.pdf")), (e: unknown) => e instanceof PdfError && e.code === "password_required");
  assert.throws(() => extractText(fixture("statement-ng-report-rc4.pdf"), { password: "9999" }), (e: unknown) => e instanceof PdfError && e.code === "wrong_password");
  assert.throws(() => extractText(Buffer.from("hello")), (e: unknown) => e instanceof PdfError && e.code === "not_pdf");
});

test("RC4 matches the published test vector", () => {
  assert.equal(rc4(Buffer.from("Key"), Buffer.from("Plaintext")).toString("hex"), "bbf316e8d940af0ad3");
});
