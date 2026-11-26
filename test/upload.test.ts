import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

process.env.DATA_DIR = mkdtempSync(join(tmpdir(), "sooto-upload-"));
const { completeUpload, createUploadLink, loadStatement, uploadLink } = await import("../src/sooto-tools.ts");

const fixture = (name: string) => readFileSync(new URL(`./fixtures/${name}`, import.meta.url));
const tokenOf = (url: string) => url.split("/upload/")[1]!;

test("an upload link takes one protected PDF, survives a wrong password, then closes", () => {
  const link = createUploadLink({ label: "Test bank" });
  const token = tokenOf(link.url);
  assert.ok(uploadLink(token));
  const wrong = completeUpload(token, fixture("statement-ng-report-aes128.pdf"), "nope");
  assert.equal(wrong.error, "wrong_password");
  assert.ok(uploadLink(token), "a wrong password does not use up the link");
  const ok = completeUpload(token, fixture("statement-ng-report-aes128.pdf"), "0123");
  assert.equal(ok.ok, true);
  assert.equal(ok.rows, 37);
  assert.equal((ok.verification as { verdict: string }).verdict, "consistent");
  assert.equal(uploadLink(token), undefined, "the link is single-use");
  assert.equal(completeUpload(token, fixture("statement-ng.csv")).error, "link_invalid");
});

test("loadStatement reads CSV text and PDFs alike", () => {
  const a = loadStatement({ text: fixture("statement-ng.csv").toString("utf8") });
  const b = loadStatement({ pdf: fixture("statement-ng-chrome.pdf") });
  assert.equal(a.rows, b.rows);
  assert.equal(b.format, "pdf");
});

test("a verified identity must match the statement's account holder before a proof names it", async () => {
  const { held, proofSubject } = await import("../src/sooto-tools.ts");
  const { verifyIdentity, dojah, forgetIdentity } = await import("../src/identity/verify.ts");
  const loaded = loadStatement({ pdf: fixture("statement-ng-report.pdf") });
  assert.equal(loaded.holder_name, "ADA OBI ENTERPRISES");
  const s = held(loaded.statement_id as string);

  const asPerson = (first: string, last: string) =>
    dojah({ appId: "a", secretKey: "s", fetch: (async () => new Response(JSON.stringify({ entity: { first_name: first, last_name: last } }), { status: 200 })) as unknown as typeof fetch });

  await verifyIdentity({ id_type: "bvn", number: "22222222222", consent: true }, asPerson("ADA", "OBI"));
  const ok = proofSubject(s, undefined, true);
  assert.equal((ok.subject as { name_verified: boolean }).name_verified, true);
  assert.equal((ok.holder as { matches_verified_name: string }).matches_verified_name, "exact");

  await verifyIdentity({ id_type: "bvn", number: "22222222222", consent: true }, asPerson("KEMI", "BELLO"));
  assert.throws(() => proofSubject(s, undefined, true), /does not match the verified identity/);
  forgetIdentity();
  assert.equal((proofSubject(s, "Ada Obi", true).subject as { name_verified: boolean }).name_verified, false);
});
