# Sooto

**Sooto lets any AI assistant connect to, prove and protect a person's or business's money, across African banks, mobile-money wallets and statements.** It is read-only and cannot move money. It is the reference implementation of the **[Open Financial Proof (OFP)](docs/ofp/SPEC.md)** standard.

*Sooto* comes from the Yoruba *òótọ́*, "truth".

> **Status: v0.2, early.** Statement verification (CSV and PDF, including password-protected PDFs), OFP proofs, the scam shield and the injection guard work today from any statement export. Live African bank connections (Mono, Stitch, the NIBSS open-banking registry) are next. European banks already work through Enable Banking, as in the code Sooto started from.

## The problem

Across Africa, a person's financial record is split across bank accounts, wallets, PDFs, SMS alerts and cash. As a result:

1. **Honest people can't prove what they earn**, so they can't get credit. This is the root of the MSME finance gap.
2. **Dishonest people can fake it.** Edited bank statements are the document lenders, landlords and consulates are most often deceived with.
3. **Criminals talk people into sending money themselves.** Social engineering is the largest category of payment fraud in Nigeria, and bank controls don't see it coming.

Sooto makes the record **visible** to its owner, **provable** to others without exposing it, and **protected** at the moment money is about to move.

## What it does

| | Tool | What it does |
|---|---|---|
| **Verify** | `verify_statement` | Loads any bank or wallet statement (CSV, text or PDF, including password-protected PDFs) and checks it: running balance, totals, dates, duplicates, padding (large late deposits, money in and straight out), and narrations that try to instruct an AI |
| | `request_statement_upload` | A one-time link where the owner uploads a statement PDF and its password from their browser, so neither passes through the chat (or costs the assistant tokens) |
| | `list_statements` | Statements loaded in the last 24 hours (held in memory only) |
| | `cashflow_profile` | Monthly in/out, average and median inflow, how steady it is, payer count and concentration, balance range |
| **Prove** | `issue_proof` | A signed **Open Financial Proof** for one named verifier and purpose. `funds_held` covers visa proof of funds and deposits; `cashflow` covers lending, tenancy and employment. Gives bands, not transactions, and always includes risk signals |
| | `verify_proof` | Checks a proof's signature, expiry, addressee and nonce |
| **Protect** | `check_message` | Scam check for messages and calls: OTP/PIN/BVN requests, fake CBN/EFCC/bank officials, "wrong transfer, send it back", advance fees, guaranteed returns, remote-access apps |
| | `check_payee` | Before paying: first-time payee, unusual amount, and whether the account name matches who you think you're paying |
| **Secure** | built in | **Injection guard:** narrations and counterparty names are cleaned, capped and flagged when they look like instructions, and nothing that decides what a proof says ever reads them |
| **Connect** | `list_banks`, `start_consent`, `get_transactions`, … | Live read-only bank connections (Enable Banking/PSD2 today; African providers next) |

Verifiers check proofs against the issuer key at `/.well-known/ofp-issuer`.

## Run it locally

You need Node 24 or newer.

```bash
git clone https://github.com/heirmexxy/Sooto.git
cd Sooto
npm ci && npm run build
claude mcp add sooto -- node "$(pwd)/bin/sooto.js"     # Claude Code
```

For Claude Desktop or another MCP client, add a stdio server with the command `node /path/to/Sooto/bin/sooto.js`. Then ask your assistant something like:

> "Here is my GTBank statement export. Check it, then make a proof for the University of Leeds that I held at least £15,000 for 28 days, using the CBN rate of 0.00048."

State lives in `~/.sooto`. Statements are never written to disk.

### Hosted deployment

Deploy with the Docker image or the Railway, Fly or Render configurations (`Dockerfile`, `fly.toml`, `render.yaml`, `railway.json`). Then open the server's address and choose **Start with statements**: set the password your assistant will use, and the verify, prove and protect tools work immediately. No bank account or aggregator contract is needed. Add your assistant as a remote MCP connector at `https://YOUR-HOST/mcp`.

European bank connections are optional. Set `EB_APP_ID` and `EB_PRIVATE_KEY` for Enable Banking.

## Project layout

```
src/sooto-tools.ts      the verify / prove / protect MCP tools
src/guard/injection.ts  cleans and flags third-party text before an AI sees it
src/providers/          provider interface, statement importer, dependency-free PDF reader
                        (pdf.ts: text, fonts, RC4/AES decryption; pdf-table.ts: rebuilds the table)
src/verify/statement.ts statement consistency and padding checks
src/ofp/                Open Financial Proof: metrics, templates, signing and verification
src/shield/scam.ts      message and payee risk checks
src/tools.ts            bank-connection tools (inherited, Enable Banking)
src/attestation.ts      issuer key and IBAN-ownership attestation (inherited)
docs/ofp/SPEC.md        the Open Financial Proof specification, v0.1 draft
test/                   node:test suites; run with npm test
```

## Roadmap

1. **Connect:** provider adapters for Mono and Stitch; NIBSS open banking once licensed; SMS bank-alert ingestion through a companion app; mobile-money statement formats (M-Pesa, MTN MoMo); OCR for scanned statements.
2. **Prove:** BVN/NIN identity linking; OFP v0.2 as W3C Verifiable Credentials / SD-JWT with EU Digital Identity Wallet compatibility; L3 bank co-signing; QR proofs that can be checked offline; a verifier portal.
3. **Protect:** real-time watches for account drains and money-mule patterns; a shared scam-account signal network; WhatsApp and USSD channels.
4. **Secure:** consent and access ledger; "know your agent" identity and scoped mandates; the OFP security profile and conformance tests.
5. **Optimise:** optional [WasteZero](https://github.com/heirmexxy/WasteZero) integration. Sooto's own model calls are routed through WasteZero for cost per verification, and customers can opt into it. Metadata-only logging, never prompts. WasteZero is not part of the OFP standard.

## Principles

- **Read-only.** No tool moves money. Payments, if ever added, go through a licensed partner with mandates confirmed outside the AI conversation.
- **The owner decides.** Proofs are issued only when the owner asks, and only to the verifier they name.
- **No data trade.** Sooto never sells or reuses anyone's financial data.
- **Deterministic where it matters.** Verification and proof claims are computed by code, never by a model.

## Licence and credits

MIT. Sooto is derived from [BankMCP](https://github.com/noskillish/bankmcp) by Nils Smed, used under the MIT License. "BankMCP" is its owner's trademark, and Sooto is not affiliated with it. See [LICENSE](LICENSE).
