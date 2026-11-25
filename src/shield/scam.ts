// Scam shield: deterministic checks for social engineering and risky payees.
//
// Social engineering is the largest category of payment fraud in Nigeria by
// volume: the victim is talked into sending the money themselves, so bank
// controls that look for unauthorised access never fire. The defence has to
// happen before the transfer, on the customer's side, in the conversation
// where the pressure is applied. That is where an AI assistant already is.
//
// These checks are rules, not a model. They give the assistant concrete,
// explainable signals to put in front of the person ("this message asks for
// your OTP; no bank ever does"). The assistant can add judgement on top; the
// signals themselves stay reproducible.

export interface Signal {
  id: string;
  weight: number;
  explanation: string;
}

export interface ScamAssessment {
  risk: "low" | "medium" | "high";
  score: number;
  signals: Signal[];
  advice: string[];
}

const RULES: Array<{ id: string; weight: number; re: RegExp; explanation: string }> = [
  { id: "credential_request", weight: 5, re: /\b(otp|one[- ]time (pass|code)|pin|password|cvv|card number|token code|bvn|nin)\b.{0,60}\b(send|share|give|provide|tell|confirm|enter|forward|reply)\b|\b(send|share|give|provide|tell|confirm|forward|reply)\b.{0,60}\b(otp|pin|password|cvv|card number|token|bvn)\b/i, explanation: "Asks for an OTP, PIN, password, card details or BVN. No bank, CBN, NIBSS or payment company ever asks for these." },
  { id: "account_threat", weight: 3, re: /\b(account|card|bvn|sim|line)\b.{0,40}\b(blocked|block|suspended|restricted|deactivated|frozen|closed|flagged)\b/i, explanation: "Threatens that an account, card, BVN or SIM will be blocked. Pressure through fear is the most common opener." },
  { id: "urgency", weight: 2, re: /\b(urgent|urgently|immediately|right now|within \d+ ?(min|mins|minutes|hours?|hrs?)|today only|last chance|act now|asap)\b/i, explanation: "Creates urgency so there is no time to check." },
  { id: "authority_impersonation", weight: 3, re: /\b(cbn|central bank|efcc|nfiu|nibss|police|dss|customs|firs|kra|sars|interpol|bank (manager|official|customer care)|customer care (agent|officer))\b/i, explanation: "Claims to be a regulator, law enforcement or a bank official. These bodies do not contact people this way to move money." },
  { id: "wrong_transfer_reversal", weight: 4, re: /\b(wrong(ly)?|mistaken(ly)?|erroneous(ly)?|accidental(ly)?)\b.{0,40}\b(transfer|sent|credit|payment)\b|\b(reverse|refund|send (it |the money )?back|return (the|my) money)\b/i, explanation: "Says money was sent by mistake and asks for it back. Often the 'credit' was a fake alert or stolen funds; send nothing and let the bank reverse it." },
  { id: "advance_fee", weight: 4, re: /\b(processing|clearance|registration|activation|release|delivery|insurance|tax|transfer) (fee|charge|charges)\b|\bpay\b.{0,30}\b(to (receive|claim|release|unlock))\b/i, explanation: "Asks for a fee before you receive a prize, loan, job, parcel or payment. That is advance-fee fraud." },
  { id: "prize_or_windfall", weight: 3, re: /\b(you (have )?won|winner|lottery|promo(tion)? winner|cash prize|grant approved|selected (for|to receive)|unclaimed (funds|inheritance)|inheritance)\b/i, explanation: "Promises a prize, grant or inheritance you did not apply for." },
  { id: "investment_promise", weight: 4, re: /\b(double your|guaranteed (returns?|profit)|\d{2,3}% (returns?|profit|interest) (in|within|every|per)|risk[- ]free|forex signal|crypto (investment|trading) (platform|plan)|mining pool|ponzi|roi daily)\b/i, explanation: "Promises high or guaranteed returns. Real investments never guarantee them." },
  { id: "job_fee", weight: 3, re: /\b(job|employment|visa|recruitment|placement)\b.{0,50}\b(fee|deposit|pay|payment)\b/i, explanation: "Asks for payment to secure a job or visa. Legitimate employers do not charge applicants." },
  { id: "secrecy", weight: 2, re: /\b(don'?t tell|do not tell|keep (this|it) (secret|confidential|between us)|don'?t (call|contact) (the|your) bank)\b/i, explanation: "Asks you to keep it secret or not to call your bank. Isolation is a red flag." },
  { id: "remote_access", weight: 4, re: /\b(anydesk|teamviewer|quick ?support|rustdesk|screen ?shar(e|ing)|install (this|the) app|download (this|the) app)\b/i, explanation: "Asks you to install an app or share your screen. That gives the caller control of your phone or banking app." },
  { id: "link", weight: 1, re: /\bhttps?:\/\/\S+|\bbit\.ly\/\S+|\bwa\.me\/\S+|\b\S+\.(xyz|top|click|link|live|online|site)\b/i, explanation: "Contains a link. Open banking and payment pages only by typing the bank's address yourself." },
  { id: "gift_card_crypto_payment", weight: 3, re: /\b(gift ?cards?|itunes card|steam card|usdt|bitcoin|btc|crypto wallet|p2p)\b.{0,40}\b(pay|send|buy|payment)\b|\b(pay|send|buy)\b.{0,40}\b(gift ?cards?|usdt|bitcoin|btc)\b/i, explanation: "Asks for payment in gift cards or crypto, which cannot be reversed." },
  { id: "romance_emergency", weight: 2, re: /\b(my (love|dear|darling|baby)|stranded|hospital bill|stuck at the airport|customs (is )?holding)\b/i, explanation: "An emotional emergency from someone asking for money. Confirm by calling them on a number you already had." },
];

/** Scores a message, call summary or chat the person pasted in. */
export function assessMessage(text: string): ScamAssessment {
  const t = text.normalize("NFKC").slice(0, 10_000);
  const signals = RULES.filter((r) => r.re.test(t)).map(({ id, weight, explanation }) => ({ id, weight, explanation }));
  const score = signals.reduce((s, x) => s + x.weight, 0);
  const risk = score >= 6 || signals.some((s) => s.id === "credential_request" || s.id === "remote_access") ? "high" : score >= 3 ? "medium" : "low";
  const advice =
    risk === "low"
      ? ["No common scam pattern found. That does not make it safe: if it asks for money or details, confirm through a number you already trust."]
      : [
          "Do not send money, codes, PINs or card details, and do not install anything.",
          "Hang up or stop replying, then contact your bank using the number on your card or in the official app.",
          "If you already sent money, call your bank immediately and ask them to flag the transfer; speed matters for recovery.",
        ];
  return { risk, score, signals, advice };
}

export interface PayeeHistoryRow {
  date: string;
  amount: number;
  counterparty?: string;
  description?: string;
}

export interface PayeeAssessment {
  risk: "low" | "medium" | "high";
  signals: Signal[];
  history: { previous_payments: number; first_paid?: string; typical_amount?: number };
}

const normName = (s: string) =>
  s
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, " ")
    .replace(/\s+/g, " ")
    .trim();

/**
 * Before a transfer: has this person paid this payee before, and is the amount unusual for them?
 * `nameOnAccount` is what the bank's name enquiry returned, when the app has it; a mismatch with the
 * name the person was given is one of the strongest signals there is.
 */
export function assessPayee(input: {
  payee: string;
  amount: number;
  history: PayeeHistoryRow[];
  expectedName?: string;
  nameOnAccount?: string;
}): PayeeAssessment {
  const signals: Signal[] = [];
  const payee = normName(input.payee);
  const tokens = payee.split(" ").filter((t) => t.length >= 3);
  const paid = input.history.filter((r) => {
    if (r.amount >= 0) return false;
    const text = normName(`${r.counterparty ?? ""} ${r.description ?? ""}`);
    return tokens.length > 0 && tokens.every((t) => text.includes(t));
  });
  const debits = input.history.filter((r) => r.amount < 0).map((r) => -r.amount).sort((a, b) => a - b);
  const p95 = debits.length ? debits[Math.min(debits.length - 1, Math.floor(debits.length * 0.95))]! : undefined;

  if (!paid.length) signals.push({ id: "first_time_payee", weight: 2, explanation: "No earlier payment to this payee in the available history." });
  const typical = paid.length ? paid.map((r) => -r.amount).sort((a, b) => a - b)[Math.floor(paid.length / 2)] : undefined;
  if (typical !== undefined && input.amount > 3 * typical) {
    signals.push({ id: "unusual_for_payee", weight: 2, explanation: `Much larger than usual for this payee (typical ${typical}).` });
  }
  if (p95 !== undefined && input.amount > p95 && input.amount > 2 * (debits[Math.floor(debits.length / 2)] ?? 0)) {
    signals.push({ id: "unusual_amount", weight: 2, explanation: "Larger than almost every payment in the available history." });
  }
  if (input.expectedName && input.nameOnAccount) {
    const a = new Set(normName(input.expectedName).split(" ").filter((t) => t.length >= 3));
    const b = normName(input.nameOnAccount).split(" ").filter((t) => t.length >= 3);
    const overlap = b.filter((t) => a.has(t)).length;
    if (overlap === 0) {
      signals.push({ id: "name_mismatch", weight: 5, explanation: `The account is in the name "${input.nameOnAccount}", not "${input.expectedName}". Stop and confirm before paying.` });
    }
  }
  const score = signals.reduce((s, x) => s + x.weight, 0);
  const risk = signals.some((s) => s.id === "name_mismatch") || score >= 5 ? "high" : score >= 2 ? "medium" : "low";
  return {
    risk,
    signals,
    history: { previous_payments: paid.length, first_paid: paid[0]?.date, typical_amount: typical },
  };
}
