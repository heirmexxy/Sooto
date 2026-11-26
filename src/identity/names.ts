// Name matching for Nigerian and wider African names.
//
// The same person's name appears differently on a BVN record, a bank
// statement and a visa form: order varies (surname first on most Nigerian
// bank records), middle names come and go, titles are added ("ALHAJI",
// "CHIEF", "ENGR"), spellings drift (MICHAEL / MICHEAL, MOHAMMED / MUHAMMAD),
// and businesses add "ENTERPRISES" or "VENTURES". A match has to survive all
// of that without letting two different people through, so the rules are
// conservative: two shared name tokens, one of which must be the surname when
// it is known, before anything counts as a strong match.

const TITLES = new Set([
  "mr", "mrs", "miss", "ms", "dr", "prof", "engr", "eng", "arc", "barr", "chief", "alhaji", "alhaja", "hajia", "hon", "sir", "lady", "pastor", "rev", "revd", "bishop",
  "elder", "deacon", "deaconess", "evang", "prince", "princess", "oba", "otunba", "mallam", "malam", "comrade", "dcn", "pst", "capt", "col", "gen", "late",
]);
const BUSINESS = new Set(["enterprise", "enterprises", "ventures", "venture", "global", "nigeria", "nig", "ltd", "limited", "plc", "and", "sons", "co", "company", "services", "stores", "store", "investment", "investments", "concept", "concepts", "int", "intl", "international", "resources"]);

/** Spellings that refer to the same name, mapped to one form. */
const VARIANTS: Record<string, string> = {
  mohammed: "muhammad", mohammad: "muhammad", muhammed: "muhammad", mohamed: "muhammad", muhammadu: "muhammad", mohd: "muhammad",
  abubakr: "abubakar", aminat: "aminah", aminatu: "aminah", amina: "aminah", fatimah: "fatima", fatimat: "fatima",
  oluwaseun: "seun", oluwatobi: "tobi", oluwafemi: "femi", oluwadamilare: "damilare", olawale: "wale",
  chukwuemeka: "emeka", ifeanyichukwu: "ifeanyi",
};

export function nameTokens(name: string): string[] {
  return name
    .normalize("NFKD")
    .replace(/[̀-ͯ]/g, "")
    .toLowerCase()
    .replace(/[^a-z\s'-]/g, " ")
    .replace(/['-]/g, "")
    .split(/\s+/)
    .filter((t) => t.length > 1 && !TITLES.has(t) && !BUSINESS.has(t))
    .map((t) => VARIANTS[t] ?? t);
}

/** Optimal string alignment distance (Levenshtein plus adjacent transposition), capped at 3. */
function distance(a: string, b: string): number {
  if (Math.abs(a.length - b.length) > 2) return 3;
  const d: number[][] = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array<number>(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0]![j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let v = Math.min(d[i - 1]![j]! + 1, d[i]![j - 1]! + 1, d[i - 1]![j - 1]! + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) v = Math.min(v, d[i - 2]![j - 2]! + 1);
      d[i]![j] = v;
    }
  }
  return Math.min(3, d[a.length]![b.length]!);
}

/** Same name token, allowing one slip in longer names (MICHAEL/MICHEAL, OKAFOR/OKAFFOR). */
function sameToken(a: string, b: string): boolean {
  if (a === b) return true;
  return a.length >= 5 && b.length >= 5 && distance(a, b) <= 1;
}

export type NameMatch = "exact" | "strong" | "partial" | "none";

export interface NameMatchResult {
  match: NameMatch;
  /** Tokens of `a` found in `b`. */
  shared: string[];
  explanation: string;
}

/**
 * Compares two renderings of a name. `surname`, when known (from a BVN record), must be among the shared tokens
 * for a strong match: "ADA OBI" and "ADA NWOSU" share a first name, which is not the same person.
 */
export function matchNames(a: string, b: string, opts: { surname?: string } = {}): NameMatchResult {
  const ta = [...new Set(nameTokens(a))];
  const tb = [...new Set(nameTokens(b))];
  if (!ta.length || !tb.length) return { match: "none", shared: [], explanation: "One of the names is empty after removing titles and business words." };
  const shared = ta.filter((t) => tb.some((u) => sameToken(t, u)));
  const surname = opts.surname ? nameTokens(opts.surname)[0] : undefined;
  const surnameShared = surname ? shared.some((t) => sameToken(t, surname)) && tb.some((u) => sameToken(u, surname)) : true;
  const sameSet = shared.length === ta.length && tb.every((u) => ta.some((t) => sameToken(t, u)));
  if (sameSet && surnameShared) return { match: "exact", shared, explanation: "Same names, allowing for order, titles and spelling." };
  if (shared.length >= 2 && surnameShared) return { match: "strong", shared, explanation: "At least two names match, including the surname." };
  if (shared.length >= 1) return { match: "partial", shared, explanation: surnameShared ? "Only one name matches." : "Names overlap but the surname does not match." };
  return { match: "none", shared: [], explanation: "No names in common." };
}

/** Finds the account holder's name in the text above a statement table, if the bank printed it with a label. */
export function holderNameFrom(lines: string[]): string | undefined {
  for (const line of lines) {
    const m = /\b(?:account\s+name|customer\s+name|account\s+holder|customer|name)\s*[:\-–]\s*,?\s*([A-Za-z][A-Za-z .'&-]{2,80}?)(?=\s{2,}|,|\s+(?:account|acct|a\/c|mobile|phone|currency|period|address|branch|bvn)\b|$)/i.exec(line);
    if (m) return m[1]!.trim();
  }
  return undefined;
}
