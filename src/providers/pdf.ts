// A small, dependency-free PDF text reader for bank statements.
//
// Most African banks send statements as PDFs, often password-protected (the
// password is usually derived from the account number or date of birth). A
// statement is a table drawn with text operators, so what Sooto needs is every
// piece of text with its position on the page; pdf-table.ts then rebuilds the
// table from those positions and hands it to the statement parser.
//
// Supported: classic and compressed (object-stream) files; FlateDecode,
// ASCIIHex and ASCII85 filters; simple fonts (WinAnsi/Standard encodings,
// /Differences) and composite fonts (Identity-H) through ToUnicode maps;
// glyph widths for accurate positions; form XObjects; and the standard
// security handler (RC4 40/128-bit, AES-128, AES-256) with a user password.
//
// Not supported, by design or for now: scanned statements (images, need OCR),
// LZW and JBIG2/JPX images (irrelevant to text), public-key encryption.
import { createCipheriv, createDecipheriv, createHash } from "node:crypto";
import { inflateSync, constants as zlibConstants } from "node:zlib";

// ---------- Values ----------

export class PdfName {
  readonly name: string;
  constructor(name: string) {
    this.name = name;
  }
}
export class PdfRef {
  readonly num: number;
  readonly gen: number;
  constructor(num: number, gen: number) {
    this.num = num;
    this.gen = gen;
  }
}
export class PdfOp {
  readonly op: string;
  constructor(op: string) {
    this.op = op;
  }
}
export type PdfDict = Map<string, PdfValue>;
export interface PdfStream {
  kind: "stream";
  dict: PdfDict;
  raw: Buffer;
  num: number;
  gen: number;
}
export type PdfValue = number | boolean | null | Buffer | PdfName | PdfRef | PdfValue[] | PdfDict | PdfStream | PdfOp;

export type PdfErrorCode = "not_pdf" | "password_required" | "wrong_password" | "unsupported_encryption" | "no_text";
export class PdfError extends Error {
  readonly code: PdfErrorCode;
  constructor(message: string, code: PdfErrorCode) {
    super(message);
    this.code = code;
  }
}

const isWs = (c: number) => c === 0x20 || c === 0x0a || c === 0x0d || c === 0x09 || c === 0x0c || c === 0x00;
const isDelim = (c: number) => c === 0x28 || c === 0x29 || c === 0x3c || c === 0x3e || c === 0x5b || c === 0x5d || c === 0x7b || c === 0x7d || c === 0x2f || c === 0x25;

/** Parses PDF values from a byte buffer. With `ops`, bare words become operators (content streams). */
export class Lexer {
  pos: number;
  private readonly b: Buffer;
  private readonly ops: boolean;
  constructor(b: Buffer, start = 0, ops = false) {
    this.b = b;
    this.pos = start;
    this.ops = ops;
  }

  skipWs(): void {
    const b = this.b;
    while (this.pos < b.length) {
      const c = b[this.pos]!;
      if (isWs(c)) this.pos++;
      else if (c === 0x25) {
        while (this.pos < b.length && b[this.pos] !== 0x0a && b[this.pos] !== 0x0d) this.pos++;
      } else break;
    }
  }

  private word(): string {
    const start = this.pos;
    while (this.pos < this.b.length && !isWs(this.b[this.pos]!) && !isDelim(this.b[this.pos]!)) this.pos++;
    return this.b.toString("latin1", start, this.pos);
  }

  /** Next value, or undefined at the end. Returns ">>" and "]" as PdfOp markers for the container parsers. */
  next(): PdfValue | undefined {
    this.skipWs();
    const b = this.b;
    if (this.pos >= b.length) return undefined;
    const c = b[this.pos]!;
    if (c === 0x2f) {
      this.pos++;
      return new PdfName(this.word().replace(/#([0-9a-fA-F]{2})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16))));
    }
    if (c === 0x28) return this.literalString();
    if (c === 0x3c) {
      if (b[this.pos + 1] === 0x3c) {
        this.pos += 2;
        return this.dict();
      }
      return this.hexString();
    }
    if (c === 0x3e && b[this.pos + 1] === 0x3e) {
      this.pos += 2;
      return new PdfOp(">>");
    }
    if (c === 0x5b) {
      this.pos++;
      const arr: PdfValue[] = [];
      for (;;) {
        const v = this.next();
        if (v === undefined || (v instanceof PdfOp && v.op === "]")) break;
        arr.push(v);
      }
      return arr;
    }
    if (c === 0x5d) {
      this.pos++;
      return new PdfOp("]");
    }
    if (c === 0x7b || c === 0x7d || c === 0x29 || c === 0x3e) {
      this.pos++;
      return new PdfOp(String.fromCharCode(c));
    }
    const w = this.word();
    if (!w) {
      this.pos++;
      return new PdfOp(String.fromCharCode(c));
    }
    if (/^[+-]?(\d+\.?\d*|\.\d+)$/.test(w)) {
      const n = Number(w);
      if (!this.ops && /^\d+$/.test(w)) {
        // "12 0 R" is a reference.
        const save = this.pos;
        const m = /^\s+(\d+)\s+R(?![^\s()<>[\]{}/%])/.exec(b.toString("latin1", this.pos, this.pos + 24));
        if (m) {
          this.pos = save + m[0].length;
          return new PdfRef(n, Number(m[1]));
        }
      }
      return n;
    }
    if (w === "true") return true;
    if (w === "false") return false;
    if (w === "null") return null;
    return new PdfOp(w);
  }

  private dict(): PdfDict {
    const d: PdfDict = new Map();
    for (;;) {
      const k = this.next();
      if (k === undefined || (k instanceof PdfOp && k.op === ">>")) break;
      if (!(k instanceof PdfName)) continue;
      const v = this.next();
      if (v instanceof PdfOp && v.op === ">>") break;
      if (v !== undefined) d.set(k.name, v);
    }
    return d;
  }

  private literalString(): Buffer {
    const b = this.b;
    this.pos++;
    const out: number[] = [];
    let depth = 1;
    while (this.pos < b.length) {
      const c = b[this.pos++]!;
      if (c === 0x5c) {
        const n = b[this.pos++]!;
        const map: Record<number, number> = { 0x6e: 10, 0x72: 13, 0x74: 9, 0x62: 8, 0x66: 12, 0x28: 0x28, 0x29: 0x29, 0x5c: 0x5c };
        if (n in map) out.push(map[n]!);
        else if (n >= 0x30 && n <= 0x37) {
          let v = n - 0x30;
          for (let i = 0; i < 2 && b[this.pos]! >= 0x30 && b[this.pos]! <= 0x37; i++) v = v * 8 + (b[this.pos++]! - 0x30);
          out.push(v & 0xff);
        } else if (n === 0x0d) {
          if (b[this.pos] === 0x0a) this.pos++;
        } else if (n !== 0x0a) out.push(n);
      } else if (c === 0x28) {
        depth++;
        out.push(c);
      } else if (c === 0x29) {
        if (--depth === 0) break;
        out.push(c);
      } else out.push(c);
    }
    return Buffer.from(out);
  }

  private hexString(): Buffer {
    this.pos++;
    const end = this.b.indexOf(0x3e, this.pos);
    const stop = end === -1 ? this.b.length : end;
    let hex = this.b.toString("latin1", this.pos, stop).replace(/[^0-9a-fA-F]/g, "");
    this.pos = stop + 1;
    if (hex.length % 2) hex += "0";
    return Buffer.from(hex, "hex");
  }
}

// ---------- Filters ----------

function ascii85(data: Buffer): Buffer {
  const s = data.toString("latin1").replace(/\s/g, "").replace(/^<~/, "").replace(/~>.*$/, "");
  const out: number[] = [];
  let group: number[] = [];
  for (const ch of s) {
    if (ch === "z" && group.length === 0) {
      out.push(0, 0, 0, 0);
      continue;
    }
    group.push(ch.charCodeAt(0) - 33);
    if (group.length === 5) {
      let v = 0;
      for (const g of group) v = v * 85 + g;
      out.push((v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255);
      group = [];
    }
  }
  if (group.length) {
    const n = group.length;
    while (group.length < 5) group.push(84);
    let v = 0;
    for (const g of group) v = v * 85 + g;
    const bytes = [(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255];
    out.push(...bytes.slice(0, n - 1));
  }
  return Buffer.from(out);
}

function inflate(data: Buffer): Buffer {
  try {
    return inflateSync(data);
  } catch {
    // Truncated or slightly damaged streams are common; take what decodes.
    try {
      return inflateSync(data, { finishFlush: zlibConstants.Z_SYNC_FLUSH });
    } catch {
      return Buffer.alloc(0);
    }
  }
}

function pngUnpredict(data: Buffer, columns: number, colors = 1, bpc = 8): Buffer {
  const bpp = Math.max(1, Math.ceil((colors * bpc) / 8));
  const rowLen = Math.ceil((columns * colors * bpc) / 8);
  const out: number[] = [];
  let prev = new Array<number>(rowLen).fill(0);
  for (let i = 0; i + rowLen < data.length + 1; i += rowLen + 1) {
    const type = data[i]!;
    const row = new Array<number>(rowLen);
    for (let j = 0; j < rowLen; j++) {
      const raw = data[i + 1 + j] ?? 0;
      const left = j >= bpp ? row[j - bpp]! : 0;
      const up = prev[j]!;
      const ul = j >= bpp ? prev[j - bpp]! : 0;
      let v = raw;
      if (type === 1) v = raw + left;
      else if (type === 2) v = raw + up;
      else if (type === 3) v = raw + ((left + up) >> 1);
      else if (type === 4) {
        const p = left + up - ul;
        const pa = Math.abs(p - left), pb = Math.abs(p - up), pc = Math.abs(p - ul);
        v = raw + (pa <= pb && pa <= pc ? left : pb <= pc ? up : ul);
      }
      row[j] = v & 255;
    }
    out.push(...row);
    prev = row;
  }
  return Buffer.from(out);
}

// ---------- Encryption (standard security handler) ----------

const PASSWORD_PAD = Buffer.from("28bf4e5e4e758a4164004e56fffa01082e2e00b6d0683e802f0ca9fe6453697a", "hex");

export function rc4(key: Buffer, data: Buffer): Buffer {
  const s = new Uint8Array(256);
  for (let i = 0; i < 256; i++) s[i] = i;
  for (let i = 0, j = 0; i < 256; i++) {
    j = (j + s[i]! + key[i % key.length]!) & 255;
    [s[i], s[j]] = [s[j]!, s[i]!];
  }
  const out = Buffer.alloc(data.length);
  for (let n = 0, i = 0, j = 0; n < data.length; n++) {
    i = (i + 1) & 255;
    j = (j + s[i]!) & 255;
    [s[i], s[j]] = [s[j]!, s[i]!];
    out[n] = data[n]! ^ s[(s[i]! + s[j]!) & 255]!;
  }
  return out;
}

function aesDecrypt(key: Buffer, data: Buffer): Buffer {
  if (data.length < 32 || data.length % 16) return Buffer.alloc(0);
  const algo = key.length === 32 ? "aes-256-cbc" : "aes-128-cbc";
  try {
    const d = createDecipheriv(algo, key, data.subarray(0, 16));
    return Buffer.concat([d.update(data.subarray(16)), d.final()]);
  } catch {
    const d = createDecipheriv(algo, key, data.subarray(0, 16));
    d.setAutoPadding(false);
    return Buffer.concat([d.update(data.subarray(16)), d.final()]);
  }
}

const md5 = (...parts: Buffer[]) => createHash("md5").update(Buffer.concat(parts)).digest();

/** Algorithm 2.B (ISO 32000-2) for revision 6. `udata` is the 48-byte U string for owner checks, empty for users. */
function hash2B(password: Buffer, salt: Buffer, udata: Buffer): Buffer {
  let k = createHash("sha256").update(Buffer.concat([password, salt, udata])).digest();
  for (let i = 0; ; i++) {
    const k1 = Buffer.concat(Array<Buffer>(64).fill(Buffer.concat([password, k, udata])));
    const cipher = createCipheriv("aes-128-cbc", k.subarray(0, 16), k.subarray(16, 32));
    cipher.setAutoPadding(false);
    const e = Buffer.concat([cipher.update(k1), cipher.final()]);
    let sum = 0;
    for (let j = 0; j < 16; j++) sum += e[j]!;
    k = createHash(["sha256", "sha384", "sha512"][sum % 3]!).update(e).digest();
    if (i >= 63 && e[e.length - 1]! <= i - 32) break;
  }
  return k.subarray(0, 32);
}

interface Crypt {
  decrypt(data: Buffer, num: number, gen: number): Buffer;
}

function bytesOf(v: PdfValue | undefined): Buffer {
  return Buffer.isBuffer(v) ? v : Buffer.alloc(0);
}

function setupCrypt(enc: PdfDict, id0: Buffer, password: string): Crypt {
  const filter = enc.get("Filter");
  if (!(filter instanceof PdfName) || filter.name !== "Standard") throw new PdfError("This PDF uses an encryption method other than a password, which Sooto cannot open.", "unsupported_encryption");
  const v = Number(enc.get("V") ?? 0);
  const r = Number(enc.get("R") ?? 0);
  const o = bytesOf(enc.get("O"));
  const u = bytesOf(enc.get("U"));
  const p = Number(enc.get("P") ?? 0);
  let aes = false;
  const cf = enc.get("CF");
  const stmf = enc.get("StmF");
  if (v === 4 && cf instanceof Map && stmf instanceof PdfName) {
    const f = cf.get(stmf.name);
    const cfm = f instanceof Map ? f.get("CFM") : undefined;
    if (cfm instanceof PdfName) aes = cfm.name === "AESV2";
    if (stmf.name === "Identity") return { decrypt: (d) => d };
  }

  if (r >= 5) {
    const pw = Buffer.from(password, "utf8").subarray(0, 127);
    const ue = bytesOf(enc.get("UE"));
    const check = r === 6 ? hash2B(pw, u.subarray(32, 40), Buffer.alloc(0)) : createHash("sha256").update(Buffer.concat([pw, u.subarray(32, 40)])).digest();
    if (!check.equals(u.subarray(0, 32))) throw passwordError(password);
    const ikey = r === 6 ? hash2B(pw, u.subarray(40, 48), Buffer.alloc(0)) : createHash("sha256").update(Buffer.concat([pw, u.subarray(40, 48)])).digest();
    const d = createDecipheriv("aes-256-cbc", ikey, Buffer.alloc(16));
    d.setAutoPadding(false);
    const fileKey = Buffer.concat([d.update(ue), d.final()]);
    return { decrypt: (data) => aesDecrypt(fileKey, data) };
  }

  const length = r === 2 ? 5 : Math.max(5, Math.min(16, Number(enc.get("Length") ?? 40) / 8));
  const pw = Buffer.concat([Buffer.from(password, "latin1"), PASSWORD_PAD]).subarray(0, 32);
  const pBytes = Buffer.alloc(4);
  pBytes.writeInt32LE(p | 0);
  const encryptMetadata = enc.get("EncryptMetadata") !== false;
  let key = md5(pw, o, pBytes, id0, r >= 4 && !encryptMetadata ? Buffer.from([255, 255, 255, 255]) : Buffer.alloc(0)).subarray(0, length);
  if (r >= 3) for (let i = 0; i < 50; i++) key = md5(key).subarray(0, length);

  let ok: boolean;
  if (r === 2) ok = rc4(key, PASSWORD_PAD).equals(u.subarray(0, 32));
  else {
    let x = rc4(key, md5(PASSWORD_PAD, id0));
    for (let i = 1; i <= 19; i++) x = rc4(Buffer.from(key.map((b) => b ^ i)), x);
    ok = x.subarray(0, 16).equals(u.subarray(0, 16));
  }
  if (!ok) throw passwordError(password);

  return {
    decrypt(data, num, gen) {
      const ext = Buffer.from([num & 255, (num >> 8) & 255, (num >> 16) & 255, gen & 255, (gen >> 8) & 255]);
      const objKey = md5(key, ext, aes ? Buffer.from("sAlT", "latin1") : Buffer.alloc(0)).subarray(0, Math.min(length + 5, 16));
      return aes ? aesDecrypt(objKey, data) : rc4(objKey, data);
    },
  };
}

function passwordError(password: string): PdfError {
  return password
    ? new PdfError("The password does not open this PDF. Banks usually send the statement password in the same email or by SMS.", "wrong_password")
    : new PdfError("This PDF is password-protected. Give the statement password (banks usually send it in the same email or by SMS).", "password_required");
}

// ---------- Document ----------

export class PdfDocument {
  private objects = new Map<number, { offset: number; gen: number } | { stream: number; index: number }>();
  private cache = new Map<number, PdfValue>();
  private crypt?: Crypt;
  readonly trailer: PdfDict = new Map();
  private readonly buf: Buffer;

  constructor(buf: Buffer, password = "") {
    this.buf = buf;
    if (buf.indexOf("%PDF-") === -1 || buf.indexOf("%PDF-") > 1024) throw new PdfError("This is not a PDF file.", "not_pdf");
    this.index();
    const enc = this.resolve(this.trailer.get("Encrypt"));
    if (enc instanceof Map) {
      const ids = this.trailer.get("ID");
      const id0 = Array.isArray(ids) ? bytesOf(ids[0]) : Buffer.alloc(0);
      const encRef = this.trailer.get("Encrypt");
      const crypt = setupCrypt(enc, id0, password);
      // The Encrypt dictionary itself is never encrypted.
      this.crypt = {
        decrypt: (d, num, gen) => (encRef instanceof PdfRef && encRef.num === num ? d : crypt.decrypt(d, num, gen)),
      };
    }
  }

  get encrypted(): boolean {
    return this.crypt !== undefined;
  }

  /** Finds every "n g obj" in the file (later definitions win, as in incremental updates) and the trailer(s). */
  private index(): void {
    const s = this.buf.toString("latin1");
    const re = /(?:^|[\s>\]])(\d+)\s+(\d+)\s+obj\b/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(s))) {
      const num = Number(m[1]);
      this.objects.set(num, { offset: m.index + m[0].length, gen: Number(m[2]) });
    }
    // Classic trailers.
    const tr = /trailer\s*<</g;
    while ((m = tr.exec(s))) {
      const d = new Lexer(this.buf, m.index + m[0].length - 2).next();
      if (d instanceof Map) for (const [k, v] of d) if (!this.trailer.has(k) || k === "Root" || k === "Encrypt" || k === "ID") this.trailer.set(k, v);
    }
    // Cross-reference streams carry the trailer keys, and object streams hold compressed objects.
    for (const [num] of [...this.objects]) {
      const v = this.rawObject(num);
      if (!v || typeof v !== "object" || !("kind" in v)) continue;
      const type = v.dict.get("Type");
      if (!(type instanceof PdfName)) continue;
      if (type.name === "XRef") {
        for (const k of ["Root", "Encrypt", "ID", "Info"]) if (!this.trailer.has(k) && v.dict.has(k)) this.trailer.set(k, v.dict.get(k)!);
      }
    }
    // Object streams are indexed lazily below, after encryption is known.
  }

  private objStmsIndexed = false;
  private indexObjectStreams(): void {
    if (this.objStmsIndexed) return;
    this.objStmsIndexed = true;
    for (const [num, loc] of [...this.objects]) {
      if (!("offset" in loc)) continue;
      const v = this.get(num);
      if (!v || typeof v !== "object" || !("kind" in v)) continue;
      const type = v.dict.get("Type");
      if (!(type instanceof PdfName) || type.name !== "ObjStm") continue;
      const data = this.decode(v);
      const n = Number(this.resolve(v.dict.get("N")) ?? 0);
      const lx = new Lexer(data);
      for (let i = 0; i < n; i++) {
        const objNum = lx.next();
        lx.next();
        if (typeof objNum === "number" && !this.objects.has(objNum)) this.objects.set(objNum, { stream: num, index: i });
      }
    }
  }

  /** Parses the object at a file offset without resolving references or decrypting. */
  private rawObject(num: number): PdfValue | undefined {
    const loc = this.objects.get(num);
    if (!loc || !("offset" in loc)) return undefined;
    const lx = new Lexer(this.buf, loc.offset);
    const v = lx.next();
    if (!(v instanceof Map)) return v;
    lx.skipWs();
    if (this.buf.toString("latin1", lx.pos, lx.pos + 6) !== "stream") return v;
    let start = lx.pos + 6;
    if (this.buf[start] === 0x0d) start++;
    if (this.buf[start] === 0x0a) start++;
    const len = v.get("Length");
    let end = -1;
    if (typeof len === "number" && start + len <= this.buf.length) {
      const after = this.buf.toString("latin1", start + len, start + len + 12);
      if (/^\s*endstream/.test(after)) end = start + len;
    }
    if (end === -1) {
      end = this.buf.indexOf("endstream", start, "latin1");
      if (end === -1) end = this.buf.length;
      while (end > start && (this.buf[end - 1] === 0x0a || this.buf[end - 1] === 0x0d)) end--;
    }
    return { kind: "stream", dict: v, raw: this.buf.subarray(start, end), num, gen: loc.gen };
  }

  get(num: number): PdfValue | undefined {
    if (this.cache.has(num)) return this.cache.get(num);
    let loc = this.objects.get(num);
    if (!loc) {
      this.indexObjectStreams();
      loc = this.objects.get(num);
    }
    let v: PdfValue | undefined;
    if (loc && "offset" in loc) v = this.rawObject(num);
    else if (loc) {
      const container = this.get(loc.stream);
      if (container && typeof container === "object" && "kind" in container) {
        const data = this.decode(container);
        const n = Number(this.resolve(container.dict.get("N")) ?? 0);
        const first = Number(this.resolve(container.dict.get("First")) ?? 0);
        const lx = new Lexer(data);
        let offset = -1;
        for (let i = 0; i < n; i++) {
          const objNum = lx.next();
          const off = lx.next();
          if (objNum === num && typeof off === "number") offset = off;
        }
        if (offset >= 0) v = new Lexer(data, first + offset).next();
      }
    }
    this.cache.set(num, v ?? null);
    return v;
  }

  resolve(v: PdfValue | undefined, depth = 0): PdfValue | undefined {
    if (v instanceof PdfRef && depth < 32) return this.resolve(this.get(v.num), depth + 1);
    return v;
  }

  dict(v: PdfValue | undefined): PdfDict | undefined {
    const r = this.resolve(v);
    if (r instanceof Map) return r;
    if (r && typeof r === "object" && "kind" in r) return r.dict;
    return undefined;
  }

  /** Decrypts and decodes a stream. */
  decode(s: PdfStream): Buffer {
    let data = this.crypt && !this.isXRef(s) ? this.crypt.decrypt(s.raw, s.num, s.gen) : s.raw;
    const f = this.resolve(s.dict.get("Filter"));
    const filters = (Array.isArray(f) ? f : f ? [f] : []).map((x) => (x instanceof PdfName ? x.name : ""));
    const p = this.resolve(s.dict.get("DecodeParms"));
    const params = (Array.isArray(p) ? p : [p]).map((x) => this.dict(x ?? undefined));
    filters.forEach((name, i) => {
      if (name === "FlateDecode" || name === "Fl") {
        data = inflate(data);
        const dp = params[i];
        const predictor = Number(dp?.get("Predictor") ?? 1);
        if (predictor >= 10) data = pngUnpredict(data, Number(dp?.get("Columns") ?? 1), Number(dp?.get("Colors") ?? 1), Number(dp?.get("BitsPerComponent") ?? 8));
      } else if (name === "ASCIIHexDecode" || name === "AHx") data = Buffer.from(data.toString("latin1").replace(/[^0-9a-fA-F]/g, "").replace(/^(.(..)*)$/, "$10"), "hex");
      else if (name === "ASCII85Decode" || name === "A85") data = ascii85(data);
      else if (name) data = Buffer.alloc(0);
    });
    return data;
  }

  private isXRef(s: PdfStream): boolean {
    const t = s.dict.get("Type");
    return t instanceof PdfName && t.name === "XRef";
  }

  /** Pages in document order, each with its inherited resources. */
  pages(): Array<{ dict: PdfDict; resources?: PdfDict }> {
    const out: Array<{ dict: PdfDict; resources?: PdfDict }> = [];
    let root = this.dict(this.trailer.get("Root"));
    if (!root) {
      this.indexObjectStreams();
      for (const num of this.objects.keys()) {
        const d = this.dict(this.get(num));
        const t = d?.get("Type");
        if (t instanceof PdfName && t.name === "Catalog") {
          root = d;
          break;
        }
      }
    }
    const walk = (node: PdfDict | undefined, inherited: PdfDict | undefined, depth: number) => {
      if (!node || depth > 50) return;
      const resources = this.dict(node.get("Resources")) ?? inherited;
      const kids = this.resolve(node.get("Kids"));
      if (Array.isArray(kids)) for (const k of kids) walk(this.dict(k), resources, depth + 1);
      else out.push({ dict: node, resources });
    };
    walk(this.dict(root?.get("Pages")), undefined, 0);
    return out;
  }
}

// ---------- Fonts ----------

const WIN_ANSI_EXTRA: Record<number, string> = {
  0x80: "€", 0x82: "‚", 0x83: "ƒ", 0x84: "„", 0x85: "…", 0x86: "†", 0x87: "‡", 0x88: "ˆ", 0x89: "‰", 0x8a: "Š", 0x8b: "‹", 0x8c: "Œ", 0x8e: "Ž",
  0x91: "‘", 0x92: "’", 0x93: "“", 0x94: "”", 0x95: "•", 0x96: "–", 0x97: "—", 0x98: "˜", 0x99: "™", 0x9a: "š", 0x9b: "›", 0x9c: "œ", 0x9e: "ž", 0x9f: "Ÿ",
};
const GLYPHS: Record<string, string> = {
  space: " ", exclam: "!", quotedbl: '"', numbersign: "#", dollar: "$", percent: "%", ampersand: "&", quotesingle: "'", quoteright: "’", parenleft: "(", parenright: ")",
  asterisk: "*", plus: "+", comma: ",", hyphen: "-", minus: "-", period: ".", slash: "/", zero: "0", one: "1", two: "2", three: "3", four: "4", five: "5", six: "6",
  seven: "7", eight: "8", nine: "9", colon: ":", semicolon: ";", less: "<", equal: "=", greater: ">", question: "?", at: "@", bracketleft: "[", backslash: "\\",
  bracketright: "]", underscore: "_", bar: "|", braceleft: "{", braceright: "}", endash: "–", emdash: "—", bullet: "•", naira: "₦", Euro: "€", sterling: "£", nbspace: " ",
};

interface Font {
  bytes: 1 | 2;
  decode(code: number): string;
  width(code: number): number;
}

function parseCMap(data: Buffer): { map: Map<number, string>; bytes: 1 | 2 } {
  const s = data.toString("latin1");
  const map = new Map<number, string>();
  const utf16 = (hex: string) => {
    const b = Buffer.from(hex.length % 4 ? hex.padStart(Math.ceil(hex.length / 4) * 4, "0") : hex, "hex");
    let out = "";
    for (let i = 0; i + 1 < b.length; i += 2) out += String.fromCharCode(b.readUInt16BE(i));
    return out;
  };
  let bytes: 1 | 2 = 1;
  const cs = /begincodespacerange([\s\S]*?)endcodespacerange/.exec(s);
  if (cs && /<[0-9a-fA-F]{4}>/.test(cs[1]!)) bytes = 2;
  for (const block of s.matchAll(/beginbfchar([\s\S]*?)endbfchar/g)) {
    for (const m of block[1]!.matchAll(/<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]*)>/g)) {
      if (m[1]!.length >= 4) bytes = 2;
      map.set(parseInt(m[1]!, 16), utf16(m[2]!));
    }
  }
  for (const block of s.matchAll(/beginbfrange([\s\S]*?)endbfrange/g)) {
    for (const m of block[1]!.matchAll(/<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]+)>\s*(<[0-9a-fA-F]*>|\[[^\]]*\])/g)) {
      const lo = parseInt(m[1]!, 16);
      const hi = parseInt(m[2]!, 16);
      if (m[1]!.length >= 4) bytes = 2;
      if (hi - lo > 65535) continue;
      if (m[3]!.startsWith("[")) {
        const items = [...m[3]!.matchAll(/<([0-9a-fA-F]*)>/g)].map((x) => x[1]!);
        items.forEach((h, i) => map.set(lo + i, utf16(h)));
      } else {
        const base = m[3]!.slice(1, -1);
        const b = Buffer.from(base.length % 4 ? base.padStart(Math.ceil(base.length / 4) * 4, "0") : base, "hex");
        for (let c = lo; c <= hi; c++) {
          const copy = Buffer.from(b);
          copy.writeUInt16BE((copy.readUInt16BE(copy.length - 2) + (c - lo)) & 0xffff, copy.length - 2);
          let out = "";
          for (let i = 0; i + 1 < copy.length; i += 2) out += String.fromCharCode(copy.readUInt16BE(i));
          map.set(c, out);
        }
      }
    }
  }
  return { map, bytes };
}

function loadFont(doc: PdfDocument, fd: PdfDict | undefined): Font {
  const fallback: Font = { bytes: 1, decode: (c) => String.fromCharCode(c), width: () => 0.5 };
  if (!fd) return fallback;
  const subtype = (doc.resolve(fd.get("Subtype")) as PdfName | undefined)?.name;
  const composite = subtype === "Type0";
  let toUnicode: Map<number, string> | undefined;
  let bytes: 1 | 2 = composite ? 2 : 1;
  const tu = doc.resolve(fd.get("ToUnicode"));
  if (tu && typeof tu === "object" && "kind" in tu) {
    const cm = parseCMap(doc.decode(tu));
    toUnicode = cm.map;
    if (!composite) bytes = 1;
  }

  // Widths, in glyph space units / 1000.
  let width: (code: number) => number = () => 0.5;
  if (composite) {
    const desc = doc.dict((doc.resolve(fd.get("DescendantFonts")) as PdfValue[] | undefined)?.[0]);
    const dw = Number(doc.resolve(desc?.get("DW")) ?? 1000);
    const w = doc.resolve(desc?.get("W"));
    const widths = new Map<number, number>();
    if (Array.isArray(w)) {
      for (let i = 0; i < w.length; ) {
        const first = Number(doc.resolve(w[i]));
        const next = doc.resolve(w[i + 1]);
        if (Array.isArray(next)) {
          next.forEach((x, j) => widths.set(first + j, Number(doc.resolve(x))));
          i += 2;
        } else {
          const last = Number(next);
          const val = Number(doc.resolve(w[i + 2]));
          for (let c = first; c <= last && c - first < 65536; c++) widths.set(c, val);
          i += 3;
        }
      }
    }
    width = (c) => (widths.get(c) ?? dw) / 1000;
  } else {
    const first = Number(doc.resolve(fd.get("FirstChar")) ?? 0);
    const ws = doc.resolve(fd.get("Widths"));
    if (Array.isArray(ws)) width = (c) => Number(doc.resolve(ws[c - first]) ?? 500) / 1000 || 0.5;
    else {
      // Standard 14 fonts without /Widths: approximate Helvetica-like widths.
      width = (c) => (c === 32 ? 0.278 : c >= 48 && c <= 57 ? 0.556 : c >= 65 && c <= 90 ? 0.667 : 0.5);
    }
  }

  let decode: (code: number) => string;
  if (toUnicode) {
    const tuMap = toUnicode;
    decode = (c) => tuMap.get(c) ?? (bytes === 1 ? String.fromCharCode(c) : "");
  } else if (composite) {
    decode = () => "";
  } else {
    const differences = new Map<number, string>();
    const enc = doc.resolve(fd.get("Encoding"));
    const encDict = enc instanceof Map ? enc : undefined;
    const diffs = doc.resolve(encDict?.get("Differences"));
    if (Array.isArray(diffs)) {
      let code = 0;
      for (const d of diffs) {
        const r = doc.resolve(d);
        if (typeof r === "number") code = r;
        else if (r instanceof PdfName) {
          const g = r.name;
          const ch = GLYPHS[g] ?? (g.length === 1 ? g : /^uni[0-9A-F]{4}$/.test(g) ? String.fromCharCode(parseInt(g.slice(3), 16)) : undefined);
          if (ch !== undefined) differences.set(code, ch);
          code++;
        }
      }
    }
    decode = (c) => differences.get(c) ?? WIN_ANSI_EXTRA[c] ?? String.fromCharCode(c);
  }
  return { bytes, decode, width };
}

// ---------- Content streams ----------

export interface TextItem {
  page: number;
  x: number;
  y: number;
  /** x where the text ends, from glyph widths. */
  x2: number;
  size: number;
  text: string;
}

type Matrix = [number, number, number, number, number, number];
const mul = (m: Matrix, n: Matrix): Matrix => [
  m[0] * n[0] + m[1] * n[2],
  m[0] * n[1] + m[1] * n[3],
  m[2] * n[0] + m[3] * n[2],
  m[2] * n[1] + m[3] * n[3],
  m[4] * n[0] + m[5] * n[2] + n[4],
  m[4] * n[1] + m[5] * n[3] + n[5],
];
const IDENTITY: Matrix = [1, 0, 0, 1, 0, 0];

function runContent(doc: PdfDocument, data: Buffer, resources: PdfDict | undefined, pageNo: number, ctm0: Matrix, items: TextItem[], depth: number): void {
  if (depth > 8) return;
  const fontCache = new Map<string, Font>();
  const fontDict = doc.dict(resources?.get("Font"));
  const xobjects = doc.dict(resources?.get("XObject"));
  const getFont = (name: string) => {
    if (!fontCache.has(name)) fontCache.set(name, loadFont(doc, doc.dict(fontDict?.get(name))));
    return fontCache.get(name)!;
  };

  let ctm = ctm0;
  const stack: Array<{ ctm: Matrix; font?: Font; size: number; tc: number; tw: number; th: number; tl: number; rise: number }> = [];
  let font: Font | undefined;
  let size = 10, tc = 0, tw = 0, th = 1, tl = 0, rise = 0;
  let tm: Matrix = IDENTITY;
  let tlm: Matrix = IDENTITY;
  const operands: PdfValue[] = [];
  const lx = new Lexer(data, 0, true);

  const show = (strings: PdfValue[]) => {
    if (!font) font = getFont("");
    let text = "";
    let start: Matrix | undefined;
    let effSize = size;
    const flush = () => {
      if (!start || !text.trim()) {
        text = "";
        start = undefined;
        return;
      }
      const end = mul([1, 0, 0, 1, 0, rise], mul(tm, ctm));
      items.push({ page: pageNo, x: start[4], y: start[5], x2: end[4], size: effSize, text });
      text = "";
      start = undefined;
    };
    for (const s of strings) {
      if (typeof s === "number") {
        const shift = (-s / 1000) * size * th;
        // A big gap inside one TJ is a column break, not kerning.
        if (shift > size * 0.9) flush();
        tm = mul([1, 0, 0, 1, shift, 0], tm);
        continue;
      }
      if (!Buffer.isBuffer(s)) continue;
      for (let i = 0; i < s.length; ) {
        const code = font.bytes === 2 && i + 1 < s.length ? s.readUInt16BE(i) : s[i]!;
        const n = font.bytes === 2 && i + 1 < s.length ? 2 : 1;
        i += n;
        if (!start) {
          const m = mul([1, 0, 0, 1, 0, rise], mul(tm, ctm));
          start = m;
          effSize = Math.abs(size * Math.hypot(m[2], m[3])) || size;
        }
        text += font.decode(code);
        const adv = (font.width(code) * size + tc + (n === 1 && code === 32 ? tw : 0)) * th;
        tm = mul([1, 0, 0, 1, adv, 0], tm);
      }
    }
    flush();
  };

  for (let guard = 0; guard < 2_000_000; guard++) {
    const t = lx.next();
    if (t === undefined) break;
    if (!(t instanceof PdfOp)) {
      operands.push(t);
      continue;
    }
    const op = t.op;
    const num = (i: number) => Number(operands[i] ?? 0);
    switch (op) {
      case "q":
        stack.push({ ctm, font, size, tc, tw, th, tl, rise });
        break;
      case "Q": {
        const s = stack.pop();
        if (s) ({ ctm, font, size, tc, tw, th, tl, rise } = s);
        break;
      }
      case "cm":
        if (operands.length >= 6) ctm = mul([num(0), num(1), num(2), num(3), num(4), num(5)], ctm);
        break;
      case "BT":
        tm = tlm = IDENTITY;
        break;
      case "Tf": {
        const name = operands[0];
        if (name instanceof PdfName) font = getFont(name.name);
        size = num(1);
        break;
      }
      case "Tc": tc = num(0); break;
      case "Tw": tw = num(0); break;
      case "Tz": th = num(0) / 100; break;
      case "TL": tl = num(0); break;
      case "Ts": rise = num(0); break;
      case "Td":
        tlm = mul([1, 0, 0, 1, num(0), num(1)], tlm);
        tm = tlm;
        break;
      case "TD":
        tl = -num(1);
        tlm = mul([1, 0, 0, 1, num(0), num(1)], tlm);
        tm = tlm;
        break;
      case "Tm":
        tlm = tm = [num(0), num(1), num(2), num(3), num(4), num(5)];
        break;
      case "T*":
        tlm = mul([1, 0, 0, 1, 0, -tl], tlm);
        tm = tlm;
        break;
      case "Tj":
        show([operands[0] ?? Buffer.alloc(0)]);
        break;
      case "'":
        tlm = mul([1, 0, 0, 1, 0, -tl], tlm);
        tm = tlm;
        show([operands[0] ?? Buffer.alloc(0)]);
        break;
      case '"':
        tw = num(0);
        tc = num(1);
        tlm = mul([1, 0, 0, 1, 0, -tl], tlm);
        tm = tlm;
        show([operands[2] ?? Buffer.alloc(0)]);
        break;
      case "TJ":
        if (Array.isArray(operands[0])) show(operands[0]);
        break;
      case "Do": {
        const name = operands[0];
        if (!(name instanceof PdfName)) break;
        const xo = doc.resolve(xobjects?.get(name.name));
        if (xo && typeof xo === "object" && "kind" in xo) {
          const st = doc.resolve(xo.dict.get("Subtype"));
          if (st instanceof PdfName && st.name === "Form") {
            const m = doc.resolve(xo.dict.get("Matrix"));
            const fm: Matrix = Array.isArray(m) && m.length === 6 ? (m.map((v) => Number(v)) as Matrix) : IDENTITY;
            runContent(doc, doc.decode(xo), doc.dict(xo.dict.get("Resources")) ?? resources, pageNo, mul(fm, ctm), items, depth + 1);
          }
        }
        break;
      }
      case "BI": {
        // Inline image: skip to EI.
        const end = data.indexOf("EI", lx.pos, "latin1");
        lx.pos = end === -1 ? data.length : end + 2;
        break;
      }
    }
    operands.length = 0;
  }
}

/** Every piece of text in the PDF with its position (points from the bottom-left of its page). */
export function extractText(buf: Buffer, opts: { password?: string } = {}): { items: TextItem[]; pages: number; encrypted: boolean } {
  const doc = new PdfDocument(buf, opts.password ?? "");
  const pages = doc.pages();
  const items: TextItem[] = [];
  pages.forEach((p, i) => {
    const contents = doc.resolve(p.dict.get("Contents"));
    const parts = (Array.isArray(contents) ? contents : [contents]).map((c) => doc.resolve(c));
    const data = Buffer.concat(parts.flatMap((s) => (s && typeof s === "object" && "kind" in s ? [doc.decode(s), Buffer.from("\n")] : [])));
    runContent(doc, data, p.resources, i + 1, IDENTITY, items, 0);
  });
  return { items, pages: pages.length, encrypted: doc.encrypted };
}
