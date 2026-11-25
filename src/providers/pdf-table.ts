// Rebuilds a statement table from positioned PDF text.
//
// A PDF has no table, only text drawn at coordinates. This module:
//   1. groups text into lines by height on the page, and lines into cells by the gaps between them;
//   2. finds the header row ("Date", "Narration", "Debit", "Credit", "Balance", …) and takes each
//      header's horizontal extent as a column;
//   3. places every cell in the column it overlaps most, so empty cells (a row with no debit) stay empty;
//   4. joins narration lines that wrap onto the next line back into their row;
//   5. skips repeated page headers and footers;
// and returns CSV that parseStatement reads like any other export.
import { headerFieldOf, type Field } from "./statement.ts";
import { extractText, PdfError, type TextItem } from "./pdf.ts";

export interface Cell {
  x: number;
  x2: number;
  text: string;
}

export interface Line {
  page: number;
  y: number;
  size: number;
  cells: Cell[];
}

/** Groups items into lines (top to bottom, page by page) and each line into cells. */
export function toLines(items: TextItem[]): Line[] {
  const lines: Line[] = [];
  const byPage = new Map<number, TextItem[]>();
  for (const it of items) {
    if (!byPage.has(it.page)) byPage.set(it.page, []);
    byPage.get(it.page)!.push(it);
  }
  for (const page of [...byPage.keys()].sort((a, b) => a - b)) {
    const sorted = byPage.get(page)!.sort((a, b) => b.y - a.y || a.x - b.x);
    const groups: TextItem[][] = [];
    for (const it of sorted) {
      const g = groups.at(-1);
      if (g && Math.abs(g[0]!.y - it.y) <= Math.max(1.5, 0.35 * Math.max(g[0]!.size, it.size))) g.push(it);
      else groups.push([it]);
    }
    for (const g of groups) {
      g.sort((a, b) => a.x - b.x);
      const size = Math.max(...g.map((i) => i.size));
      const cells: Cell[] = [];
      for (const it of g) {
        const last = cells.at(-1);
        const gap = last ? it.x - last.x2 : Infinity;
        if (last && gap <= 0.8 * size) {
          last.text += (gap > 0.15 * size && !last.text.endsWith(" ") && !it.text.startsWith(" ") ? " " : "") + it.text;
          last.x2 = Math.max(last.x2, it.x2);
        } else cells.push({ x: it.x, x2: Math.max(it.x2, it.x + 1), text: it.text });
      }
      for (const c of cells) c.text = c.text.replace(/\s+/g, " ").trim();
      lines.push({ page, y: g[0]!.y, size, cells: cells.filter((c) => c.text) });
    }
  }
  return lines;
}

interface Column {
  field: Field;
  name: string;
  x: number;
  x2: number;
}

function headerColumns(line: Line): Column[] | undefined {
  const cols: Column[] = [];
  for (const c of line.cells) {
    const field = headerFieldOf(c.text);
    if (field && !cols.some((k) => k.field === field)) cols.push({ field, name: c.text, x: c.x, x2: c.x2 });
  }
  const fields = new Set(cols.map((c) => c.field));
  const hasDate = fields.has("date") || fields.has("value_date");
  const hasMoney = fields.has("amount") || fields.has("debit") || fields.has("credit");
  return hasDate && hasMoney && cols.length >= 3 ? cols : undefined;
}

/** The column a cell belongs to: most horizontal overlap, else the nearest. */
function columnFor(cell: Cell, cols: Column[]): Column {
  let best = cols[0]!;
  let bestScore = -Infinity;
  for (const col of cols) {
    const overlap = Math.min(cell.x2, col.x2) - Math.max(cell.x, col.x);
    const distance = overlap > 0 ? 0 : Math.min(Math.abs(cell.x - col.x2), Math.abs(col.x - cell.x2));
    const score = overlap > 0 ? overlap : -distance;
    if (score > bestScore) {
      bestScore = score;
      best = col;
    }
  }
  return best;
}

const MONEY = new Set<Field>(["debit", "credit", "amount", "balance"]);

/** The start of a date, even when the rest wrapped to the next line ("26-Sep-" then "2026"). */
const startsLikeDate = (s: string) => /^\d{1,2}[-/. ][A-Za-z0-9]{1,9}/.test(s) || /^\d{4}[-/.]\d{1,2}/.test(s) || /^[A-Za-z]{3,9} \d{1,2}/.test(s);

const csvCell = (s: string) => (/[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s);

export interface PdfTable {
  csv: string;
  /** Text above the first header row: bank name, account holder, account number, period. */
  preamble: string[];
  rows: number;
  pages: number;
}

/** Turns extracted PDF text into CSV for parseStatement. */
export function linesToCsv(lines: Line[]): PdfTable {
  let cols: Column[] | undefined;
  const preamble: string[] = [];
  const out: Array<Partial<Record<Field, string>>> = [];
  let header: Column[] | undefined;
  let lastRowLine: Line | undefined;

  for (const line of lines) {
    const h = headerColumns(line);
    if (h) {
      // First header defines the output columns; repeats (one per page) re-anchor positions only.
      cols = h;
      header ??= h;
      lastRowLine = undefined;
      continue;
    }
    if (!cols) {
      preamble.push(line.cells.map((c) => c.text).join("  "));
      continue;
    }
    const row: Partial<Record<Field, string>> = {};
    let alignedToColumns = true;
    for (const cell of line.cells) {
      const col = columnFor(cell, cols);
      if (cell.x < col.x - 0.6 * line.size && !MONEY.has(col.field)) alignedToColumns = false;
      row[col.field] = row[col.field] ? `${row[col.field]} ${cell.text}` : cell.text;
    }
    const dateField: Field = cols.some((c) => c.field === "date") ? "date" : "value_date";
    const hasMoney = [...MONEY].some((f) => row[f]);
    if (row[dateField] && startsLikeDate(row[dateField]!) && (hasMoney || row.description)) {
      out.push(row);
      lastRowLine = line;
      continue;
    }
    // A continuation line: a narration (or a date) that wrapped inside its cell. It has no amounts,
    // starts where its column starts, and sits just below the previous line of the row.
    const prev = out.at(-1);
    if (prev && lastRowLine && !hasMoney && alignedToColumns && line.page === lastRowLine.page && lastRowLine.y - line.y <= 1.8 * line.size) {
      for (const f of Object.keys(row) as Field[]) {
        const joiner = prev[f] && /[-/.]$/.test(prev[f]!) && (f === "date" || f === "value_date") ? "" : " ";
        prev[f] = prev[f] ? `${prev[f]}${joiner}${row[f]}` : row[f];
      }
      lastRowLine = line;
      continue;
    }
    // Anything else (totals, page numbers, footers) ends the current row's continuation.
    lastRowLine = undefined;
  }

  if (!header) return { csv: "", preamble, rows: 0, pages: lines.at(-1)?.page ?? 0 };
  const fields = header.map((c) => c.field);
  const csv = [header.map((c) => csvCell(c.name)).join(","), ...out.map((r) => fields.map((f) => csvCell(r[f] ?? "")).join(","))].join("\n");
  return { csv, preamble, rows: out.length, pages: lines.at(-1)?.page ?? 0 };
}

export interface PdfStatementText extends PdfTable {
  encrypted: boolean;
}

/**
 * PDF bytes to statement CSV. Throws PdfError for a missing or wrong password or an unreadable file,
 * and a "no_text" PdfError for scanned statements, which are images and need OCR.
 */
export function readPdfStatement(buf: Buffer, password = ""): PdfStatementText {
  const { items, encrypted } = extractText(buf, { password });
  if (!items.length) throw new PdfError("This PDF has no text layer: it is probably a scan or a photo. Download the statement again from the bank's app or internet banking, which gives a text PDF or CSV.", "no_text");
  const table = linesToCsv(toLines(items));
  if (!table.rows) throw new PdfError("No statement table was found in this PDF (no header row with a date and an amount, debit or credit column). If the bank offers a CSV or Excel export, use that instead.", "no_text");
  return { ...table, encrypted };
}
