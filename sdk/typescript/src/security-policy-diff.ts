// Adapted from CPython 3.12.10 difflib's SequenceMatcher and unified_diff.
// See PYTHON-DIFFLIB-LICENSE.txt. This subset compares lines with default
// autojunk behavior, yields for cancellation, and marks missing final newlines.
import { setImmediate } from "node:timers/promises";

type Match = [before: number, after: number, length: number];
type Range = [
  beforeStart: number,
  beforeEnd: number,
  afterStart: number,
  afterEnd: number,
];
type Opcode = [tag: "equal" | "replace" | "delete" | "insert", ...range: Range];

function lines(text: string): string[] {
  const parts = text.split("\n");
  const last = parts.pop()!;
  return [...parts.map((part) => `${part}\n`), ...(last ? [last] : [])];
}

async function matchingBlocks(
  a: string[],
  b: string[],
  signal?: AbortSignal,
): Promise<Match[]> {
  const positions = new Map<string, number[]>();
  for (let index = 0; index < b.length; index++) {
    const line = b[index]!;
    const indices = positions.get(line);
    if (indices) indices.push(index);
    else positions.set(line, [index]);
  }
  if (b.length >= 200) {
    const popular = Math.floor(b.length / 100) + 1;
    for (const [line, indices] of positions) {
      if (indices.length > popular) positions.delete(line);
    }
  }
  const pending: Range[] = [[0, a.length, 0, b.length]];
  const matches: Match[] = [];
  let steps = 0;
  while (pending.length) {
    const [alo, ahi, blo, bhi] = pending.pop()!;
    let besti = alo,
      bestj = blo,
      bestsize = 0;
    let lengths = new Map<number, number>();
    for (let i = alo; i < ahi; i++) {
      if (++steps % 4096 === 0) await setImmediate(undefined, { signal });
      const next = new Map<number, number>();
      for (const j of positions.get(a[i]!) ?? []) {
        if (++steps % 4096 === 0) await setImmediate(undefined, { signal });
        if (j < blo) continue;
        if (j >= bhi) break;
        const length = (lengths.get(j - 1) ?? 0) + 1;
        next.set(j, length);
        if (length > bestsize) {
          besti = i - length + 1;
          bestj = j - length + 1;
          bestsize = length;
        }
      }
      lengths = next;
    }
    // Popular lines cannot start a match, but can extend an existing one.
    while (besti > alo && bestj > blo && a[besti - 1] === b[bestj - 1]) {
      if (++steps % 4096 === 0) await setImmediate(undefined, { signal });
      besti--;
      bestj--;
      bestsize++;
    }
    while (
      besti + bestsize < ahi &&
      bestj + bestsize < bhi &&
      a[besti + bestsize] === b[bestj + bestsize]
    ) {
      if (++steps % 4096 === 0) await setImmediate(undefined, { signal });
      bestsize++;
    }
    if (bestsize) {
      matches.push([besti, bestj, bestsize]);
      if (alo < besti && blo < bestj) pending.push([alo, besti, blo, bestj]);
      if (besti + bestsize < ahi && bestj + bestsize < bhi)
        pending.push([besti + bestsize, ahi, bestj + bestsize, bhi]);
    }
  }
  matches.sort((x, y) => x[0] - y[0] || x[1] - y[1] || x[2] - y[2]);
  const combined: Match[] = [];
  for (const match of matches) {
    const last = combined.at(-1);
    if (
      last &&
      last[0] + last[2] === match[0] &&
      last[1] + last[2] === match[1]
    )
      last[2] += match[2];
    else combined.push(match);
  }
  combined.push([a.length, b.length, 0]);
  return combined;
}

function* groups(matches: Match[]): Generator<Opcode[]> {
  const codes: Opcode[] = [];
  let i = 0,
    j = 0;
  for (const [ai, bj, size] of matches) {
    if (i < ai || j < bj)
      codes.push([
        i < ai ? (j < bj ? "replace" : "delete") : "insert",
        i,
        ai,
        j,
        bj,
      ]);
    i = ai + size;
    j = bj + size;
    if (size) codes.push(["equal", ai, i, bj, j]);
  }
  if (!codes.length) return;
  const first = codes[0]!,
    last = codes.at(-1)!;
  if (first[0] === "equal") {
    first[1] = Math.max(first[1], first[2] - 3);
    first[3] = Math.max(first[3], first[4] - 3);
  }
  if (last[0] === "equal") {
    last[2] = Math.min(last[2], last[1] + 3);
    last[4] = Math.min(last[4], last[3] + 3);
  }
  let group: Opcode[] = [];
  for (let [tag, i1, i2, j1, j2] of codes) {
    if (tag === "equal" && i2 - i1 > 6) {
      group.push([tag, i1, i1 + 3, j1, j1 + 3]);
      yield group;
      group = [];
      i1 = i2 - 3;
      j1 = j2 - 3;
    }
    group.push([tag, i1, i2, j1, j2]);
  }
  if (group.length && !(group.length === 1 && group[0]![0] === "equal"))
    yield group;
}

function formatRange(start: number, end: number): string {
  const length = end - start;
  return length === 1
    ? `${start + 1}`
    : `${start + (length ? 1 : 0)},${length}`;
}

export async function unifiedPolicyDiff(
  before: string,
  after: string,
  fromfile: string,
  tofile: string,
  signal?: AbortSignal,
): Promise<string> {
  signal?.throwIfAborted();
  if (before === after) return "";
  const a = lines(before),
    b = lines(after);
  const output: string[] = [];
  const append = (prefix: string, line: string) => {
    output.push(prefix + line);
    if (!line.endsWith("\n")) output.push("\n\\ No newline at end of file\n");
  };
  for (const group of groups(await matchingBlocks(a, b, signal))) {
    if (!output.length) output.push(`--- ${fromfile}\n+++ ${tofile}\n`);
    const first = group[0]!,
      last = group.at(-1)!;
    output.push(
      `@@ -${formatRange(first[1], last[2])} +${formatRange(first[3], last[4])} @@\n`,
    );
    for (const [tag, i1, i2, j1, j2] of group) {
      if (tag === "equal") for (let i = i1; i < i2; i++) append(" ", a[i]!);
      if (tag === "replace" || tag === "delete")
        for (let i = i1; i < i2; i++) append("-", a[i]!);
      if (tag === "replace" || tag === "insert")
        for (let j = j1; j < j2; j++) append("+", b[j]!);
    }
  }
  signal?.throwIfAborted();
  return output.join("");
}
