// The live editor's pure parts, without DOM or network, so Node can test them: line numbers and
// presence, selections carried through a change, the backoff, the stream address, and the rebase
// of what was typed before the first `init`.
import { apply, cpLength, cpToUnit, diff, transform, unitToCp, wellFormed } from "./ot.js";

const BACKOFF_MS = 500;
const BACKOFF_CAP_MS = 8000;

// The line, from 1, that code-point position `cp` of `text` is on.
export function lineOf(text, cp) {
  const end = cpToUnit(text, cp);
  let line = 1;
  for (let i = text.indexOf("\n"); i !== -1 && i < end; i = text.indexOf("\n", i + 1)) line += 1;
  return line;
}

// The UTF-16 index where line `n` (from 0) begins, or the text's end.
export function lineStart(text, n) {
  let at = 0;
  for (let i = 0; i < n; i += 1) {
    const next = text.indexOf("\n", at);
    if (next === -1) return text.length;
    at = next + 1;
  }
  return at;
}

// The presence row for a `peers` event: everyone counted, you included, and a chip per other person.
export function presence(peers, me, text) {
  const others = peers.filter((p) => p.peer !== me).sort((a, b) => a.peer - b.peer);
  const count = others.length + 1;
  const label = count === 1 ? "1 person here" : `${count} people here`;
  return { label, chips: others.map((p) => `line ${lineOf(text, p.pos)}`) };
}

// A textarea selection (UTF-16 units of `oldText`) carried through `map` into `newText`. A caret
// stays before text inserted at it, so a person's own typing stays together.
export function mapSelection(oldText, newText, start, end, map) {
  const limit = cpLength(oldText);
  const at = (unit, sticky) => cpToUnit(newText, map(Math.min(unitToCp(oldText, unit), limit), sticky));
  if (start === end) {
    const caret = at(start, true);
    return [caret, caret];
  }
  return [at(start, false), at(end, true)];
}

// Whether the text before UTF-16 index `unit` of `oldText` is unchanged in `newText`.
export function keepsAbove(oldText, newText, unit, map) {
  const moved = cpToUnit(newText, map(unitToCp(oldText, unit), true));
  return oldText.slice(0, unit) === newText.slice(0, moved);
}

export function backoff(attempt) {
  return Math.min(BACKOFF_MS * 2 ** attempt, BACKOFF_CAP_MS);
}

export function streamUrl({ live, grant, client, last }) {
  const q = new URLSearchParams();
  if (grant) q.set("g", grant);
  if (client) {
    q.set("client", client);
    q.set("last", String(last));
  }
  const query = q.toString();
  return query ? `${live}/events?${query}` : `${live}/events`;
}

// What was typed (`typed`) over the page's text (`base`) before the session's text (`theirs`)
// arrived, kept on top of it.
export function rebase(base, typed, theirs) {
  const from = wellFormed(base);
  const [, mine] = transform(diff(from, wellFormed(theirs)), diff(from, wellFormed(typed)));
  return apply(wellFormed(theirs), mine);
}

export const syntaxValue = {
  send: (value) => (value === "auto" ? null : value),
  show: (syntax) => syntax ?? "auto",
};
