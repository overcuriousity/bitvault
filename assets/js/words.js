// Paste words in the browser: reading what someone typed as an address, the way the server's
// `words::parse_typed` does, and offering the words that fit the one being typed. The list is
// the server's, sorted, one word per line in `bip39-english.txt`.

// Four letters always name one word in this list.
const PREFIX_LEN = 4;
const SEPARATORS = /[\s-]+/;
// Chips start at the second letter; one letter fits too many words to be a useful list.
const CHIPS_FROM = 2;
const CHIP_LIMIT = 6;

/** The index of the word `part` spells in full or, from four letters, is the only word to begin; or -1. */
export function findIn(words, part) {
  const exact = words.indexOf(part);
  if (exact !== -1) return exact;
  if (part.length < PREFIX_LEN) return -1;
  const fits = [];
  for (let i = 0; i < words.length && fits.length < 2; i++) if (words[i].startsWith(part)) fits.push(i);
  return fits.length === 1 ? fits[0] : -1;
}

// Every way to read `s` as exactly `count` whole words, as lists of words.
function wholeWords(words, s, count) {
  if (count === 0) return s === "" ? [[]] : [];
  if (s.length < 3 * count || s.length > 8 * count) return [];
  const out = [];
  for (let len = 3; len <= Math.min(8, s.length); len++) {
    const head = s.slice(0, len);
    if (words.indexOf(head) === -1) continue;
    for (const tail of wholeWords(words, s.slice(len), count - 1)) out.push([head, ...tail]);
  }
  return out;
}

function readParts(words, parts, done, out) {
  if (parts.length === 0) {
    if (done.length === 3) out.push(done);
    return;
  }
  const [part, ...rest] = parts;
  const one = findIn(words, part);
  if (one !== -1) readParts(words, rest, [...done, words[one]], out);
  for (let count = 2; count <= 3 - done.length; count++) {
    for (const split of wholeWords(words, part, count)) readParts(words, rest, [...done, ...split], out);
  }
}

/**
 * What `value` reads as: `{ address: "apple-banana-cherry" }`, `{ ambiguous: true }` for letters
 * run together that read two ways, or null when it is not three paste words.
 */
export function readAddress(value, words) {
  if (value.length > 64) return null;
  const parts = value.toLowerCase().split(SEPARATORS).filter(Boolean);
  if (parts.length === 3) {
    const found = parts.map((p) => findIn(words, p));
    return found.includes(-1) ? null : { address: found.map((i) => words[i]).join("-") };
  }
  if (parts.length !== 1 && parts.length !== 2) return null;
  const readings = [];
  readParts(words, parts, [], readings);
  if (readings.length === 1) return { address: readings[0].join("-") };
  return readings.length > 1 ? { ambiguous: true } : null;
}

/**
 * Whether `value` could still become three paste words: one line of at most three letter runs,
 * each finished one a paste word (or words run together), and a third one that begins a word.
 * Without the word list only the shape is checked.
 */
export function addressLike(value, words) {
  if (value.includes("\n") || value.length > 64 || /[^\sa-z-]/i.test(value)) return false;
  const parts = value.toLowerCase().split(SEPARATORS).filter(Boolean);
  if (parts.length > 3) return false;
  if (!words) return true;
  const ended = /[\s-]$/.test(value);
  const finished = ended ? parts : parts.slice(0, -1);
  const readable = (p) => findIn(words, p) !== -1 || wholeWords(words, p, 2).length > 0 || wholeWords(words, p, 3).length > 0;
  if (!finished.every(readable)) return false;
  const last = ended ? null : parts[parts.length - 1];
  return !(last && parts.length === 3 && !words.some((w) => w.startsWith(last)));
}

/**
 * The words that fit the one being typed, while the box still looks like an address: one line,
 * at most three words so far, each finished one a paste word. Null otherwise.
 */
export function chips(value, words, limit = CHIP_LIMIT) {
  if (value.includes("\n")) return null;
  const match = /^(\s*(?:[^\s-]+[\s-]+){0,2})([a-zA-Z]+)$/.exec(value);
  if (!match) return null;
  const [, done, part] = match;
  if (part.length < CHIPS_FROM) return null;
  const finished = done.toLowerCase().split(SEPARATORS).filter(Boolean);
  if (finished.some((w) => findIn(words, w) === -1)) return null;
  const prefix = part.toLowerCase();
  const fits = [];
  for (const w of words) {
    if (!w.startsWith(prefix)) continue;
    fits.push(w);
    if (fits.length >= limit) break;
  }
  // A finished last word needs no list.
  if (fits.length === 0 || (fits.length === 1 && fits[0] === prefix && finished.length === 2)) return null;
  return { done, part, fits, count: finished.length + 1 };
}

/**
 * The box after choosing `word` for the word being typed: followed by a separator unless it is the
 * third word, in the separator already used. Null when there is nothing to change.
 */
export function choose(value, words, word) {
  const found = chips(value, words, Number.POSITIVE_INFINITY);
  if (!found || !found.fits.includes(word)) return null;
  const separator = found.count < 3 ? (/\s$/.test(found.done) ? " " : "-") : "";
  const next = found.done + word + separator;
  return next === value ? null : next;
}

/** Tab takes the first word in the list. */
export function accept(value, words) {
  const found = chips(value, words);
  return found ? choose(value, words, found.fits[0]) : null;
}
