import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { accept, completion, suggestions } from "./words.js";

const WORDS = readFileSync(new URL("../bip39-english.txt", import.meta.url), "utf8").split("\n").filter(Boolean);

test("the word being typed is completed after the words before it", () => {
  assert.deepEqual(suggestions("happ", WORDS), ["happy"]);
  assert.deepEqual(suggestions("happy appl", WORDS), ["happy apple"]);
  assert.deepEqual(suggestions("happy-apple-bana", WORDS), ["happy-apple-banana"]);
  assert.deepEqual(suggestions("Happy  BAN", WORDS), ["Happy  banana", "Happy  banner"]);
});

test("suggestions are capped and empty when nothing is being typed", () => {
  assert.equal(suggestions("a", WORDS).length, 12);
  assert.deepEqual(suggestions("", WORDS), []);
  assert.deepEqual(suggestions("happy ", WORDS), []);
  assert.deepEqual(suggestions("happy apple banana cherry", WORDS), []);
  assert.deepEqual(suggestions("zzz", WORDS), []);
});

test("a finished word suggests nothing more", () => {
  assert.deepEqual(suggestions("happy", WORDS), []);
});

test("the word being typed is completed to the first word it begins, from the second letter", () => {
  assert.equal(completion("h", WORDS), "");
  assert.equal(completion("ha", WORDS), "bit");
  assert.equal(completion("happ", WORDS), "y");
  assert.equal(completion("happy-ap", WORDS), "art");
  assert.equal(completion("Happy BAN", WORDS), "ana");
  assert.equal(completion("happy", WORDS), "");
  assert.equal(completion("happy-", WORDS), "");
  assert.equal(completion("zz", WORDS), "");
});

test("Tab finishes a word that is whole or the only fit, and adds a separator before the third word", () => {
  assert.equal(accept("happ", WORDS), "happy-");
  assert.equal(accept("happy", WORDS), "happy-");
  assert.equal(accept("happy appl", WORDS), "happy apple ");
  assert.equal(accept("happy-apple-bana", WORDS), "happy-apple-banana");
  // "act" is a word and also begins "action", so the typed word is taken as it is.
  assert.equal(accept("act", WORDS), "act-");
});

test("Tab has nothing to do, so it moves focus, when the word is unclear or the address is done", () => {
  assert.equal(accept("", WORDS), null);
  assert.equal(accept("ban", WORDS), null);
  assert.equal(accept("happy-", WORDS), null);
  assert.equal(accept("happy-apple-banana", WORDS), null);
  assert.equal(accept("zzz", WORDS), null);
});
