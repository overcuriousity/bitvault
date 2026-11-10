import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { suggestions } from "./words.js";

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
