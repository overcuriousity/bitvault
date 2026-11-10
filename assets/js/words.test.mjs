import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { accept, addressLike, chips, choose, findIn, linkWords, readAddress } from "./words.js";

const WORDS = readFileSync(new URL("../bip39-english.txt", import.meta.url), "utf8").split("\n").filter(Boolean);

test("a word is found in full, or from four letters when only one word begins so", () => {
  assert.equal(WORDS[findIn(WORDS, "act")], "act");
  assert.equal(WORDS[findIn(WORDS, "happ")], "happy");
  assert.equal(findIn(WORDS, "hap"), -1);
  assert.equal(findIn(WORDS, "bana"), WORDS.indexOf("banana"));
  assert.equal(findIn(WORDS, "aple"), -1);
});

test("an address is read with any separators, in any case, or run together like the server reads it", () => {
  for (const typed of ["happy apple banana", "Happy-APPLE-banana", "  happy --  apple\tbanana ", "happ appl bana", "happyapplebanana", "happy applebanana", "happyapple-banana"]) {
    assert.deepEqual(readAddress(typed, WORDS), { address: "happy-apple-banana" }, typed);
  }
});

test("letters that read as two addresses, and text that is no address, are told apart", () => {
  assert.deepEqual(readAddress("qualityseathen", WORDS), { ambiguous: true });
  for (const typed of ["", "happy apple", "happy apple banana cherry", "hello world", "happyaplebanana", "happ applbana", "a\nb\nc"]) {
    assert.equal(readAddress(typed, WORDS), null, typed);
  }
});

test("the word list follows the word being typed while the box looks like an address", () => {
  assert.deepEqual(chips("ban", WORDS).fits, ["banana", "banner"]);
  assert.deepEqual(chips("happy-apple-bana", WORDS).fits, ["banana"]);
  assert.equal(chips("h", WORDS), null);
  assert.equal(chips("happy-", WORDS), null);
  assert.equal(chips("happy-apple-banana", WORDS), null);
  assert.equal(chips("lorem ips", WORDS), null, "lorem is no paste word");
  assert.equal(chips("happy\nap", WORDS), null);
  assert.equal(chips("a b c de", WORDS), null);
  assert.equal(chips("a", WORDS), null);
  assert.equal(chips("ab", WORDS).fits.length, 6);
});

test("choosing a word completes it and adds the separator already in use before the third word", () => {
  assert.equal(choose("ban", WORDS, "banner"), "banner-");
  assert.equal(choose("happy appl", WORDS, "apple"), "happy apple ");
  assert.equal(choose("happy-apple-bana", WORDS, "banana"), "happy-apple-banana");
  assert.equal(choose("ban", WORDS, "apple"), null);
});

test("Tab takes the first word in the list, and has nothing to do once the address is done", () => {
  assert.equal(accept("happ", WORDS), "happy-");
  assert.equal(accept("act", WORDS), "act-");
  assert.equal(accept("ban", WORDS), "banana-");
  assert.equal(accept("happy-apple-banana", WORDS), null);
  assert.equal(accept("happy-", WORDS), null);
  assert.equal(accept("lorem ipsum", WORDS), null);
});

test("the box stays one line while what is typed can still be three words", () => {
  for (const v of ["", "h", "happy", "happy ", "happy-apple ban", "happyapple ban", "happyapplebanana", "Happy Apple Banana"]) {
    assert.equal(addressLike(v, WORDS), true, v);
  }
});

test("the box grows for anything that cannot be three words", () => {
  for (const v of ["lorem ", "happy apple banana cherry", "happy apple xyzq", "line one\nline two", "https://example.org", "it's", "happy, apple", "a".repeat(65)]) {
    assert.equal(addressLike(v, WORDS), false, v);
  }
  // Without the word list, only the shape counts.
  assert.equal(addressLike("lorem ipsum", null), true);
  assert.equal(addressLike("lorem ipsum dolor sit", null), false);
});

test("a link to a paste here reads as that paste's words", () => {
  const hosts = ["paste.example", "s.example:8443", undefined];
  for (const link of [
    "https://paste.example/happy-apple-banana",
    "  https://paste.example/happy-apple-banana\n",
    "HTTPS://Paste.Example/Happy-Apple-Banana",
    "http://paste.example/happy-apple-banana/",
    "paste.example/happy-apple-banana",
    "https://paste.example/happy-apple-banana?view",
    "https://paste.example/happy-apple-banana#L3",
    "https://s.example:8443/happy-apple-banana",
  ]) {
    assert.equal(linkWords(link, hosts), "happy-apple-banana", link);
  }
});

test("other links and other pages stay what they are", () => {
  const hosts = ["paste.example"];
  for (const text of [
    "https://evil.example/happy-apple-banana",
    "https://paste.example.evil.example/happy-apple-banana",
    "https://paste.example:8080/happy-apple-banana",
    "https://paste.example/happy-apple-banana/raw",
    "https://paste.example/guide",
    "https://paste.example/happy-apple",
    "https://paste.example/",
    "see https://paste.example/happy-apple-banana",
    "happy-apple-banana",
    "ftp://paste.example/happy-apple-banana",
    "",
  ]) {
    assert.equal(linkWords(text, hosts), null, text);
  }
});
