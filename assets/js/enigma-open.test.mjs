import { test } from "node:test";
import assert from "node:assert/strict";

import { ENIGMA_TEXT_KEY, openInEnigma } from "./enigma-open.js";

test("the text travels in session storage and the Enigma page is opened", () => {
  const kept = new Map();
  const gone = [];
  openInEnigma("ABCDE FGHIJ", { setItem: (k, v) => kept.set(k, v) }, (to) => gone.push(to));
  assert.equal(kept.get(ENIGMA_TEXT_KEY), "ABCDE FGHIJ");
  assert.deepEqual(gone, ["/enigma"]);
});

test("the Enigma page is opened even when storage refuses", () => {
  const gone = [];
  const refusing = {
    setItem() {
      throw new Error("no storage");
    },
  };
  openInEnigma("ABCDE FGHIJ", refusing, (to) => gone.push(to));
  assert.deepEqual(gone, ["/enigma"]);
});
