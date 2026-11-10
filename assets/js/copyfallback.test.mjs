import test from "node:test";
import assert from "node:assert/strict";
import { needsFallback, textFor } from "./copyfallback.js";

test("the fallback is used outside a secure context or without a clipboard", () => {
  assert.equal(needsFallback(false, undefined), true);
  assert.equal(needsFallback(false, {}), true);
  assert.equal(needsFallback(true, undefined), true);
  assert.equal(needsFallback(true, {}), false);
});

test("a copy button copies its value or the text of its target", () => {
  const doc = { getElementById: (id) => (id === "paste-text" ? { textContent: "the text" } : null) };
  assert.equal(textFor({ dataset: { ocCopy: "a-b-c" } }, doc), "a-b-c");
  assert.equal(textFor({ dataset: { bvCopyTarget: "paste-text" } }, doc), "the text");
  assert.equal(textFor({ dataset: { bvCopyTarget: "missing" } }, doc), "");
});
