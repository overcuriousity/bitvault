import { test } from "node:test";
import assert from "node:assert/strict";

import { buildEnvelope, createdLocation, tooLarge } from "./create.js";

test("the envelope carries file names in order", () => {
  const files = [{ name: "b.png" }, { name: "a report.pdf" }, { name: "ünïcode.txt" }];
  const envelope = JSON.parse(buildEnvelope("some text\n", files));
  assert.deepEqual(envelope, { text: "some text\n", files: ["b.png", "a report.pdf", "ünïcode.txt"] });
});

test("the envelope of a paste without files has an empty list", () => {
  assert.deepEqual(JSON.parse(buildEnvelope("", [])), { text: "", files: [] });
});

test("a file over the secret limit is reported", () => {
  const mb = 1024 * 1024;
  assert.equal(tooLarge([{ size: 2 * mb }, { size: 2 * mb + 1 }], 2), true);
  assert.equal(tooLarge([{ size: 2 * mb }], 2), false);
  assert.equal(tooLarge([], 2), false);
});

test("a created paste opens at the path the server names", () => {
  assert.equal(createdLocation(new Headers({ "HX-Redirect": "/happy-apple-banana" })), "/happy-apple-banana");
});

test("a missing or foreign redirect target is not followed", () => {
  for (const to of [undefined, "", "happy-apple-banana", "//evil.example/x", "/\\evil.example", "https://evil.example/"]) {
    const headers = new Headers(to === undefined ? {} : { "HX-Redirect": to });
    assert.equal(createdLocation(headers), null, String(to));
  }
});
