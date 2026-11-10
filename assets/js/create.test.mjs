import { test } from "node:test";
import assert from "node:assert/strict";

import {
  buildEnvelope,
  createdLocation,
  mergeFiles,
  pastedFiles,
  progressText,
  sizeProblem,
  tooLarge,
} from "./create.js";

const MB = 1024 * 1024;
const ORIGIN = "https://paste.example";

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
  assert.equal(createdLocation(new Headers({ "HX-Redirect": "/happy-apple-banana" }), ORIGIN), "/happy-apple-banana");
});

test("a missing or foreign redirect target is not followed", () => {
  for (const to of [undefined, "", "happy-apple-banana", "//evil.example/x", "/\\evil.example", "https://evil.example/"]) {
    const headers = new Headers(to === undefined ? {} : { "HX-Redirect": to });
    assert.equal(createdLocation(headers, ORIGIN), null, String(to));
  }
});

test("a redirect target with a tab or line break is not followed", () => {
  // Headers refuse CR and LF, so the getter is a plain object here, as XMLHttpRequest's is.
  for (const to of ["/\t/evil.example", "/\n/evil.example", "/\r/evil.example", "/happy\tapple", "/a\nb"]) {
    assert.equal(createdLocation({ get: () => to }, ORIGIN), null, JSON.stringify(to));
  }
});

test("without an origin to compare with, nothing is followed", () => {
  assert.equal(createdLocation({ get: () => "/happy-apple-banana" }, undefined), null);
});

test("files over the total limit are refused before upload", () => {
  const files = [{ size: 1 * MB }, { size: 1 * MB + 1 }];
  assert.equal(sizeProblem(files, "unlisted", 2, 256), "Files can be at most 2 MB together.");
  assert.equal(sizeProblem([{ size: 2 * MB }], "public", 2, 256), null);
  assert.equal(sizeProblem([], "private", 2, 256), null);
});

test("a secret file over its own limit is refused, and the total still counts", () => {
  assert.equal(sizeProblem([{ size: 3 * MB }], "secret", 2048, 2), "Secret files can be at most 2 MB.");
  assert.equal(sizeProblem([{ size: 3 * MB }], "unlisted", 2048, 2), null);
  assert.equal(sizeProblem([{ size: 2 * MB }, { size: 2 * MB }], "secret", 3, 2), "Files can be at most 3 MB together.");
});

test("upload progress is a whole percentage that never passes 100", () => {
  assert.equal(progressText(0, 1), "Uploading… 0%");
  assert.equal(progressText(1, 3), "Uploading… 33%");
  assert.equal(progressText(999, 1000), "Uploading… 99%");
  assert.equal(progressText(5, 4), "Uploading… 100%");
  assert.equal(progressText(5, 0), "Uploading… 0%");
});

function clipboard(types, files) {
  return { types, items: files.map((f) => ({ kind: "file", getAsFile: () => f })) };
}

test("pasted files are taken from the clipboard", () => {
  const image = { name: "image.png", size: 10, type: "image/png" };
  assert.deepEqual(pastedFiles(clipboard(["Files"], [image]), false), [image]);
  assert.deepEqual(pastedFiles(clipboard(["Files"], [image]), true), [image]);
  const textOnly = { types: ["text/plain"], items: [{ kind: "string", getAsFile: () => null }] };
  assert.deepEqual(pastedFiles(textOnly, false), []);
  assert.deepEqual(pastedFiles(null, false), []);
});

test("pasting text into a text field stays a text paste", () => {
  const picture = { name: "image.png", size: 10, type: "image/png" };
  assert.deepEqual(pastedFiles(clipboard(["text/plain", "text/html", "Files"], [picture]), true), []);
  assert.deepEqual(pastedFiles(clipboard(["text/plain", "Files"], [picture]), false), [picture]);
});

test("adding the same file twice keeps one", () => {
  const a = { name: "a.png", size: 1, type: "image/png" };
  const b = { name: "b.png", size: 1, type: "image/png" };
  assert.deepEqual(mergeFiles([a], [{ ...a }, b, { ...b }]), [a, b]);
});
