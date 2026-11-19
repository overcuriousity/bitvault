import { test } from "node:test";
import assert from "node:assert/strict";

import { contentStep, delay, label, withGrant } from "./live-view.js";

test("the link names how many are editing", () => {
  assert.equal(label(0), "Live edit");
  assert.equal(label(1), "Live edit · 1 editing");
  assert.equal(label(2), "Live edit · 2 editing");
});

test("a grant is added to a bare path", () => {
  assert.equal(withGrant("/a-b-c/raw", "new"), "/a-b-c/raw?g=new");
});

test("a grant replaces the one a link carries", () => {
  assert.equal(withGrant("/a-b-c/edit?g=old", "new"), "/a-b-c/edit?g=new");
});

test("a grant keeps the other parameters and the fragment", () => {
  assert.equal(withGrant("/a-b-c/zip?x=1&g=old&y=2", "new"), "/a-b-c/zip?x=1&g=new&y=2");
  assert.equal(withGrant("/a-b-c/file/0?x=1#top", "new"), "/a-b-c/file/0?x=1&g=new#top");
  assert.equal(withGrant("https://paste.example/a-b-c/file/0?g=old", "n+w"), "https://paste.example/a-b-c/file/0?g=n%2Bw");
});

test("a failed connect is retried after 1 s, doubling to 30 s", () => {
  assert.deepEqual([0, 1, 2, 3, 4, 5, 6, 20].map(delay), [1000, 2000, 4000, 8000, 16000, 30000, 30000, 30000]);
});

test("empty html does not reload", () => {
  assert.equal(contentStep("", true), "hide");
  assert.equal(contentStep("", false), "none");
  assert.equal(contentStep("<span>x</span>", true), "show");
  assert.equal(contentStep("x", false), "create");
  for (const html of ["", "x"]) {
    for (const hasText of [true, false]) assert.notEqual(contentStep(html, hasText), "reload");
  }
});
