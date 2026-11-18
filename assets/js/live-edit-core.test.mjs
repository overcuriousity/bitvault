import { test } from "node:test";
import assert from "node:assert/strict";

import { transformPos } from "./ot.js";
import {
  backoff,
  keepsAbove,
  lineOf,
  lineStart,
  mapSelection,
  presence,
  rebase,
  streamUrl,
  syntaxValue,
} from "./live-edit-core.js";

test("lineOf counts lines from 1 at a code-point position", () => {
  assert.equal(lineOf("", 0), 1);
  assert.equal(lineOf("ab\ncd\nef", 2), 1);
  assert.equal(lineOf("ab\ncd\nef", 3), 2);
  assert.equal(lineOf("ab\ncd\nef", 8), 3);
  // A pair before the newline is one code point.
  assert.equal(lineOf("😀\nx", 2), 2);
  assert.equal(lineOf("ab", 99), 1);
});

test("lineStart is the UTF-16 index where a line begins", () => {
  assert.equal(lineStart("ab\ncd\nef", 0), 0);
  assert.equal(lineStart("ab\ncd\nef", 2), 6);
  assert.equal(lineStart("ab", 5), 2);
});

test("presence counts everyone and gives each other person a chip", () => {
  assert.deepEqual(presence([{ peer: 1, pos: 0 }], 1, "x"), { label: "1 person here", chips: [] });
  const peers = [
    { peer: 3, pos: 5 },
    { peer: 1, pos: 0 },
    { peer: 2, pos: 1 },
  ];
  assert.deepEqual(presence(peers, 1, "a\nbc\nd"), { label: "3 people here", chips: ["line 1", "line 3"] });
  // You are counted even before your own entry arrives.
  assert.deepEqual(presence([{ peer: 2, pos: 0 }], 1, ""), { label: "2 people here", chips: ["line 1"] });
});

test("mapSelection moves a caret and a selection through a change, in UTF-16 units", () => {
  const op = ["😀", 3];
  const map = (pos, sticky) => transformPos(pos, op, sticky);
  assert.deepEqual(mapSelection("abc", "😀abc", 1, 1, map), [3, 3]);
  assert.deepEqual(mapSelection("abc", "😀abc", 0, 3, map), [2, 5]);
  // A caret at the insert stays before it, so its own typing stays together.
  assert.deepEqual(mapSelection("abc", "😀abc", 0, 0, map), [0, 0]);
  const del = [1, -1, 1];
  const back = (pos, sticky) => transformPos(pos, del, sticky);
  assert.deepEqual(mapSelection("a😀b", "ab", 3, 3, back), [1, 1]);
});

test("keepsAbove tells whether the text before a position stayed the same", () => {
  const below = (pos, sticky) => transformPos(pos, [4, "x", 1], sticky);
  assert.equal(keepsAbove("abc\nd", "abc\nxd", 4, below), true);
  const above = (pos, sticky) => transformPos(pos, ["x", 5], sticky);
  assert.equal(keepsAbove("abc\nd", "xabc\nd", 4, above), false);
});

test("backoff doubles from 500 ms to a cap of 8 s", () => {
  assert.deepEqual([0, 1, 2, 3, 4, 5, 9].map(backoff), [500, 1000, 2000, 4000, 8000, 8000, 8000]);
});

test("streamUrl carries the grant, then the client and the last revision", () => {
  assert.equal(streamUrl({ live: "/a-b-c/live" }), "/a-b-c/live/events");
  assert.equal(streamUrl({ live: "/a-b-c/live", grant: "t+k/=" }), "/a-b-c/live/events?g=t%2Bk%2F%3D");
  assert.equal(
    streamUrl({ live: "/a-b-c/live", grant: "", client: "ff", last: 0 }),
    "/a-b-c/live/events?client=ff&last=0",
  );
  assert.equal(streamUrl({ live: "/x/live", grant: "g", client: "ff", last: 7 }), "/x/live/events?g=g&client=ff&last=7");
});

test("rebase keeps what was typed before the first init on top of the session's text", () => {
  assert.equal(rebase("hello", "hello", "hello world"), "hello world");
  assert.equal(rebase("hello", "hello!", "hello"), "hello!");
  assert.equal(rebase("hello", "> hello", "hello world"), "> hello world");
  assert.equal(rebase("hello", "hello\ud800", "hello"), "hello�");
});

test("syntaxValue maps Automatic to null and back", () => {
  assert.equal(syntaxValue.send("auto"), null);
  assert.equal(syntaxValue.send("rs"), "rs");
  assert.equal(syntaxValue.show(null), "auto");
  assert.equal(syntaxValue.show("plain"), "plain");
});
