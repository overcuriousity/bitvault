import { test } from "node:test";
import assert from "node:assert/strict";

import { relativeFor, relativeText } from "./paste.js";
import { splitLines } from "./lines.js";

const MIN = 60;
const H = 60 * MIN;
const D = 24 * H;

test("a future time reads in calm units without seconds", () => {
  assert.equal(relativeText(3 * H + 2 * MIN + 30), "in 3 h 2 min");
  assert.equal(relativeText(3 * H), "in 3 h");
  assert.equal(relativeText(5 * MIN), "in 5 min");
  assert.equal(relativeText(2 * D + 4 * H), "in 2 d 4 h");
  assert.equal(relativeText(45 * D), "in 45 d");
});

test("a time under a minute away is not counted in seconds", () => {
  assert.equal(relativeText(59), "in less than a minute");
  assert.equal(relativeText(-59), "just now");
});

test("a past time reads as ago", () => {
  assert.equal(relativeText(-(2 * H + 5 * MIN)), "2 h 5 min ago");
});

test("years are shown with the days left over", () => {
  assert.equal(relativeText(2 * 365 * D), "in 2 y");
  assert.equal(relativeText(2 * 365 * D + 10 * D), "in 2 y 10 d");
});

test("an expiry that has passed reads Expired", () => {
  assert.equal(relativeFor("expires", 0), "Expired");
  assert.equal(relativeFor("expires", -5 * D), "Expired");
  assert.equal(relativeFor("expires", 2 * H), "in 2 h");
});

test("a last read is never shown in the future", () => {
  assert.equal(relativeFor("ago", 30 * MIN), "just now");
  assert.equal(relativeFor("ago", -3 * MIN), "3 min ago");
});

test("lines keep their line break and a final break adds no empty line", () => {
  assert.deepEqual(splitLines("a\nb"), ["a\n", "b"]);
  assert.deepEqual(splitLines("a\n\nb\n"), ["a\n", "\n", "b\n"]);
  assert.deepEqual(splitLines(""), []);
});
