import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  apply,
  baseLength,
  coarsen,
  compose,
  cpLength,
  cpToUnit,
  diff,
  invert,
  isNoop,
  targetLength,
  transform,
  transformPos,
  unitToCp,
  wellFormed,
} from "./ot.js";

const fixture = JSON.parse(readFileSync(new URL("../../tests/fixtures/ot.json", import.meta.url)));

/** mulberry32: a small seeded generator, so the random cases are the same on every run. */
function rng(seed) {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const ALPHABET = ["a", "b", "ä", "😀", "😁", "\n"];

function randomText(next, max) {
  let s = "";
  const n = Math.floor(next() * (max + 1));
  for (let i = 0; i < n; i += 1) s += ALPHABET[Math.floor(next() * ALPHABET.length)];
  return s;
}

/** A random operation on `text`, built from parts in any order and then written normalised. */
function randomOp(next, text) {
  const chars = Array.from(text);
  const out = [];
  let i = 0;
  for (;;) {
    const left = chars.length - i;
    if (left === 0 && next() < 0.7) break;
    const kind = next();
    if (kind < 0.3 || left === 0) {
      out.push(randomText(next, 3) || "x");
    } else {
      const n = 1 + Math.floor(next() * Math.min(left, 4));
      out.push(kind < 0.65 ? n : -n);
      i += n;
    }
  }
  return normal(out);
}

/** Normalises by hand, the way the server does, so the test does not trust the module for it. */
function normal(parts) {
  const out = [];
  for (const p of parts) {
    const last = out[out.length - 1];
    if (typeof p === "number" && p > 0) {
      if (typeof last === "number" && last > 0) out[out.length - 1] += p;
      else out.push(p);
    } else if (typeof p === "number") {
      if (typeof last === "number" && last < 0) out[out.length - 1] += p;
      else out.push(p);
    } else {
      const at = typeof last === "number" && last < 0 ? out.length - 1 : out.length;
      if (typeof out[at - 1] === "string") out[at - 1] += p;
      else out.splice(at, 0, p);
    }
  }
  return out;
}

function isNormal(op) {
  assert.deepEqual(op, normal(op), "not normalised");
  for (const p of op) assert.ok(p !== 0 && p !== "", "empty part");
}

test("the shared fixture's operations apply", () => {
  for (const c of fixture.apply) {
    isNormal(c.op);
    assert.equal(apply(c.text, c.op), c.result, JSON.stringify(c.op));
  }
});

test("the shared fixture's operations transform", () => {
  for (const c of fixture.transform) {
    const name = `${JSON.stringify(c.first)} / ${JSON.stringify(c.second)}`;
    const [first2, second2] = transform(c.first, c.second);
    assert.deepEqual(first2, c.first2, name);
    assert.deepEqual(second2, c.second2, name);
    assert.equal(apply(apply(c.text, c.first), second2), c.result, name);
    assert.equal(apply(apply(c.text, c.second), first2), c.result, name);
  }
});

test("the shared fixture's invalid operations are refused", () => {
  for (const c of fixture.invalid) {
    assert.throws(
      () => apply(c.text, c.op),
      (e) => e instanceof TypeError || e instanceof RangeError,
      JSON.stringify(c.op),
    );
  }
});

test("a malformed part is a TypeError and a wrong length a RangeError", () => {
  for (const bad of [[0], [""], [1.5], [null], [2 ** 32], [-(2 ** 32)], [true], [[1]], null, "abc", {}]) {
    assert.throws(() => apply("abc", bad), TypeError, JSON.stringify(bad));
    assert.throws(() => transform(bad, [3]), TypeError, JSON.stringify(bad));
    assert.throws(() => compose(bad, [3]), TypeError, JSON.stringify(bad));
  }
  assert.throws(() => apply("abc", [2]), RangeError);
  assert.throws(() => apply("a😀b", [4]), RangeError);
  assert.throws(() => transform([1], [2]), RangeError);
  assert.throws(() => compose([1], [2]), RangeError);
  assert.throws(() => invert([2], "abc"), RangeError);
});

test("lengths count code points", () => {
  assert.equal(baseLength([1, "😀ä", -1]), 2);
  assert.equal(targetLength([1, "😀ä", -1]), 3);
  assert.equal(cpLength("a😀b"), 3);
  assert.ok(isNoop([]));
  assert.ok(isNoop([5]));
  assert.ok(!isNoop([5, "x"]));
  assert.ok(!isNoop([-1]));
});

test("compose is one step equal to two", () => {
  const next = rng(2026);
  for (let n = 0; n < 500; n += 1) {
    const t = randomText(next, 12);
    const a = randomOp(next, t);
    const mid = apply(t, a);
    const b = randomOp(next, mid);
    const ab = compose(a, b);
    isNormal(ab);
    assert.equal(apply(t, ab), apply(mid, b), `${JSON.stringify(t)} ${JSON.stringify(a)} ${JSON.stringify(b)}`);
  }
});

test("invert undoes an operation", () => {
  const next = rng(1);
  for (let n = 0; n < 500; n += 1) {
    const t = randomText(next, 12);
    const op = randomOp(next, t);
    const back = invert(op, t);
    isNormal(back);
    assert.equal(apply(apply(t, op), back), t, `${JSON.stringify(t)} ${JSON.stringify(op)}`);
  }
});

test("transformed random operations converge", () => {
  const next = rng(0xb177a17);
  for (let n = 0; n < 500; n += 1) {
    const t = randomText(next, 12);
    const a = randomOp(next, t);
    const b = randomOp(next, t);
    const [a2, b2] = transform(a, b);
    isNormal(a2);
    isNormal(b2);
    assert.equal(apply(apply(t, a), b2), apply(apply(t, b), a2));
  }
});

test("diff keeps the common ends and never cuts a surrogate pair", () => {
  assert.deepEqual(diff("a😀b", "a😁b"), [1, "😁", -1, 1]);
  assert.deepEqual(diff("😀", "😁"), ["😁", -1]);
  assert.deepEqual(diff("x\ude00", "😀"), ["😀", -2]);
  const typo = diff("the teh", "the the");
  assert.equal(apply("the teh", typo), "the the");
  assert.equal(typo.filter((p) => typeof p === "string").length, 1);
  assert.equal(typo.filter((p) => typeof p === "number" && p < 0).length, 1);
  assert.deepEqual(diff("abc", "abc"), [3]);
  assert.ok(isNoop(diff("a😀b", "a😀b")));
  assert.deepEqual(diff("", ""), []);
  const next = rng(7);
  for (let n = 0; n < 500; n += 1) {
    const a = randomText(next, 8);
    const b = randomText(next, 8);
    const op = diff(a, b);
    isNormal(op);
    assert.equal(apply(a, op), b);
  }
});

test("a position follows the operation", () => {
  assert.equal(transformPos(3, [3, "xy", 2], false), 5);
  assert.equal(transformPos(3, [3, "xy", 2], true), 3);
  assert.equal(transformPos(4, [1, -5], false), 1);
  assert.equal(transformPos(0, ["😀", 2], false), 1);
  assert.equal(transformPos(2, [1, "xy", -2], false), 3);
});

test("code points and UTF-16 units convert", () => {
  assert.equal(unitToCp("a😀b", 3), 2);
  assert.equal(cpToUnit("a😀b", 2), 3);
  assert.equal(cpToUnit("a😀b", 3), 4);
  assert.equal(unitToCp("a😀b", 4), 3);
  assert.equal(wellFormed("a\ud83d"), "a�");
  assert.equal(wellFormed("\ude00a😀"), "�a😀");
  assert.equal(wellFormed("plain"), "plain");
  // Without String.prototype.toWellFormed, as in older browsers.
  const old = Object.assign(new String("\ude00a\ud83d\ude00\ud83d"), { toWellFormed: undefined });
  assert.equal(wellFormed(old), "\ufffda😀\ufffd");
});

test("coarsen keeps the ends and replaces the middle, with the same result", () => {
  assert.deepEqual(coarsen([2, "X", 3, -1, "Y", 4], "abXcdeYghij"), [2, "XcdeY", -4, 4]);
  assert.deepEqual(coarsen(["X", 3], "Xabc"), ["X", 3]);
  assert.deepEqual(coarsen([5], "hello"), [5]);
  assert.deepEqual(coarsen([-3], ""), [-3]);
  assert.deepEqual(coarsen([1, "😀", 1, "é", 1], "a😀béc"), [1, "😀bé", -1, 1]);
  assert.throws(() => coarsen([1, "x"], "a"), RangeError);
  // Seeded, so every run checks the same cases.
  const r = rng(7);
  for (let i = 0; i < 500; i += 1) {
    const text = Array.from("abcdefghij😀".repeat(3)).slice(0, Math.floor(r() * 30)).join("");
    const op = [];
    for (let left = cpLength(text); left > 0; ) {
      const n = 1 + Math.floor(r() * left);
      op.push(r() < 0.5 ? n : -n);
      if (r() < 0.5) op.push("xy");
      left -= n;
    }
    const result = apply(text, op);
    const coarse = coarsen(op, result);
    assert.ok(coarse.length <= 4, JSON.stringify(coarse));
    assert.equal(apply(text, coarse), result, JSON.stringify(op));
  }
});
