import { test } from "node:test";
import assert from "node:assert/strict";

import { rememberLookups, submitDecision } from "./box.js";

// A lookup whose answers come from `answers` in turn, and the timers it set.
function fixture(answers) {
  const asked = [];
  const timers = [];
  let forgotten = 0;
  const lookups = rememberLookups(
    async (address) => {
      asked.push(address);
      const next = answers.shift();
      if (next instanceof Error) throw next;
      return next;
    },
    () => forgotten++,
    60_000,
    (fn, ms) => timers.push({ fn, ms }),
  );
  return { lookups, asked, timers, forgotten: () => forgotten };
}

test("an answer about an address is asked once and remembered", async () => {
  const { lookups, asked, timers } = fixture(["found", "missing"]);
  assert.equal(lookups.known("a-b-c"), undefined);
  assert.equal(await lookups.resolve("a-b-c"), "found");
  assert.equal(await lookups.resolve("a-b-c"), "found");
  assert.equal(await lookups.resolve("d-e-f"), "missing");
  assert.deepEqual(asked, ["a-b-c", "d-e-f"]);
  assert.equal(lookups.known("d-e-f"), "missing");
  assert.equal(timers.length, 0);
});

test("too many lookups is forgotten after a minute and the address asked again", async () => {
  const { lookups, asked, timers, forgotten } = fixture(["busy", "found"]);
  assert.equal(await lookups.resolve("a-b-c"), "busy");
  assert.equal(await lookups.resolve("a-b-c"), "busy");
  assert.deepEqual(asked, ["a-b-c"]);
  assert.equal(timers.length, 1);
  assert.equal(timers[0].ms, 60_000);
  timers[0].fn();
  assert.equal(forgotten(), 1);
  assert.equal(lookups.known("a-b-c"), undefined);
  assert.equal(await lookups.resolve("a-b-c"), "found");
  assert.deepEqual(asked, ["a-b-c", "a-b-c"]);
});

test("a lookup that fails is not remembered", async () => {
  const { lookups, asked } = fixture([new Error("offline"), "found"]);
  assert.equal(await lookups.resolve("a-b-c"), null);
  assert.equal(await lookups.resolve("a-b-c"), "found");
  assert.equal(asked.length, 2);
});

test("a submit opens a found paste, keeps missing words, and leaves the rest to the server", () => {
  assert.deepEqual(submitDecision("found", "a-b-c"), { open: "/a-b-c" });
  assert.deepEqual(submitDecision("missing", "a-b-c"), { intent: "create" });
  // Keeping the words here would store them as a new paste although their paste may exist.
  assert.deepEqual(submitDecision("busy", "a-b-c"), {});
  assert.deepEqual(submitDecision(null, "a-b-c"), {});
});
