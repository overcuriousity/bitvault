import { test } from "node:test";
import assert from "node:assert/strict";

import { nextCollapsed, rememberLookups, spotAt, submitDecision } from "./box.js";

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

const facts = (over) => ({ empty: false, found: false, addressLike: true, files: false, ...over });

test("the box collapses only on a found paste", () => {
  assert.equal(nextCollapsed(false, facts({ found: true })), true);
  // Pending, missing, ambiguous and busy all arrive as found: false.
  assert.equal(nextCollapsed(false, facts({})), false);
  assert.equal(nextCollapsed(false, facts({ empty: true })), false);
});

test("a collapsed box stays one line while it could still be an address", () => {
  assert.equal(nextCollapsed(true, facts({})), true);
  assert.equal(nextCollapsed(true, facts({ found: true })), true);
});

test("a collapsed box regrows when emptied, when it holds text, and when files are attached", () => {
  assert.equal(nextCollapsed(true, facts({ empty: true, addressLike: true })), false);
  assert.equal(nextCollapsed(true, facts({ addressLike: false })), false);
  assert.equal(nextCollapsed(true, facts({ files: true })), false);
  assert.equal(nextCollapsed(false, facts({ found: true, files: true })), false);
});

test("the border light sits where the pointer is, measured from the box", () => {
  assert.deepEqual(spotAt({ left: 100, top: 40 }, 130, 20), { x: "30px", y: "-20px" });
});
