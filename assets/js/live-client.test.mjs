import { test } from "node:test";
import assert from "node:assert/strict";

import { apply, diff, transform } from "./ot.js";
import { LiveClient } from "./live-client.js";

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

/**
 * The server's side of the protocol: it transforms an edit over everything after its base, with
 * the applied operations as `first`, and ignores `seq` 0 and any `seq` it has applied from that
 * peer before.
 */
class Server {
  constructor(text) {
    this.text = text;
    this.log = [];
    this.applied = new Map();
  }

  get rev() {
    return this.log.length;
  }

  receive(peer, { seq, base, op }) {
    const seen = this.applied.get(peer) ?? new Set();
    this.applied.set(peer, seen);
    if (seq === 0 || seen.has(seq)) return null;
    let mine = op;
    for (const done of this.log.slice(base)) [, mine] = transform(done.op, mine);
    this.text = apply(this.text, mine);
    seen.add(seq);
    const event = { rev: this.log.length + 1, peer, seq, op: mine };
    this.log.push(event);
    return event;
  }

  /** An edit from the form or the API: peer 0, seq 0, made against the current text. */
  form(newText) {
    const op = diff(this.text, newText);
    this.text = newText;
    const event = { rev: this.log.length + 1, peer: 0, seq: 0, op };
    this.log.push(event);
    return event;
  }
}

/** A client joined to `server` as `peer`, with its sends and changes recorded. */
function join(server, peer, clock = { t: 0 }) {
  const sent = [];
  const changes = [];
  const client = new LiveClient({
    send: (message) => sent.push(message),
    onChange: (text, map) => changes.push({ text, map }),
    now: () => clock.t,
  });
  client.init({ rev: server.rev, text: server.text, peer });
  return { client, sent, changes, clock, cursor: server.rev };
}

/** Feeds `who` every event of `server` it has not seen yet. */
function feed(server, who) {
  while (who.cursor < server.log.length) {
    who.client.remote(server.log[who.cursor]);
    who.cursor += 1;
  }
}

test("one_edit_in_flight", () => {
  const server = new Server("");
  const me = join(server, 1);
  me.client.local("a");
  me.client.local("ab");
  me.client.local("abc");
  assert.equal(me.sent.length, 1);
  assert.deepEqual(me.sent[0], { seq: 1, base: 0, op: ["a"] });
  assert.equal(me.client.state, "buffered");
  assert.ok(me.client.unsent);

  server.receive(1, me.sent[0]);
  feed(server, me);
  assert.equal(me.sent.length, 2);
  assert.deepEqual(me.sent[1], { seq: 2, base: 1, op: [1, "bc"] });
  assert.equal(me.client.state, "waiting");

  server.receive(1, me.sent[1]);
  feed(server, me);
  assert.equal(me.sent.length, 2);
  assert.equal(me.client.state, "synced");
  assert.ok(!me.client.unsent);
  assert.equal(me.client.text, "abc");
  assert.equal(server.text, "abc");
  assert.equal(me.client.rev, 2);
  assert.equal(me.changes.length, 0, "own edits are not reported as changes");
});

test("a_foreign_op_moves_pending_work", () => {
  const server = new Server("");
  const me = join(server, 1);
  me.client.local("a");
  me.client.local("ab");
  assert.deepEqual(me.sent[0].op, ["a"]);

  server.receive(2, { seq: 1, base: 0, op: ["F"] });
  server.receive(1, me.sent[0]);
  feed(server, me);
  assert.equal(me.client.text, "Fab");
  assert.equal(me.changes.length, 1);
  assert.equal(me.changes[0].text, "Fab");
  assert.equal(me.changes[0].map(0), 1);
  assert.deepEqual(me.sent[1], { seq: 2, base: 2, op: [2, "b"] });

  server.receive(1, me.sent[1]);
  feed(server, me);
  assert.equal(server.text, "Fab");
  assert.equal(me.client.text, server.text);
  assert.equal(me.client.state, "synced");
});

test("retry_resends_the_same_seq", () => {
  const server = new Server("xy");
  const me = join(server, 1);

  // The send is lost; a foreign edit arrives; the retry carries the transformed edit.
  me.client.local("axy");
  server.receive(2, { seq: 1, base: 0, op: [2, "F"] });
  feed(server, me);
  me.client.retry();
  assert.equal(me.sent.length, 2);
  assert.deepEqual(me.sent[1], { seq: 1, base: 1, op: ["a", 3] });
  server.receive(1, me.sent[1]);
  feed(server, me);
  assert.equal(me.client.state, "synced");
  assert.equal(me.client.text, "axyF");
  assert.equal(server.text, "axyF");

  // The send arrives but its event is lost with the stream; the retry is ignored and the replay
  // acknowledges the edit without applying it twice.
  me.client.local("abxyF");
  server.receive(1, me.sent[2]);
  me.client.retry();
  assert.equal(me.sent.length, 4);
  assert.equal(me.sent[3].seq, me.sent[2].seq);
  assert.equal(server.receive(1, me.sent[3]), null);
  feed(server, me);
  assert.equal(me.client.state, "synced");
  assert.equal(me.client.text, "abxyF");
  assert.equal(server.text, "abxyF");
  assert.equal(me.changes.length, 1, "only the foreign edit was a change");
  // A replay that overlaps what was already seen changes nothing.
  me.client.remote(server.log[0]);
  assert.equal(me.client.text, "abxyF");
  assert.equal(me.changes.length, 1);

  // The replay acknowledges the edit before the retry: nothing is sent again.
  me.client.local("abcxyF");
  server.receive(1, me.sent[4]);
  feed(server, me);
  me.client.retry();
  assert.equal(me.sent.length, 5);
  assert.equal(me.client.state, "synced");

  // The replay acknowledges the in-flight edit; the retry still sends the buffer.
  me.client.local("abcdxyF");
  me.client.local("abcdexyF");
  server.receive(1, me.sent[5]);
  feed(server, me);
  assert.equal(me.sent.length, 7);
  me.client.retry();
  assert.equal(me.sent.length, 8);
  assert.deepEqual(me.sent[7], me.sent[6]);
  server.receive(1, me.sent[7]);
  feed(server, me);
  assert.equal(me.client.state, "synced");
  assert.equal(server.text, "abcdexyF");
});

test("typing_while_offline_is_kept", () => {
  const server = new Server("start\n");
  const me = join(server, 1);
  for (let i = 0; i < 20; i += 1) {
    const at = (i * 7) % (me.client.text.length + 1);
    const t = me.client.text;
    me.client.local(`${t.slice(0, at)}${String.fromCharCode(97 + i)}${t.slice(at)}`);
  }
  assert.equal(me.sent.length, 1);
  assert.equal(me.client.state, "buffered");

  server.receive(2, { seq: 1, base: 0, op: ["other ", 6] });
  server.form(`${server.text}from the form`);
  server.receive(2, { seq: 2, base: 1, op: [3, -3, 6] });
  server.receive(1, me.sent[0]);
  feed(server, me);
  assert.equal(me.sent.length, 2);
  assert.equal(me.sent[1].base, server.rev);
  server.receive(1, me.sent[1]);
  feed(server, me);
  assert.equal(me.client.state, "synced");
  assert.equal(me.client.text, server.text);
  for (let i = 0; i < 20; i += 1) assert.ok(server.text.includes(String.fromCharCode(97 + i)));
});

test("undo_takes_back_only_mine", () => {
  const server = new Server("hello world");
  const me = join(server, 1);
  me.client.local("abchello world");
  server.receive(1, me.sent[0]);
  feed(server, me);
  server.receive(2, { seq: 1, base: server.rev, op: [14, "XYZ"] });
  feed(server, me);
  assert.equal(me.client.text, "abchello worldXYZ");

  me.client.undo();
  assert.equal(me.client.text, "hello worldXYZ");
  assert.equal(me.changes.at(-1).text, "hello worldXYZ");
  assert.equal(me.changes.at(-1).map(5), 2);
  server.receive(1, me.sent.at(-1));
  feed(server, me);
  assert.equal(server.text, "hello worldXYZ");

  me.client.redo();
  assert.equal(me.client.text, "abchello worldXYZ");
  server.receive(1, me.sent.at(-1));
  feed(server, me);
  assert.equal(server.text, "abchello worldXYZ");

  me.client.undo();
  server.receive(1, me.sent.at(-1));
  feed(server, me);
  const sends = me.sent.length;
  const changes = me.changes.length;
  me.client.undo();
  assert.equal(me.client.text, "hello worldXYZ");
  assert.equal(me.sent.length, sends);
  assert.equal(me.changes.length, changes);
  assert.equal(me.client.state, "synced");
});

test("a local edit clears redo and quick single characters undo together", () => {
  const server = new Server("");
  const me = join(server, 1);
  for (const [t, text] of [
    [0, "a"],
    [500, "ab"],
    [1400, "abc"],
    [2600, "abcd"],
  ]) {
    me.clock.t = t;
    me.client.local(text);
  }
  me.client.undo();
  assert.equal(me.client.text, "abc");
  me.client.undo();
  assert.equal(me.client.text, "");
  me.client.redo();
  assert.equal(me.client.text, "abc");
  me.client.local("abcz");
  const before = me.sent.length;
  me.client.redo();
  assert.equal(me.client.text, "abcz");
  assert.equal(me.sent.length, before);
});

test("an undo made empty by others is skipped", () => {
  const server = new Server("one two");
  const me = join(server, 1);
  me.client.local("one");
  me.clock.t = 5000;
  me.client.local("one!");
  server.receive(1, me.sent[0]);
  feed(server, me);
  server.receive(1, me.sent[1]);
  feed(server, me);
  server.receive(2, { seq: 1, base: server.rev, op: [3, -1] });
  feed(server, me);
  assert.equal(me.client.text, "one");
  // Undoing "!" is empty now that it was deleted; the next undo restores " two".
  me.client.undo();
  assert.equal(me.client.text, "one two");
});

test("text that is not well-formed is cleaned and no change sends nothing", () => {
  const server = new Server("a");
  const me = join(server, 1);
  me.client.local("a");
  assert.equal(me.sent.length, 0);
  me.client.local("a\ud83d");
  assert.equal(me.client.text, "a�");
  assert.deepEqual(me.sent[0].op, [1, "�"]);
  me.client.local("a�");
  assert.equal(me.sent.length, 1);
});

test("init starts over", () => {
  const server = new Server("abc");
  const me = join(server, 1);
  me.client.local("abcd");
  me.client.local("abcde");
  assert.ok(me.client.unsent);
  me.client.init({ rev: 40, text: "fresh", peer: 3 });
  assert.equal(me.client.text, "fresh");
  assert.equal(me.client.rev, 40);
  assert.equal(me.client.state, "synced");
  me.client.undo();
  assert.equal(me.client.text, "fresh");
  me.client.local("fresh!");
  assert.equal(me.sent.at(-1).base, 40);
  assert.ok(me.sent.at(-1).seq > me.sent[0].seq, "seq keeps counting up");
});

const ALPHABET = ["a", "b", "ä", "😀", "\n", " "];

/** A random new text: an insert, a delete or a replacement somewhere in `text`. */
function randomEdit(next, text) {
  const chars = Array.from(text);
  const at = Math.floor(next() * (chars.length + 1));
  const kind = next();
  const del = kind < 0.4 || chars.length > 60 ? Math.min(chars.length - at, 1 + Math.floor(next() * 4)) : 0;
  let ins = "";
  if (kind >= 0.3 || del === 0) {
    const n = next() < 0.6 ? 1 : 1 + Math.floor(next() * 4);
    for (let i = 0; i < n; i += 1) ins += ALPHABET[Math.floor(next() * ALPHABET.length)];
  }
  chars.splice(at, del, ins);
  return chars.join("");
}

function converge(seed) {
  const next = rng(seed);
  const server = new Server("shared text\n");
  const clock = { t: 0 };
  const all = [];
  for (let peer = 1; peer <= 4; peer += 1) {
    const who = { peer, outbox: [], online: true, cursor: 0 };
    who.client = new LiveClient({
      send: (message) => {
        if (who.online) who.outbox.push(message);
      },
      onChange: () => {},
      now: () => clock.t,
    });
    who.client.init({ rev: server.rev, text: server.text, peer });
    all.push(who);
  }
  const reconnect = (who) => {
    who.online = true;
    feed(server, who);
    who.client.retry();
  };

  let edits = 0;
  while (edits < 2000) {
    clock.t += Math.floor(next() * 1500);
    const who = all[Math.floor(next() * all.length)];
    const r = next();
    if (r < 0.3) {
      who.client.local(randomEdit(next, who.client.text));
      edits += 1;
    } else if (r < 0.36) {
      who.client.undo();
      edits += 1;
    } else if (r < 0.4) {
      who.client.redo();
      edits += 1;
    } else if (r < 0.62) {
      if (who.outbox.length > 0) {
        const [message] = who.outbox.splice(Math.floor(next() * who.outbox.length), 1);
        if (next() >= 0.1) server.receive(who.peer, message);
      }
    } else if (r < 0.94) {
      if (who.online && who.cursor < server.log.length) {
        who.client.remote(server.log[who.cursor]);
        who.cursor += 1;
      }
    } else if (r < 0.97) {
      who.online = false;
      who.outbox.length = 0;
    } else if (!who.online || next() < 0.5) {
      reconnect(who);
    }
  }

  for (const who of all) reconnect(who);
  for (let round = 0; all.some((w) => w.outbox.length > 0 || w.cursor < server.log.length); round += 1) {
    assert.ok(round < 100, "the clients do not settle");
    for (const who of all) {
      while (who.outbox.length > 0) server.receive(who.peer, who.outbox.shift());
      feed(server, who);
    }
  }
  for (const who of all) {
    assert.equal(who.client.state, "synced", `seed ${seed}, peer ${who.peer}`);
    assert.equal(who.client.text, server.text, `seed ${seed}, peer ${who.peer}`);
    assert.equal(who.client.rev, server.rev);
  }
}

test("random_clients_converge", () => {
  for (const seed of [1, 0x11fe, 20261117]) converge(seed);
});
