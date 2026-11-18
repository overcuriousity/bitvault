// The editing state of one live-edit client, without DOM or network: the usual three-state OT
// client (in sync, one edit in flight, in flight with a buffer) plus an undo history of this
// client's own edits. The stream alone gives the order: an edit is applied once its own peer and
// seq come back as an `op`, and every foreign operation is transformed with the server's
// operation as `first`, as the server does.

import { apply, compose, cpLength, diff, invert, isNoop, transform, transformPos, wellFormed } from "./ot.js";

// Single-character inserts closer together than this undo as one step.
const JOIN_MS = 1000;

// Whether `op` inserts exactly one character and deletes nothing.
function isOneInsert(op) {
  let inserts = 0;
  for (const part of op) {
    if (typeof part === "string") {
      if (cpLength(part) !== 1) return false;
      inserts += 1;
    } else if (part < 0) return false;
  }
  return inserts === 1;
}

// Moves a stack of steps over `op`, which applies to the same text as its top step. Each step
// applies after the one above it, so `op` is carried down the stack as it is transformed.
function transformStack(stack, op) {
  let over = op;
  for (let i = stack.length - 1; i >= 0; i -= 1) {
    [over, stack[i]] = transform(over, stack[i]);
  }
}

export class LiveClient {
  #send;
  #onChange;
  #now;
  #text = "";
  #rev = 0;
  #peer = 0;
  #seq = 0;
  // `{seq, op}`: the edit sent and not yet seen on the stream, transformed to the current `rev`.
  #inflight = null;
  // Everything typed since `#inflight` went out, as one operation after it.
  #buffer = null;
  #undo = [];
  #redo = [];
  // Whether the top undo step is a single-character insert that the next one may join, and when.
  #joinable = false;
  #lastAt = 0;

  constructor({ send, onChange, now = Date.now }) {
    this.#send = send;
    this.#onChange = onChange;
    this.#now = now;
  }

  get text() {
    return this.#text;
  }

  get rev() {
    return this.#rev;
  }

  get state() {
    if (this.#inflight === null) return "synced";
    return this.#buffer === null ? "waiting" : "buffered";
  }

  get unsent() {
    return this.#inflight !== null;
  }

  // Starts over from a fresh `init`; unsent work and the history are dropped. `seq` keeps
  // counting, so nothing new can look like an edit the server has already applied.
  init({ rev, text, peer }) {
    this.#rev = rev;
    this.#text = text;
    this.#peer = peer;
    this.#inflight = null;
    this.#buffer = null;
    this.#undo = [];
    this.#redo = [];
    this.#joinable = false;
  }

  // The textarea now holds `newText`.
  local(newText) {
    const next = wellFormed(newText);
    if (next === this.#text) return;
    const op = diff(this.#text, next);
    const back = invert(op, this.#text);
    this.#text = next;
    this.#redo = [];
    const now = this.#now();
    const one = isOneInsert(op);
    if (one && this.#joinable && now - this.#lastAt < JOIN_MS) {
      this.#undo.push(compose(back, this.#undo.pop()));
    } else {
      this.#undo.push(back);
    }
    this.#joinable = one;
    this.#lastAt = now;
    this.#submit(op);
  }

  // An `op` event from the stream.
  remote({ rev, peer, seq, op }) {
    if (rev <= this.#rev) return;
    this.#rev = rev;
    if (this.#inflight !== null && peer === this.#peer && seq === this.#inflight.seq) {
      this.#inflight = null;
      if (this.#buffer !== null) {
        const buffer = this.#buffer;
        this.#buffer = null;
        this.#submit(buffer);
      }
      return;
    }
    let over = op;
    if (this.#inflight !== null) [over, this.#inflight.op] = transform(over, this.#inflight.op);
    if (this.#buffer !== null) [over, this.#buffer] = transform(over, this.#buffer);
    this.#text = apply(this.#text, over);
    transformStack(this.#undo, over);
    transformStack(this.#redo, over);
    if (!isNoop(over)) this.#changed(over);
  }

  // After a reconnect and its replay: sends the in-flight edit again, as of the current `rev`.
  retry() {
    if (this.#inflight === null) return;
    this.#send({ seq: this.#inflight.seq, base: this.#rev, op: this.#inflight.op });
  }

  undo() {
    this.#step(this.#undo, this.#redo);
  }

  redo() {
    this.#step(this.#redo, this.#undo);
  }

  // Applies the first step of `from` that still changes something and keeps its inverse in `to`.
  #step(from, to) {
    while (from.length > 0) {
      const op = from.pop();
      if (isNoop(op)) continue;
      to.push(invert(op, this.#text));
      this.#text = apply(this.#text, op);
      this.#joinable = false;
      this.#submit(op);
      this.#changed(op);
      return;
    }
  }

  #submit(op) {
    if (this.#inflight === null) {
      this.#seq += 1;
      this.#inflight = { seq: this.#seq, op };
      this.#send({ seq: this.#seq, base: this.#rev, op });
    } else {
      this.#buffer = this.#buffer === null ? op : compose(this.#buffer, op);
    }
  }

  #changed(op) {
    this.#onChange(this.#text, (pos, sticky = false) => transformPos(pos, op, sticky));
  }
}
