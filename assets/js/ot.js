// Text operations for live edit, the browser side of `src/domain/live/ot.rs`; the shared fixture
// `tests/fixtures/ot.json` pins that both give the same answers.
//
// An operation is a plain array that walks the whole text once: a positive integer keeps that
// many characters, a negative one deletes them, a string inserts it. Every function here returns
// operations in normal form: adjacent parts of one kind merged, no empty part, and an insert
// before a delete at the same spot. Positions and lengths count code points, never UTF-16 units.

const MAX = 0xffffffff;
// The most parts the server takes in one operation (`MAX_PARTS` in `ot.rs`).
export const MAX_PARTS = 4096;

const isHigh = (c) => c >= 0xd800 && c <= 0xdbff;
const isLow = (c) => c >= 0xdc00 && c <= 0xdfff;

export function cpLength(text) {
  let n = text.length;
  for (let i = 0; i < text.length - 1; i += 1) {
    if (isHigh(text.charCodeAt(i)) && isLow(text.charCodeAt(i + 1))) {
      n -= 1;
      i += 1;
    }
  }
  return n;
}

// The UTF-16 index `n` code points after unit index `from`, or the end of the text.
function advance(text, from, n) {
  let i = from;
  for (; n > 0 && i < text.length; n -= 1) {
    i += isHigh(text.charCodeAt(i)) && isLow(text.charCodeAt(i + 1)) ? 2 : 1;
  }
  return i;
}

// The UTF-16 index of code point `cp`; past the end it is the text's length.
export function cpToUnit(text, cp) {
  return advance(text, 0, cp);
}

// How many code points lie wholly before UTF-16 index `unit`; inside a pair it counts the pair
// as after.
export function unitToCp(text, unit) {
  let n = 0;
  for (let i = 0; i < unit && i < text.length; n += 1) {
    const pair = isHigh(text.charCodeAt(i)) && isLow(text.charCodeAt(i + 1));
    if (pair && i + 1 >= unit) break;
    i += pair ? 2 : 1;
  }
  return n;
}

// The text with every lone surrogate replaced by U+FFFD, so it survives being sent as UTF-8.
export function wellFormed(text) {
  if (typeof text.toWellFormed === "function") return text.toWellFormed();
  let out = "";
  let from = 0;
  for (let i = 0; i < text.length; i += 1) {
    const c = text.charCodeAt(i);
    if (isHigh(c) && isLow(text.charCodeAt(i + 1))) {
      i += 1;
    } else if (isHigh(c) || isLow(c)) {
      out += `${text.slice(from, i)}�`;
      from = i + 1;
    }
  }
  return out + text.slice(from);
}

function checkPart(part) {
  if (typeof part === "string") {
    if (part === "") throw new TypeError("An operation inserts an empty string.");
  } else if (!Number.isInteger(part) || part === 0 || Math.abs(part) > MAX) {
    throw new TypeError("An operation part is not a non-zero integer or a string.");
  }
}

// Checks every part and returns the base and target lengths.
function lengths(op) {
  if (!Array.isArray(op)) throw new TypeError("An operation is not an array.");
  let base = 0;
  let target = 0;
  for (const part of op) {
    checkPart(part);
    if (typeof part === "string") target += cpLength(part);
    else if (part > 0) {
      base += part;
      target += part;
    } else base -= part;
  }
  if (base > MAX || target > MAX) throw new RangeError("The operation is too long.");
  return { base, target };
}

export function baseLength(op) {
  return lengths(op).base;
}

export function targetLength(op) {
  return lengths(op).target;
}

export function isNoop(op) {
  lengths(op);
  return op.every((part) => typeof part === "number" && part > 0);
}

// Appends a part to the normalised operation `out`.
function push(out, part) {
  if (part === 0 || part === "") return;
  const last = out[out.length - 1];
  if (typeof part === "number") {
    if (typeof last === "number" && (last > 0) === (part > 0)) out[out.length - 1] = last + part;
    else out.push(part);
    return;
  }
  const at = typeof last === "number" && last < 0 ? out.length - 1 : out.length;
  if (typeof out[at - 1] === "string") out[at - 1] += part;
  else out.splice(at, 0, part);
}

export function apply(text, op) {
  if (lengths(op).base !== cpLength(text)) {
    throw new RangeError("The operation does not fit the text's length.");
  }
  const out = [];
  let i = 0;
  for (const part of op) {
    if (typeof part === "string") out.push(part);
    else {
      const j = advance(text, i, Math.abs(part));
      if (part > 0) out.push(text.slice(i, j));
      i = j;
    }
  }
  return out.join("");
}

// The operation that undoes `op` on `text`: kept text stays, deleted text comes back, inserted
// text goes.
export function invert(op, text) {
  if (lengths(op).base !== cpLength(text)) {
    throw new RangeError("The operation does not fit the text's length.");
  }
  const out = [];
  let i = 0;
  for (const part of op) {
    if (typeof part === "string") push(out, -cpLength(part));
    else {
      const j = advance(text, i, Math.abs(part));
      push(out, part > 0 ? part : text.slice(i, j));
      i = j;
    }
  }
  return out;
}

// Walks an operation part by part, splitting keeps, deletes and inserts as asked.
class Steps {
  constructor(op) {
    this.op = op;
    this.index = 0;
    this.head = op[0];
  }

  next() {
    this.index += 1;
    this.head = this.op[this.index];
  }

  // Consumes `n` characters of the current keep or delete.
  take(n) {
    const left = Math.abs(this.head) - n;
    if (left > 0) this.head = this.head > 0 ? left : -left;
    else this.next();
  }

  // Consumes `n` characters of the current insert and returns them.
  takeText(n) {
    const at = cpToUnit(this.head, n);
    const taken = this.head.slice(0, at);
    if (at < this.head.length) this.head = this.head.slice(at);
    else this.next();
    return taken;
  }
}

const size = (part) => (typeof part === "string" ? cpLength(part) : Math.abs(part));

// Transforms two operations on the same text into `[first2, second2]`, so that `second2` applies
// after `first` and `first2` after `second`, both giving the same text. `first` is the operation
// the server received first: of two inserts at one position, its text comes first.
export function transform(first, second) {
  if (lengths(first).base !== lengths(second).base) {
    throw new RangeError("The two operations do not share a text.");
  }
  const first2 = [];
  const second2 = [];
  const a = new Steps(first);
  const b = new Steps(second);
  while (a.head !== undefined || b.head !== undefined) {
    if (typeof a.head === "string") {
      push(first2, a.head);
      push(second2, cpLength(a.head));
      a.next();
    } else if (typeof b.head === "string") {
      push(first2, cpLength(b.head));
      push(second2, b.head);
      b.next();
    } else {
      // Equal base lengths mean neither runs out while the other still keeps or deletes.
      const n = Math.min(size(a.head), size(b.head));
      if (a.head > 0 && b.head > 0) {
        push(first2, n);
        push(second2, n);
      } else if (a.head < 0 && b.head > 0) push(first2, -n);
      else if (a.head > 0 && b.head < 0) push(second2, -n);
      a.take(n);
      b.take(n);
    }
  }
  return [first2, second2];
}

// One operation equal to `a` followed by `b`.
export function compose(a, b) {
  if (lengths(a).target !== lengths(b).base) {
    throw new RangeError("The second operation does not fit the first one's result.");
  }
  const out = [];
  const x = new Steps(a);
  const y = new Steps(b);
  while (x.head !== undefined || y.head !== undefined) {
    if (typeof x.head === "number" && x.head < 0) {
      push(out, x.head);
      x.next();
    } else if (typeof y.head === "string") {
      push(out, y.head);
      y.next();
    } else {
      // Matching lengths mean both still have a part here.
      const n = Math.min(size(x.head), size(y.head));
      if (typeof x.head === "string") {
        const text = x.takeText(n);
        if (y.head > 0) push(out, text);
      } else {
        push(out, y.head > 0 ? n : -n);
        x.take(n);
      }
      y.take(n);
    }
  }
  return out;
}

// An operation of at most four parts with the effect of `op`, whose result is `target`: the
// start and end `op` keeps stay kept, everything between is replaced by what `target` has there.
// It merges less finely with crossing edits, so it stands in only for an operation too long to
// send.
export function coarsen(op, target) {
  const { base, target: length } = lengths(op);
  if (length !== cpLength(target)) {
    throw new RangeError("The text is not the operation's result.");
  }
  const first = op[0];
  const last = op[op.length - 1];
  const head = typeof first === "number" && first > 0 ? first : 0;
  const tail = op.length > 1 && typeof last === "number" && last > 0 ? last : 0;
  const out = [];
  push(out, head);
  push(out, -(base - head - tail));
  push(out, target.slice(cpToUnit(target, head), cpToUnit(target, length - tail)));
  push(out, tail);
  return out;
}

// The operation that turns `oldText` into `newText`: the common prefix and suffix are kept, the
// middle is deleted and the new middle inserted. Both ends are compared on UTF-16 units and moved
// back to a code-point boundary, so a surrogate pair is never cut.
export function diff(oldText, newText) {
  const shorter = Math.min(oldText.length, newText.length);
  let start = 0;
  while (start < shorter && oldText.charCodeAt(start) === newText.charCodeAt(start)) start += 1;
  if (
    start > 0 &&
    isHigh(oldText.charCodeAt(start - 1)) &&
    (isLow(oldText.charCodeAt(start)) || isLow(newText.charCodeAt(start)))
  ) {
    start -= 1;
  }
  let end = 0;
  const room = shorter - start;
  const unitAt = (text, back) => text.charCodeAt(text.length - 1 - back);
  while (end < room && unitAt(oldText, end) === unitAt(newText, end)) end += 1;
  if (end > 0 && isLow(unitAt(oldText, end - 1)) && (isHigh(unitAt(oldText, end)) || isHigh(unitAt(newText, end)))) {
    end -= 1;
  }
  const out = [];
  push(out, cpLength(oldText.slice(0, start)));
  push(out, -cpLength(oldText.slice(start, oldText.length - end)));
  push(out, newText.slice(start, newText.length - end));
  push(out, cpLength(oldText.slice(oldText.length - end)));
  return out;
}

// Where code-point position `pos` of the base text ends up after `op`. A position inside a deleted
// range moves to where the range was; `sticky` keeps it before an insert at that very position.
export function transformPos(pos, op, sticky) {
  const { base } = lengths(op);
  if (!Number.isInteger(pos) || pos < 0 || pos > base) {
    throw new RangeError("The position is outside the text.");
  }
  let at = 0;
  let moved = pos;
  for (const part of op) {
    if (at > pos) break;
    if (typeof part === "string") {
      if (at < pos || !sticky) moved += cpLength(part);
    } else {
      if (part < 0) moved -= Math.min(-part, pos - at);
      at += Math.abs(part);
    }
  }
  return moved;
}
