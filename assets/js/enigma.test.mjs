import test from "node:test";
import assert from "node:assert/strict";
import {
  defaultKey,
  encipher,
  group,
  keyLine,
  looksLikeEnigma,
  normalise,
  startedLine,
  swapRotor,
  togglePlug,
  turnStart,
  wheelSteps,
} from "./enigma.js";

const out = (text, key) => encipher(text, key).records.map((record) => record.out).join("");
const pairs = (text) => text.split(" ").map((pair) => [...pair].map((letter) => letter.charCodeAt(0) - 65));

const BARBAROSSA_CIPHER = "EDPUDNRGYSZRCXNUYTPOMRMBOFKTBZREZKMLXLVEFGUEYSIOZVEQMIKUBPMMYLKLTTDEISMDICAGYKUACTCDOMOHWXMUUIAUBSTSLRNBZSZWNRFXWFYSSXJZVIJHIDISHPRKLKAYUPADTXQSPINQMATLPIFSVKDASCTACDPBOPVHJK";
const BARBAROSSA_PLAIN = "AUFKLXABTEILUNGXVONXKURTINOWAXKURTINOWAXNORDWESTLXSEBEZXSEBEZXUAFFLIEGERSTRASZERIQTUNGXDUBROWKIXDUBROWKIXOPOTSCHKAXOPOTSCHKAXUMXEINSAQTDREINULLXUHRANGETRETENXANGRIFFXINFXRGTX";

test("the textbook result", () => assert.equal(out("AAAAA", defaultKey()), "BDZGO"));
test("ring settings 02 02 02", () => assert.equal(out("AAAAA", { ...defaultKey(), rings: [1, 1, 1] }), "EWTYX"));
test("the middle rotor steps twice", () => {
  const pos = encipher("AAA", { ...defaultKey(), start: [0, 3, 20] }).records.map((record) => record.pos);
  assert.deepEqual(pos, [[0, 3, 21], [0, 4, 22], [1, 5, 23]]);
});
test("Barbarossa, 1941, part one", () => {
  const key = {
    rotors: ["II", "IV", "V"],
    reflector: "B",
    rings: [1, 20, 11],
    start: [1, 11, 0],
    plugs: pairs("AV BS CG DL FU HZ IN KM OW RX"),
  };
  assert.equal(out(BARBAROSSA_CIPHER, key), BARBAROSSA_PLAIN);
});
test("deciphers with the key it enciphers with, and no letter stays itself", () => {
  const key = {
    rotors: ["IV", "I", "V"],
    reflector: "C",
    rings: [3, 25, 9],
    start: [7, 16, 4],
    plugs: [[0, 25], [4, 12]],
  };
  const plain = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG".repeat(8);
  const cipher = out(plain, key);
  assert.equal(out(cipher, key), plain);
  for (let i = 0; i < plain.length; i++) assert.notEqual(cipher[i], plain[i]);
});
test("the path names nine stages", () => {
  const [record] = encipher("A", defaultKey()).records;
  assert.deepEqual(record.path.map((part) => part.stage), ["plug", "III", "II", "I", "reflector B", "I", "II", "III", "plug"]);
  assert.equal(record.path.at(-1).letter, record.out);
});
test("empty input leaves the rotors at the start", () => {
  assert.deepEqual(encipher("", { ...defaultKey(), start: [1, 2, 3] }).end, [1, 2, 3]);
});


test("normalise keys text in as an operator would", () => {
  assert.equal(normalise("Wetter für Köln, Straße 7!\n"), "WETTERFUERKOELNSTRASSE");
  assert.equal(normalise("Ärger café Æ"), "AERGERCAFE");
  assert.equal(normalise("123 🙂 ..."), "");
});
test("group writes fives", () => {
  assert.equal(group("ABCDEFGHIJKL"), "ABCDE FGHIJ KL");
  assert.equal(group(""), "");
});
test("the key line names the start and orders the cables", () => {
  const key = {
    rotors: ["I", "II", "III"],
    reflector: "B",
    rings: [0, 0, 25],
    start: [0, 0, 22],
    plugs: [[5, 4], [3, 2], [1, 0]],
  };
  assert.equal(keyLine(key), "Rotors I II III · Reflector B · Rings 01 01 26 · Start A A W · Plugs AB CD EF");
  assert.equal(keyLine(defaultKey()), "Rotors I II III · Reflector B · Rings 01 01 01 · Start A A A · Plugs none");
});
test("the started line", () => {
  const key = { ...defaultKey(), start: [0, 0, 22] };
  assert.equal(startedLine(key, 12), "Started at A A W, 12 letters ago. Turning a rotor moves the start.");
  assert.equal(startedLine(key, 1), "Started at A A W, 1 letter ago. Turning a rotor moves the start.");
});
test("plugging", () => {
  assert.deepEqual(togglePlug([], null, 3), { plugs: [], pending: 3 });
  assert.deepEqual(togglePlug([], 3, 3), { plugs: [], pending: null });
  assert.deepEqual(togglePlug([], 3, 7), { plugs: [[3, 7]], pending: null });
  assert.deepEqual(togglePlug([[3, 7]], null, 7), { plugs: [], pending: null });
  assert.deepEqual(togglePlug([[3, 7]], 1, 3), { plugs: [], pending: null });
});
test("a rotor sits in one slot only", () => {
  assert.deepEqual(swapRotor(["I", "II", "III"], 0, "III"), ["III", "II", "I"]);
  assert.deepEqual(swapRotor(["I", "II", "III"], 0, "V"), ["V", "II", "III"]);
});
test("turning moves the start and wraps", () => {
  assert.deepEqual(turnStart(defaultKey(), 2, -1).start, [0, 0, 25]);
  assert.deepEqual(turnStart(defaultKey(), 0, 27).start, [1, 0, 0]);
});
test("one wheel notch is one step, on mice and trackpads", () => {
  assert.deepEqual(wheelSteps(0, 120, 0), { steps: 1, acc: 20 });
  assert.deepEqual(wheelSteps(0, 3, 1), { steps: 1, acc: 2 });
  assert.deepEqual(wheelSteps(0, 4, 0), { steps: 0, acc: 4 });
  assert.equal(Array.from({ length: 30 }).reduce((state) => {
    const result = wheelSteps(state.acc, 4, 0);
    return { acc: result.acc, n: state.n + result.steps };
  }, { acc: 0, n: 0 }).n, 1);
  assert.deepEqual(wheelSteps(0, -120, 0), { steps: -1, acc: -20 });
});
test("what counts as Enigma output", () => {
  for (const yes of ["ABCDE FGHIJ", "ABCDE FGHIJ K", "ABCDE\nFGHIJ KLMNO", "  ABCDE FGHIJ  \n"]) {
    assert.equal(looksLikeEnigma(yes), true, yes);
  }
  for (const no of ["HELLO", "ABCDE", "abcde fghij", "ABCDE FGHIJK", "ABCD EFGHI", "ABCDE 12345", "ABCDE FGH IJKLM", ""]) {
    assert.equal(looksLikeEnigma(no), false, no);
  }
});
