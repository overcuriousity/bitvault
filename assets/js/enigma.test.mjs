import test from "node:test";
import assert from "node:assert/strict";
import { defaultKey, encipher } from "./enigma.js";

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
