import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";

import { CHUNK_LEN, HEADER_LEN, ITERATIONS, open, seal, verifier } from "./crypto.js";

const PASSWORD = "correct horse battery staple";
const TAG_LEN = 16;
const CT_CHUNK_LEN = CHUNK_LEN + TAG_LEN;

function pattern(n) {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = (i * 31 + 7) & 0xff;
  return out;
}

async function rejectsAs(promise, name) {
  await assert.rejects(promise, (e) => {
    assert.equal(e.name, name);
    return true;
  });
}

const b64 = (bytes) => Buffer.from(bytes).toString("base64");
const hex = (bytes) => Buffer.from(bytes).toString("hex");

test("seal then open round-trips 200 KiB", async () => {
  const plain = pattern(200 * 1024);
  const sealed = await seal(PASSWORD, plain);
  assert.equal(sealed.length, HEADER_LEN + plain.length + 4 * TAG_LEN);
  assert.deepEqual(await open(PASSWORD, sealed), plain);
});

test("empty plaintext is one empty final chunk", async () => {
  const sealed = await seal(PASSWORD, new Uint8Array(0));
  assert.equal(sealed.length, HEADER_LEN + TAG_LEN);
  assert.equal((await open(PASSWORD, sealed)).length, 0);
});

test("an exact multiple of the chunk size ends with a full final chunk", async () => {
  const plain = pattern(2 * CHUNK_LEN);
  const sealed = await seal(PASSWORD, plain);
  assert.equal(sealed.length, HEADER_LEN + 2 * CT_CHUNK_LEN);
  assert.deepEqual(await open(PASSWORD, sealed), plain);
});

test("wrong password throws WrongPassword", async () => {
  const sealed = await seal(PASSWORD, pattern(100));
  await rejectsAs(open("not the password", sealed), "WrongPassword");
});

test("flipping a header or chunk byte fails", async () => {
  const sealed = await seal(PASSWORD, pattern(100));
  // Salt, nonce prefix and ciphertext: each is bound by the key or the associated data.
  for (const at of [12, HEADER_LEN - 1, HEADER_LEN + 5, sealed.length - 1]) {
    const bad = sealed.slice();
    bad[at] ^= 0x01;
    await assert.rejects(open(PASSWORD, bad), `byte ${at}`);
  }
  const badMagic = sealed.slice();
  badMagic[0] ^= 0x01;
  await rejectsAs(open(PASSWORD, badMagic), "UnsupportedFormat");
});

test("reordered and truncated chunks fail", async () => {
  const plain = pattern(3 * CHUNK_LEN + 10);
  const sealed = await seal(PASSWORD, plain);
  const header = sealed.subarray(0, HEADER_LEN);
  const chunk = (i) => sealed.subarray(HEADER_LEN + i * CT_CHUNK_LEN, HEADER_LEN + (i + 1) * CT_CHUNK_LEN);
  const swapped = Buffer.concat([header, chunk(1), chunk(0), sealed.subarray(HEADER_LEN + 2 * CT_CHUNK_LEN)]);
  await rejectsAs(open(PASSWORD, swapped), "WrongPassword");
  const truncated = sealed.subarray(0, HEADER_LEN + 3 * CT_CHUNK_LEN);
  await rejectsAs(open(PASSWORD, truncated), "WrongPassword");
  const extended = Buffer.concat([sealed, chunk(0)]);
  await rejectsAs(open(PASSWORD, extended), "WrongPassword");
});

test("the header records 600000 iterations", async () => {
  const sealed = await seal(PASSWORD, pattern(10));
  assert.deepEqual([...sealed.subarray(0, 6)], [0x42, 0x56, 0x43, 0x01, 0x02, 0x02]);
  const view = new DataView(sealed.buffer, sealed.byteOffset);
  assert.equal(view.getUint32(6), 600000);
  assert.equal(ITERATIONS, 600000);
  assert.equal(HEADER_LEN, 33);
});

test("iteration counts outside the server's range are refused before deriving", async () => {
  const sealed = await seal(PASSWORD, pattern(10));
  // 2^32 - 1 iterations would take hours to derive, so this finishing proves no derivation ran.
  for (const iterations of [0xffffffff, 6000001, 599999, 1]) {
    const bad = sealed.slice();
    new DataView(bad.buffer).setUint32(6, iterations);
    await rejectsAs(open(PASSWORD, bad), "UnsupportedFormat");
  }
});

test("short and foreign containers are refused", async () => {
  await rejectsAs(open(PASSWORD, new Uint8Array(10)), "UnsupportedFormat");
  const sealed = await seal(PASSWORD, pattern(10));
  await rejectsAs(open(PASSWORD, sealed.subarray(0, HEADER_LEN)), "UnsupportedFormat");
  await rejectsAs(open(PASSWORD, sealed.subarray(0, HEADER_LEN + TAG_LEN - 1)), "UnsupportedFormat");
  const alg1 = sealed.slice();
  alg1[4] = 1;
  await rejectsAs(open(PASSWORD, alg1), "UnsupportedFormat");
});

test("containers sealed in Rust open in JavaScript", async () => {
  const fixture = JSON.parse(readFileSync(new URL("../../tests/fixtures/js/rust-alg2.json", import.meta.url)));
  assert.ok(fixture.cases.length >= 3);
  for (const c of fixture.cases) {
    const plain = await open(fixture.password, Buffer.from(c.container_b64, "base64"));
    assert.equal(b64(plain), c.plain_b64);
  }
  const salt = Buffer.from(fixture.verifier_salt_hex, "hex");
  assert.equal(hex(await verifier(fixture.password, salt)), fixture.verifier_hex);
});

test("writes interop fixtures", async () => {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const plain = new TextEncoder().encode(JSON.stringify({ text: "héllo from the browser ✓", files: ["a.png"] }));
  const cases = [];
  for (const p of [new Uint8Array(0), pattern(CHUNK_LEN), pattern(CHUNK_LEN + 3)]) {
    cases.push({ container_b64: b64(await seal(PASSWORD, p)), plain_b64: b64(p) });
  }
  const fixture = {
    password: PASSWORD,
    container_b64: b64(await seal(PASSWORD, plain)),
    plain_b64: b64(plain),
    verifier_salt_hex: hex(salt),
    verifier_hex: hex(await verifier(PASSWORD, salt)),
    cases,
  };
  const dir = new URL("../../tests/fixtures/js/", import.meta.url);
  mkdirSync(dir, { recursive: true });
  writeFileSync(new URL("alg2.json", dir), `${JSON.stringify(fixture, null, 2)}\n`);
});
