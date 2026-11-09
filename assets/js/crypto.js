// The browser side of the BVC container, alg 2 (src/domain/crypto.rs documents the layout).
//
// "BVC" | 0x01 | alg 2 | kdf 2 | iterations u32 BE | salt 16 | nonce prefix 7 | chunks
// Each chunk holds 65 536 plaintext bytes (the last 0–65 536) and its 16-byte AES-GCM tag, sealed
// with nonce prefix ‖ counter u32 BE ‖ last-chunk flag and the whole header as associated data.

export const ITERATIONS = 600000;
// The server's ceiling, mirrored so a crafted header cannot make a reader's browser spin.
export const MAX_ITERATIONS = 6000000;
export const CHUNK_LEN = 65536;
export const HEADER_LEN = 33;

const MAGIC = [0x42, 0x56, 0x43];
const VERSION = 0x01;
const ALG_AES256_GCM = 2;
const KDF_PBKDF2_SHA256 = 2;
const SALT_LEN = 16;
const PREFIX_LEN = 7;
const TAG_LEN = 16;
const CT_CHUNK_LEN = CHUNK_LEN + TAG_LEN;
const VERIFIER_CONTEXT = new TextEncoder().encode("bitvault-delete");

const subtle = globalThis.crypto.subtle;

function failure(name, message) {
  const e = new Error(message);
  e.name = name;
  return e;
}

const wrongPassword = () => failure("WrongPassword", "That password does not open this paste. Check it and try again.");
const unsupported = () => failure("UnsupportedFormat", "This paste was saved in a format this page cannot read.");

// PBKDF2-HMAC-SHA256 → 512 bits: the first half becomes a non-extractable AES-GCM key, the
// second the verifier HMAC key (also non-extractable).
export async function deriveKeys(password, salt, iterations = ITERATIONS) {
  const base = await subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = new Uint8Array(
    await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, base, 512),
  );
  try {
    const aesKey = await subtle.importKey("raw", bits.subarray(0, 32), "AES-GCM", false, ["encrypt", "decrypt"]);
    const verifierKey = await subtle.importKey("raw", bits.subarray(32), { name: "HMAC", hash: "SHA-256" }, false, [
      "sign",
    ]);
    return { aesKey, verifierKey };
  } finally {
    bits.fill(0);
  }
}

function nonce(prefix, counter, last) {
  const n = new Uint8Array(12);
  n.set(prefix);
  new DataView(n.buffer).setUint32(PREFIX_LEN, counter);
  n[11] = last ? 1 : 0;
  return n;
}

// Seals `bytes` under `password` with a fresh salt and nonce prefix.
export async function seal(password, bytes) {
  const header = new Uint8Array(HEADER_LEN);
  header.set(MAGIC);
  header[3] = VERSION;
  header[4] = ALG_AES256_GCM;
  header[5] = KDF_PBKDF2_SHA256;
  new DataView(header.buffer).setUint32(6, ITERATIONS);
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const prefix = globalThis.crypto.getRandomValues(new Uint8Array(PREFIX_LEN));
  header.set(salt, 10);
  header.set(prefix, 10 + SALT_LEN);
  const { aesKey } = await deriveKeys(password, salt, ITERATIONS);

  // Empty plaintext is one empty final chunk; an exact multiple ends with a full final chunk.
  const count = Math.max(1, Math.ceil(bytes.length / CHUNK_LEN));
  const out = new Uint8Array(HEADER_LEN + bytes.length + count * TAG_LEN);
  out.set(header);
  let at = HEADER_LEN;
  for (let i = 0; i < count; i++) {
    const chunk = bytes.subarray(i * CHUNK_LEN, Math.min((i + 1) * CHUNK_LEN, bytes.length));
    const sealed = await subtle.encrypt(
      { name: "AES-GCM", iv: nonce(prefix, i, i + 1 === count), additionalData: header, tagLength: 128 },
      aesKey,
      chunk,
    );
    out.set(new Uint8Array(sealed), at);
    at += sealed.byteLength;
  }
  return out;
}

// The header's salt, nonce prefix and iteration count, refusing anything the server would.
function parseHeader(container) {
  if (container.length < HEADER_LEN + TAG_LEN) throw unsupported();
  const head = container.subarray(0, HEADER_LEN);
  const fixed = [...MAGIC, VERSION, ALG_AES256_GCM, KDF_PBKDF2_SHA256];
  if (fixed.some((b, i) => head[i] !== b)) throw unsupported();
  const iterations = new DataView(head.buffer, head.byteOffset, HEADER_LEN).getUint32(6);
  if (iterations < ITERATIONS || iterations > MAX_ITERATIONS) throw unsupported();
  return {
    header: head,
    iterations,
    salt: head.subarray(10, 10 + SALT_LEN),
    prefix: head.subarray(10 + SALT_LEN),
  };
}

// Opens a container. A failed tag (a wrong password, or altered bytes) throws `WrongPassword`.
export async function open(password, container) {
  const bytes = container instanceof Uint8Array ? container : new Uint8Array(container);
  const { header, iterations, salt, prefix } = parseHeader(bytes);
  const { aesKey } = await deriveKeys(password, salt, iterations);
  const body = bytes.subarray(HEADER_LEN);
  // A final piece shorter than a tag cannot authenticate; Rust's open fails it on the tag too.
  const tail = body.length % CT_CHUNK_LEN;
  if (tail > 0 && tail < TAG_LEN) throw wrongPassword();
  const chunks = Math.max(1, Math.ceil(body.length / CT_CHUNK_LEN));
  const out = new Uint8Array(body.length - chunks * TAG_LEN);
  let at = 0;
  for (let i = 0, rest = body; ; i++) {
    // Only the final chunk may be shorter than a full one, so length alone says which is last.
    const last = rest.length <= CT_CHUNK_LEN;
    const chunk = last ? rest : rest.subarray(0, CT_CHUNK_LEN);
    let plain;
    try {
      plain = await subtle.decrypt(
        { name: "AES-GCM", iv: nonce(prefix, i, last), additionalData: header, tagLength: 128 },
        aesKey,
        chunk,
      );
    } catch {
      throw wrongPassword();
    }
    out.set(new Uint8Array(plain), at);
    at += plain.byteLength;
    if (last) break;
    rest = rest.subarray(CT_CHUNK_LEN);
  }
  return out;
}

// The delete verifier: HMAC-SHA256(verifier key, "bitvault-delete"), derived with `salt`.
export async function verifier(password, salt) {
  const { verifierKey } = await deriveKeys(password, salt, ITERATIONS);
  return new Uint8Array(await subtle.sign("HMAC", verifierKey, VERIFIER_CONTEXT));
}

export function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function fromHex(text) {
  if (!/^(?:[0-9a-f]{2})*$/i.test(text)) throw unsupported();
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(text.slice(2 * i, 2 * i + 2), 16);
  return out;
}
