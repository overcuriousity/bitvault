// The secret paste page: fetches the content container once, opens it with the password typed
// here, and decrypts files on download. The password never leaves this page.
import { CHUNK_LEN, HEADER_LEN, describe, fromHex, open, toHex, verifier } from "./crypto.js";
import { fillLines } from "./lines.js";
import { serverMessage, showNotice } from "./notice.js";

const PREVIEW_LIMIT = 10 * 1024 * 1024;
// The largest container that can hold a previewable image.
const PREVIEW_CONTAINER_LIMIT = HEADER_LEN + PREVIEW_LIMIT + 16 * (Math.ceil(PREVIEW_LIMIT / CHUNK_LEN) + 1);
const IMAGE_NAME = /\.(png|jpe?g|gif|webp|avif)$/i;
// The types the server would preview inline too; SVG is never shown, as it can carry script.
const SIGNATURES = [
  ["image/png", [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]],
  ["image/jpeg", [0xff, 0xd8, 0xff]],
  ["image/gif", [0x47, 0x49, 0x46, 0x38]],
];
// Revoking at once can cancel a download that has not started reading the Blob yet.
const REVOKE_AFTER_MS = 40000;

export function sniffImage(bytes) {
  for (const [type, sig] of SIGNATURES) if (sig.every((b, i) => bytes[i] === b)) return type;
  const ascii = (from, to) => String.fromCharCode(...bytes.subarray(from, to));
  if (ascii(0, 4) === "RIFF" && ascii(8, 12) === "WEBP") return "image/webp";
  if (ascii(4, 8) === "ftyp" && ["avif", "avis"].includes(ascii(8, 12))) return "image/avif";
  return null;
}

export function parseEnvelope(bytes) {
  const value = JSON.parse(new TextDecoder().decode(bytes));
  const files = Array.isArray(value?.files) ? value.files : [];
  if (typeof value?.text !== "string" || !files.every((f) => typeof f === "string")) {
    throw new Error("not a bitvault envelope");
  }
  return { text: value.text, files };
}

/** Base64 of `bytes`, built in pieces so a long text does not overflow the argument list. */
export function toBase64(bytes) {
  let binary = "";
  for (let at = 0; at < bytes.length; at += 0x8000) binary += String.fromCharCode(...bytes.subarray(at, at + 0x8000));
  return btoa(binary);
}

/**
 * What the page shows of a container before it is opened: the ciphertext in Base64 and, in hex,
 * the values another tool needs beside the password. Null when the container cannot be shown as
 * one ciphertext.
 */
export function cipherFacts(container) {
  let parts;
  try {
    parts = describe(container);
  } catch {
    return null;
  }
  if (!parts) return null;
  return {
    ciphertext: toBase64(parts.ciphertext),
    iterations: String(parts.iterations),
    salt: toHex(parts.salt),
    iv: toHex(parts.iv),
    aad: toHex(parts.aad),
    tag: toHex(parts.tag),
  };
}

function pastePath() {
  return window.location.pathname.replace(/\/+$/, "");
}

async function readCapped(res, limit) {
  const reader = res.body.getReader();
  const parts = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > limit) {
      await reader.cancel();
      return null;
    }
    parts.push(value);
  }
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

function dataUrl(bytes, type) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.addEventListener("load", () => resolve(reader.result));
    reader.addEventListener("error", () => reject(reader.error));
    reader.readAsDataURL(new Blob([bytes], { type }));
  });
}

function save(bytes, name) {
  const url = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.hidden = true;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), REVOKE_AFTER_MS);
}

// The server renders the Copy text button hidden for a secret paste; it has no text to copy until now.
function showCopyText(view) {
  const button = view.querySelector(".bv-actions [data-bv-copy-target]");
  if (button) button.hidden = false;
}

function setBusy(form, busy) {
  const button = form?.querySelector("button[type=submit]");
  if (!button) return;
  button.disabled = busy;
  if (busy) button.setAttribute("aria-busy", "true");
  else button.removeAttribute("aria-busy");
}

function failureMessage(e) {
  return e?.name === "WrongPassword" || e?.name === "UnsupportedFormat"
    ? e.message
    : "This paste could not be opened. Reload the page and try again.";
}

function bind(view) {
  const region = view.querySelector("#secret-notice");
  const form = view.querySelector("#secret-open");
  const input = view.querySelector("#secret-password");
  const target = view.querySelector("pre.paste-text");
  const filesSection = view.querySelector(".bv-files");
  const cipher = view.querySelector("#secret-cipher");
  const remove = view.querySelector("form.bv-delete[data-verifier-salt]");
  const state = { container: null, grant: null, password: null, names: [], opened: new Map() };

  // The ciphertext as stored, with what it takes to decrypt it elsewhere.
  function showCipher() {
    if (!cipher) return;
    const facts = cipherFacts(state.container);
    const text = cipher.querySelector("#cipher-text");
    const how = cipher.querySelector(".bv-cipher__how");
    if (text) text.textContent = facts ? facts.ciphertext : "Too long to show here.";
    const copy = cipher.querySelector(".bv-cipher__head .oc-copy");
    if (copy) {
      copy.hidden = !facts;
      copy.dataset.ocCopy = facts?.ciphertext ?? "";
    }
    if (how) how.hidden = !facts;
    for (const value of cipher.querySelectorAll("[data-bv-cipher]")) {
      const hex = facts?.[value.dataset.bvCipher] ?? "";
      value.textContent = hex;
      const button = value.parentElement?.querySelector(".oc-copy");
      if (button) button.dataset.ocCopy = hex;
    }
    cipher.hidden = false;
  }

  // Fetched once: the fetch is the read, and a burning read cannot be repeated.
  async function load() {
    if (state.container) return true;
    const res = await fetch(`${pastePath()}/raw`, { cache: "no-store", headers: { "HX-Request": "true" } });
    if (!res.ok) {
      showNotice(region, "danger", await serverMessage(res, "This paste could not be loaded. Reload the page."));
      return false;
    }
    state.grant = res.headers.get("x-bitvault-grant");
    state.container = new Uint8Array(await res.arrayBuffer());
    showCipher();
    return true;
  }

  const fileUrl = (position) => {
    const g = state.grant ? `?g=${encodeURIComponent(state.grant)}` : "";
    return `${pastePath()}/file/${position}${g}`;
  };

  async function openFile(position, limit = Infinity) {
    if (state.opened.has(position)) return state.opened.get(position);
    const res = await fetch(fileUrl(position), { cache: "no-store" });
    if (!res.ok) {
      const refused = new Error(await serverMessage(res, "This file could not be downloaded. Try again."));
      refused.name = "Refused";
      throw refused;
    }
    const sealed = await readCapped(res, limit);
    if (!sealed) return null;
    const bytes = await open(state.password, sealed);
    if (bytes.length <= PREVIEW_LIMIT) state.opened.set(position, bytes);
    return bytes;
  }

  function labelFiles() {
    for (const dt of view.querySelectorAll(".bv-file-name[data-position]")) {
      const name = state.names[Number(dt.dataset.position) - 1];
      if (name) dt.textContent = name;
    }
    for (const a of view.querySelectorAll("a[download][data-position]")) {
      const name = state.names[Number(a.dataset.position) - 1];
      if (!name) continue;
      a.setAttribute("aria-label", `Download ${name}`);
      a.dataset.ocTip = `Download ${name}`;
    }
  }

  async function preview() {
    for (const [i, name] of state.names.entries()) {
      if (!IMAGE_NAME.test(name)) continue;
      try {
        const bytes = await openFile(i + 1, PREVIEW_CONTAINER_LIMIT);
        const type = bytes && sniffImage(bytes);
        if (!type) continue;
        const figure = document.createElement("figure");
        figure.className = "bv-preview";
        const img = document.createElement("img");
        img.alt = name;
        img.src = await dataUrl(bytes, type);
        const caption = document.createElement("figcaption");
        caption.textContent = name;
        figure.append(img, caption);
        filesSection?.append(figure);
      } catch {
        /* a preview is optional; the download button still works and reports its own errors */
      }
    }
  }

  form?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const password = input?.value ?? "";
    if (!password) {
      showNotice(region, "danger", "Enter the password to open this paste.");
      input?.focus();
      return;
    }
    setBusy(form, true);
    try {
      if (!(await load())) return;
      const { text, files } = parseEnvelope(await open(password, state.container));
      state.password = password;
      state.names = files;
      fillLines(target, text);
      target.hidden = false;
      showCopyText(view);
      form.hidden = true;
      if (cipher) cipher.hidden = true;
      if (state.grant) {
        showNotice(
          region,
          "warning",
          "That was the last read, so this paste is gone. Its files stay available on this page for ten minutes.",
        );
        view.querySelector("form.bv-delete")?.setAttribute("hidden", "");
      } else {
        showNotice(region, "success", "Opened in your browser.");
        // Whoever opened the paste may delete it, with the password already typed.
        if (remove) remove.hidden = false;
      }
      labelFiles();
      preview();
    } catch (err) {
      // After a burning read the paste is gone on the server; only this page still holds it.
      const retry = state.grant && err?.name === "WrongPassword" ? " Do not reload this page; try the password again." : "";
      showNotice(region, "danger", failureMessage(err) + retry);
      input?.select();
    } finally {
      setBusy(form, false);
    }
  });

  view.addEventListener("click", async (e) => {
    const link = e.target.closest?.("a[download][data-position]");
    if (!link) return;
    e.preventDefault();
    if (!state.password) {
      showNotice(region, "danger", "Open the paste with its password first, then download its files.");
      input?.focus();
      return;
    }
    const position = Number(link.dataset.position);
    try {
      link.setAttribute("aria-busy", "true");
      save(await openFile(position), state.names[position - 1] || `file-${position}`);
    } catch (err) {
      const known = ["WrongPassword", "UnsupportedFormat", "Refused"].includes(err?.name);
      showNotice(region, "danger", known ? err.message : "This file could not be downloaded. Try again.");
    } finally {
      link.removeAttribute("aria-busy");
    }
  });

  remove?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const password = state.password;
    if (!password) return;
    setBusy(remove, true);
    try {
      const proof = toHex(await verifier(password, fromHex(remove.dataset.verifierSalt)));
      const res = await fetch(remove.action, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ verifier: proof }),
      });
      if (!res.ok) {
        showNotice(region, "danger", await serverMessage(res, "This paste could not be deleted. Try again."));
        return;
      }
      window.location.assign(res.url);
    } catch {
      showNotice(region, "danger", "This paste could not be deleted. Try again.");
    } finally {
      setBusy(remove, false);
    }
  });

  // The ciphertext is shown at once, unless reading it could burn the paste: then it waits for
  // the reader to ask for the paste.
  if (!view.hasAttribute("data-burns")) load().catch(() => {});
}

if (typeof document !== "undefined") {
  const view = document.querySelector(".paste-view[data-secret]");
  if (view) bind(view);
}
