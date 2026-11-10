// The create form: shows the password field the chosen privacy needs, accepts dropped files,
// and for a secret paste encrypts the text and every file in the browser before posting.
import { seal, toHex, verifier } from "./crypto.js";
import { serverMessage, showNotice } from "./notice.js";

const MIB = 1024 * 1024;

// The content container's plaintext: the text and the real file names, in upload order.
export function buildEnvelope(text, files) {
  return JSON.stringify({ text, files: Array.from(files, (f) => (typeof f === "string" ? f : f.name)) });
}

export function tooLarge(files, maxMb) {
  return Array.from(files).some((f) => f.size > maxMb * MIB);
}

// Where a created paste opens: the server's HX-Redirect, accepted only as a path on this origin.
// Browsers read "/\host" like "//host", so a backslash after the slash is refused too.
export function createdLocation(headers) {
  const to = headers.get("hx-redirect") ?? "";
  return /^\/(?![/\\])/.test(to) ? to : null;
}

function bindPrivacy(form) {
  const select = form.querySelector("#privacy");
  if (!select) return;
  const sync = () => {
    form.dataset.privacy = select.value;
  };
  select.addEventListener("change", sync);
  sync();
}

function bindDropZone(form) {
  const input = form.querySelector("#files");
  const zone = input?.closest(".bv-files");
  if (!zone) return;
  zone.classList.add("bv-drop");
  const hint = document.createElement("p");
  hint.className = "bv-drop__hint";
  hint.textContent = "Or drop files here.";
  zone.append(hint);
  let depth = 0;
  const hasFiles = (e) => Array.from(e.dataTransfer?.types ?? []).includes("Files");
  zone.addEventListener("dragenter", (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    depth++;
    zone.dataset.dragging = "";
  });
  zone.addEventListener("dragover", (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = "copy";
  });
  zone.addEventListener("dragleave", () => {
    depth = Math.max(0, depth - 1);
    if (depth === 0) delete zone.dataset.dragging;
  });
  zone.addEventListener("drop", (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    depth = 0;
    delete zone.dataset.dragging;
    // The input keeps its earlier choice and gains the dropped files.
    const all = new DataTransfer();
    for (const f of [...input.files, ...e.dataTransfer.files]) all.items.add(f);
    input.files = all.files;
    input.dispatchEvent(new Event("change", { bubbles: true }));
  });
}

function setBusy(form, busy) {
  const button = form.querySelector("button[type=submit]");
  if (!button) return;
  button.disabled = busy;
  if (busy) button.setAttribute("aria-busy", "true");
  else button.removeAttribute("aria-busy");
}

// Builds the request by hand, so neither the password nor the plaintext can ever be in it.
// Field order is a contract with the server: every text field and the content come before any file.
async function secretBody(form, password, files) {
  const text = form.querySelector("#content")?.value ?? "";
  const content = await seal(password, new TextEncoder().encode(buildEnvelope(text, files)));
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(16));
  const proof = await verifier(password, salt);
  const sealed = [];
  for (const f of files) sealed.push(await seal(password, new Uint8Array(await f.arrayBuffer())));

  const body = new FormData();
  body.append("privacy", "secret");
  for (const name of ["expiry", "burn_after_reads", "uploader_password"]) {
    const field = form.elements.namedItem(name);
    if (field && "value" in field) body.append(name, field.value);
  }
  body.append("content_container", new Blob([content], { type: "application/octet-stream" }), "content");
  body.append("verifier_salt", toHex(salt));
  body.append("verifier", toHex(proof));
  for (const s of sealed) body.append("file", new Blob([s], { type: "application/octet-stream" }), "");
  return body;
}

function bindSecretSubmit(form) {
  const region = form.querySelector("#create-notice");
  const privacySelect = form.querySelector("#privacy");
  const passwordInput = form.querySelector("#secret-password");
  const fileInput = form.querySelector("#files");
  const maxMb = Number(form.dataset.maxSecretMb) || 256;
  let running = false;
  form.addEventListener("submit", async (e) => {
    // The live select decides, not the mirrored attribute, which could lag behind it.
    if (privacySelect?.value !== "secret") return;
    e.preventDefault();
    if (running) return;
    const password = passwordInput?.value ?? "";
    if (!password) {
      showNotice(region, "danger", "Enter a password for the secret paste.");
      passwordInput?.focus();
      return;
    }
    const files = Array.from(fileInput?.files ?? []);
    if (tooLarge(files, maxMb)) {
      showNotice(region, "danger", `Secret files can be at most ${maxMb} MB.`);
      return;
    }
    running = true;
    setBusy(form, true);
    showNotice(region, "info", "Encrypting in your browser…");
    try {
      const body = await secretBody(form, password, files);
      // The header makes the server answer an error with its notice fragment, and a success with
      // HX-Redirect rather than a 303: fetch would follow that itself and use up the creator cookie.
      const res = await fetch("/", { method: "POST", body, headers: { "HX-Request": "true" } });
      if (res.ok) {
        // The button stays busy until the paste page replaces this one.
        window.location.assign(createdLocation(res.headers) ?? res.url);
        return;
      }
      showNotice(region, "danger", await serverMessage(res, "The paste could not be created. Try again."));
    } catch {
      showNotice(region, "danger", "The paste could not be encrypted or sent. Try again.");
    }
    running = false;
    setBusy(form, false);
  });
}

if (typeof document !== "undefined") {
  const form = document.getElementById("create-form");
  if (form) {
    // The page ships Secret disabled, so a browser without this script cannot post plaintext as secret.
    form.querySelector('#privacy option[value="secret"]')?.removeAttribute("disabled");
    bindPrivacy(form);
    bindDropZone(form);
    bindSecretSubmit(form);
  }
}
