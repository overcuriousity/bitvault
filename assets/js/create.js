// The create form: shows the password field the chosen privacy needs, accepts dropped and pasted
// files, checks sizes before anything is sent, and posts with upload progress. A secret paste's
// text and files are encrypted in the browser first. When the box holds the words of a paste that
// exists, box.js says so and the submit opens that paste instead.
import { bindBox } from "./box.js";
import { seal, toHex, verifier } from "./crypto.js";
import { serverMessage, showNotice } from "./notice.js";

const MIB = 1024 * 1024;
// Feedback timing from the manifest: a spinner after 400 ms, progress beyond 1 s.
const SPINNER_MS = 400;
const PROGRESS_MS = 1000;

// The content container's plaintext: the text and the real file names, in upload order.
export function buildEnvelope(text, files) {
  return JSON.stringify({ text, files: Array.from(files, (f) => (typeof f === "string" ? f : f.name)) });
}

export function tooLarge(files, maxMb) {
  return Array.from(files).some((f) => f.size > maxMb * MIB);
}

// The notice for files the server would refuse, or null. Secret pastes also limit each file.
export function sizeProblem(files, privacy, maxFileMb, maxSecretMb) {
  const list = Array.from(files);
  if (privacy === "secret" && tooLarge(list, maxSecretMb)) return `Secret files can be at most ${maxSecretMb} MB.`;
  const total = list.reduce((sum, f) => sum + f.size, 0);
  if (total > maxFileMb * MIB) return `Files can be at most ${maxFileMb} MB together.`;
  return null;
}

export function progressText(loaded, total) {
  const percent = total > 0 ? Math.min(100, Math.max(0, Math.floor((loaded * 100) / total))) : 0;
  return `Uploading… ${percent}%`;
}

// Where a created paste opens: the server's HX-Redirect, accepted only as a path on this origin.
// Browsers read "/\host" like "//host" and drop tabs and newlines from URLs, so those are refused too.
export function createdLocation(headers, origin = globalThis.location?.origin) {
  const to = headers.get("hx-redirect") ?? "";
  if (!origin || !/^\/(?![/\\])/.test(to) || /[\t\r\n]/.test(to)) return null;
  try {
    return new URL(to, origin).origin === origin ? to : null;
  } catch {
    return null;
  }
}

// The files a paste event carries. Pasting text into a text field stays a text paste, even when
// the clipboard also holds a picture of it (as office apps put there).
export function pastedFiles(data, intoText) {
  if (!data) return [];
  if (intoText && Array.from(data.types ?? []).includes("text/plain")) return [];
  const files = [];
  for (const item of Array.from(data.items ?? [])) {
    if (item.kind !== "file") continue;
    const file = item.getAsFile();
    if (file) files.push(file);
  }
  return files;
}

// The existing files plus the added ones, without adding the same file twice.
export function mergeFiles(existing, added) {
  const key = (f) => `${f.name}\u0000${f.size}\u0000${f.type}`;
  const seen = new Set(Array.from(existing, key));
  const out = Array.from(existing);
  for (const f of added) {
    if (seen.has(key(f))) continue;
    seen.add(key(f));
    out.push(f);
  }
  return out;
}

function addFiles(input, files) {
  const all = new DataTransfer();
  for (const f of mergeFiles(input.files, files)) all.items.add(f);
  input.files = all.files;
  input.dispatchEvent(new Event("change", { bubbles: true }));
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

// The kit's desktop listbox lists options flat; this adds the select's group labels to it.
function labelGroups(select) {
  const list = select?.nextElementSibling?.querySelector('[role="listbox"]');
  if (!list) return;
  const items = list.querySelectorAll('[role="option"]');
  let index = 0;
  for (const group of select.querySelectorAll("optgroup")) {
    const first = items[index];
    index += group.querySelectorAll("option").length;
    if (!first) continue;
    const label = document.createElement("li");
    label.setAttribute("role", "presentation");
    label.className = "bv-menu-group";
    label.textContent = group.label;
    first.before(label);
  }
}

// The whole form takes dropped files; the closed "Attach files" opens once there are any.
function bindDropZone(form) {
  const input = form.querySelector("#files");
  if (!input) return;
  const attach = form.querySelector("#attach");
  const summary = attach?.querySelector("summary");
  if (summary) {
    const hint = document.createElement("span");
    hint.className = "bv-attach__hint";
    hint.textContent = "or drop or paste them here";
    summary.append(" ", hint);
  }
  input.addEventListener("change", () => {
    if (attach && input.files.length > 0) attach.open = true;
  });
  const zone = form;
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
    addFiles(input, e.dataTransfer.files);
  });
}

function bindPaste(form) {
  const input = form.querySelector("#files");
  if (!input) return;
  document.addEventListener("paste", (e) => {
    const t = e.target;
    const intoText =
      t instanceof HTMLTextAreaElement || (t instanceof HTMLInputElement && t.type !== "file") || t?.isContentEditable;
    const files = pastedFiles(e.clipboardData, Boolean(intoText));
    if (files.length === 0) return;
    e.preventDefault();
    addFiles(input, files);
  });
}

function limits(form) {
  return [Number(form.dataset.maxFileMb) || 2048, Number(form.dataset.maxSecretMb) || 256];
}

function bindSizeCheck(form) {
  const region = form.querySelector("#create-notice");
  const input = form.querySelector("#files");
  const select = form.querySelector("#privacy");
  if (!input) return;
  let shown = false;
  const check = () => {
    const problem = sizeProblem(input.files, select?.value, ...limits(form));
    if (problem) showNotice(region, "danger", problem);
    else if (shown) showNotice(region, "", "");
    shown = Boolean(problem);
  };
  input.addEventListener("change", check);
  select?.addEventListener("change", check);
}

// The primary button while a create runs: disabled at once, a spinner after 400 ms, and from
// 1 s on the upload percentage.
function busyButton(button) {
  const content = Array.from(button.childNodes);
  let uploaded = null;
  let reveal = false;
  const render = () => {
    if (!reveal || !uploaded) return;
    button.dataset.progress = "";
    button.setAttribute("aria-busy", "true");
    button.textContent = progressText(...uploaded);
  };
  button.disabled = true;
  const spinner = setTimeout(() => button.setAttribute("aria-busy", "true"), SPINNER_MS);
  const progress = setTimeout(() => {
    reveal = true;
    render();
  }, PROGRESS_MS);
  return {
    progress(loaded, total) {
      uploaded = [loaded, total];
      render();
    },
    reset() {
      clearTimeout(spinner);
      clearTimeout(progress);
      button.disabled = false;
      button.removeAttribute("aria-busy");
      delete button.dataset.progress;
      button.replaceChildren(...content);
    },
  };
}

// XMLHttpRequest rather than fetch, which reports no upload progress. The HX-Request header makes
// the server answer an error with its notice fragment, and a success with HX-Redirect rather than
// a 303 that would be followed here and use up the creator cookie.
function send(body, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/");
    xhr.setRequestHeader("HX-Request", "true");
    xhr.upload.addEventListener("progress", (e) => {
      if (e.lengthComputable) onProgress(e.loaded, e.total);
    });
    xhr.addEventListener("load", () => resolve(xhr));
    xhr.addEventListener("error", () => reject(new Error("network error")));
    xhr.addEventListener("abort", () => reject(new Error("aborted")));
    onProgress(0, 1);
    xhr.send(body);
  });
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

function bindSubmit(form, box) {
  const region = form.querySelector("#create-notice");
  const privacySelect = form.querySelector("#privacy");
  const passwordInput = form.querySelector("#secret-password");
  const fileInput = form.querySelector("#files");
  const button = form.querySelector("button[type=submit]");
  let running = false;
  let busy = null;
  const fail = (message) => showNotice(region, "danger", message);
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (running || !button) return;
    running = true;
    const decision = await box.decide(e.submitter).catch(() => ({}));
    if (decision.open) {
      window.location.assign(decision.open);
      return;
    }
    running = false;
    // The live select decides, not the mirrored attribute, which could lag behind it.
    const secret = privacySelect?.value === "secret";
    const files = Array.from(fileInput?.files ?? []);
    const password = passwordInput?.value ?? "";
    if (secret && !password) {
      fail("Enter a password for the secret paste.");
      passwordInput?.focus();
      return;
    }
    const problem = sizeProblem(files, privacySelect?.value, ...limits(form));
    if (problem) {
      showNotice(region, "danger", problem);
      return;
    }
    running = true;
    busy = busyButton(e.submitter ?? button);
    try {
      let body;
      if (secret) {
        showNotice(region, "info", "Encrypting in your browser…");
        body = await secretBody(form, password, files);
      } else {
        // In DOM order, so the options come before the files as the server requires.
        body = new FormData(form);
        if (decision.intent) body.append("intent", decision.intent);
      }
      const xhr = await send(body, busy.progress);
      if (xhr.status >= 200 && xhr.status < 300) {
        // The button stays busy until the paste page replaces this one.
        const headers = { get: (name) => xhr.getResponseHeader(name) };
        window.location.assign(createdLocation(headers) ?? xhr.responseURL);
        return;
      }
      const res = { text: async () => xhr.responseText, headers: { get: (name) => xhr.getResponseHeader(name) } };
      fail(await serverMessage(res, "The paste could not be created. Try again."));
    } catch {
      fail(secret ? "The paste could not be encrypted or sent. Try again." : "The paste could not be sent. Try again.");
    }
    running = false;
    busy.reset();
  });
  // A page restored from the back-forward cache keeps the busy button of the create that left it,
  // or the pending submit of a paste it opened.
  window.addEventListener("pageshow", (event) => {
    if (!event.persisted) return;
    running = false;
    if (!busy) return;
    busy.reset();
    busy = null;
    showNotice(region, "", "");
  });
}

if (typeof document !== "undefined") {
  const form = document.getElementById("create-form");
  if (form) {
    // The page ships Secret disabled, so a browser without this script cannot post plaintext as secret.
    form.querySelector('#privacy option[value="secret"]')?.removeAttribute("disabled");
    bindPrivacy(form);
    labelGroups(form.querySelector("#privacy"));
    bindDropZone(form);
    bindPaste(form);
    bindSizeCheck(form);
    bindSubmit(form, bindBox(form));
  }
}
