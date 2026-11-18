// The edit page as a live editor: the textarea follows the paste's session over the stream and
// sends each change as an operation. Without scripts, without EventSource, or when the first
// connect fails, the form stays the plain form that saves on submit.
import { LiveClient } from "./live-client.js";
import { showNotice } from "./notice.js";
import { backoff, keepsAbove, lineStart, mapSelection, presence, rebase, streamUrl, syntaxValue } from "./live-edit-core.js";
import { cpLength, unitToCp } from "./ot.js";

const CARET_MS = 250;
const EMPTY = "An empty paste is not saved.";
const OUT = {
  stale: "You were disconnected for too long",
  refused: "Your last change was refused.",
  full: "The paste is full",
  gone: "This paste was deleted.",
  crowded: "Too many people are editing this paste.",
};

function icon(kind) {
  const svg = document.getElementById("bv-notice-icons")?.content.querySelector(`[data-kind="${kind}"] > svg`);
  return svg ? svg.cloneNode(true) : null;
}

function start(form) {
  const live = form.dataset.bvLive;
  const ta = form.querySelector("textarea");
  const select = form.querySelector("select[name=syntax]");
  const grantInput = form.querySelector("input[name=g]");
  const save = form.querySelector("button[type=submit]");
  const back = form.querySelector(".oc-form__actions a");
  const bar = document.getElementById("live-bar");
  const status = document.getElementById("live-status");
  const count = document.getElementById("live-count");
  const chips = document.getElementById("live-chips");
  const empty = document.getElementById("live-empty");
  const out = document.getElementById("live-out");
  const backLabel = back.textContent;

  // "connecting" until the first init, then "live"; "plain" gives the form back, "ended" is read-only.
  let mode = "connecting";
  let es = null;
  let clientId = null;
  let me = 0;
  let resuming = false;
  let attempt = 0;
  let reconnectTimer = 0;
  let composing = false;
  let held = [];
  let leaving = false;
  // The edit message LiveClient last asked to send, until the server accepts it.
  let pending = null;
  let posting = false;
  let postTimer = 0;
  let caretTimer = 0;
  let caretAt = 0;
  let caretSent = -1;

  const client = new LiveClient({ send: (msg) => queue(msg), onChange: (text, map) => show(text, map) });

  function setStatus(text, kind) {
    status.className = `oc-status bv-live__status${kind ? ` oc-status--${kind}` : ""}`;
    const symbol = icon(kind ?? "info");
    status.replaceChildren(...(symbol ? [symbol] : []), text);
  }

  function caretCp() {
    const unit = ta.selectionDirection === "backward" ? ta.selectionStart : ta.selectionEnd;
    return unitToCp(ta.value, unit);
  }

  function noteEmpty() {
    if (empty) empty.textContent = client.text === "" ? EMPTY : "";
  }

  // The textarea takes `text`, the selection and the scroll position carried through `map`.
  function show(text, map) {
    const old = ta.value;
    const { selectionStart, selectionEnd, selectionDirection, scrollTop, scrollHeight } = ta;
    let range = [selectionStart, selectionEnd];
    let above = true;
    try {
      range = mapSelection(old, text, selectionStart, selectionEnd, map);
      const lineHeight = parseFloat(getComputedStyle(ta).lineHeight) || 20;
      above = keepsAbove(old, text, lineStart(old, Math.floor(scrollTop / lineHeight)), map);
    } catch {
      /* the textarea had drifted from the text; the caret keeps its offset */
    }
    ta.value = text;
    ta.setSelectionRange(range[0], range[1], selectionDirection);
    ta.scrollTop = above ? scrollTop : scrollTop + ta.scrollHeight - scrollHeight;
    noteEmpty();
  }

  function request(body) {
    return fetch(live, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Live-Client": clientId },
      body: JSON.stringify(body),
      credentials: "same-origin",
      cache: "no-store",
    });
  }

  function queue(msg) {
    pending = msg;
    pump();
  }

  // Sends `pending`, one edit POST at a time; a retry sends whatever is pending by then.
  async function pump() {
    if (posting || pending === null || mode !== "live" || postTimer) return;
    posting = true;
    const sent = pending;
    const pos = caretCp();
    caretSent = pos;
    let res = null;
    try {
      res = await request({ ...sent, pos });
    } catch {
      /* a network error is retried below */
    }
    posting = false;
    if (mode !== "live") return;
    const code = res?.status ?? 0;
    if (code === 204) {
      if (pending === sent) pending = null;
      attempt = 0;
      pump();
    } else if (code === 0 || code === 429 || code === 503) {
      postTimer = setTimeout(() => {
        postTimer = 0;
        pump();
      }, backoff(attempt++));
    } else if (code === 403) {
      pending = null;
      reconnect();
    } else if (code === 404) {
      end("gone");
    } else {
      end(code === 413 ? "full" : "refused");
    }
  }

  function sendCaret() {
    caretTimer = 0;
    if (mode !== "live" || composing) return;
    const pos = caretCp();
    if (pos === caretSent) return;
    caretSent = pos;
    caretAt = Date.now();
    request({ pos }).catch(() => {});
  }

  function caretMoved() {
    if (caretTimer || mode !== "live") return;
    caretTimer = setTimeout(sendCaret, Math.max(0, caretAt + CARET_MS - Date.now()));
  }

  function typed() {
    if (mode !== "live" || composing) return;
    client.local(ta.value);
    if (ta.value !== client.text) show(client.text, (pos) => Math.min(pos, cpLength(client.text)));
    noteEmpty();
    caretMoved();
  }

  function showPeers(peers) {
    const { label, chips: lines } = presence(peers, me, client.text);
    count.textContent = label;
    chips.replaceChildren(
      ...lines.map((line) => {
        const chip = document.createElement("span");
        chip.className = "bv-peer";
        chip.textContent = line;
        return chip;
      }),
    );
  }

  function showSyntax(syntax) {
    if (!select) return;
    const value = syntaxValue.show(syntax);
    const option = [...select.options].find((o) => o.value === value);
    if (!option || select.value === value) return;
    select.value = value;
    // The kit's listbox shows the chosen option on its button and rereads the rest when opened.
    const button = select.nextElementSibling?.querySelector(".oc-menu-button");
    if (button) button.textContent = option.textContent;
  }

  function onInit(d) {
    resuming = false;
    attempt = 0;
    pending = null;
    if (mode === "live" && client.unsent) return end("stale");
    clientId = d.client;
    me = d.peer;
    const text = mode === "connecting" ? rebase(ta.defaultValue, ta.value, d.text) : d.text;
    client.init({ rev: d.rev, text: d.text, peer: d.peer });
    mode = "live";
    client.local(text);
    if (ta.value !== client.text) show(client.text, (pos) => Math.min(pos, cpLength(client.text)));
    noteEmpty();
    showSyntax(d.syntax);
    showPeers(d.peers);
    setStatus("Live", "success");
  }

  function onEvent(name, data) {
    if (mode === "ended") return;
    if (name === "init") return onInit(data);
    if (name === "gone") return end("gone");
    if (name === "full") return end("crowded");
    if (mode !== "live") return;
    if (name === "op") {
      if (data.rev <= client.rev) return;
      if (data.rev !== client.rev + 1) return reconnect();
      client.remote(data);
      if (leaving && !client.unsent) window.location.assign(back.href);
    } else if (name === "peers") {
      showPeers(data);
      if (resuming) {
        resuming = false;
        attempt = 0;
        client.retry();
        setStatus("Live", "success");
      }
    } else if (name === "syntax") {
      showSyntax(data.syntax);
    }
  }

  function receive(source, name, raw) {
    if (source !== es) return;
    const data = JSON.parse(raw);
    if (name === "grant") {
      if (grantInput) grantInput.value = data.g;
    } else if (composing) {
      held.push([name, data]);
    } else {
      onEvent(name, data);
    }
  }

  // At most one stream is open: every new one closes the one before.
  function connect() {
    close();
    clearTimeout(reconnectTimer);
    const source = new EventSource(
      streamUrl({ live, grant: grantInput?.value, client: clientId, last: client.rev }),
    );
    es = source;
    resuming = clientId !== null;
    for (const name of ["init", "op", "peers", "syntax", "gone", "full", "grant"]) {
      source.addEventListener(name, (e) => receive(source, name, e.data));
    }
    source.addEventListener("error", () => {
      // A replaced stream would go on reconnecting by itself with its old address.
      if (source !== es) return source.close();
      close();
      if (mode === "connecting") plain();
      else if (mode === "live") later();
    });
  }

  function close() {
    es?.close();
    es = null;
  }

  function reconnect() {
    close();
    setStatus("Reconnecting", "warning");
    connect();
  }

  // After the stream dropped: asks how the stream would answer, then waits or gives up.
  function later() {
    setStatus("Reconnecting", "warning");
    clearTimeout(reconnectTimer);
    reconnectTimer = setTimeout(async () => {
      const url = streamUrl({ live, grant: grantInput?.value, client: clientId, last: client.rev });
      let code = 0;
      try {
        code = (await fetch(url, { method: "HEAD", credentials: "same-origin", cache: "no-store" })).status;
      } catch {
        /* the server is out of reach; try again */
      }
      // A stream opened while the probe was out (a POST's 403) already answers for itself.
      if (mode !== "live" || es) return;
      if (code === 200) connect();
      else if (code === 403) end(grantInput ? "unlock" : "stale");
      else if (code === 404) end("gone");
      else later();
    }, backoff(attempt++));
  }

  // Leaves the live state for good: the text stays in the textarea, read-only and copyable.
  function end(why) {
    if (mode === "ended") return;
    mode = "ended";
    close();
    clearTimeout(reconnectTimer);
    clearTimeout(postTimer);
    clearTimeout(caretTimer);
    leaving = false;
    ta.readOnly = true;
    if (select) select.disabled = true;
    status.replaceChildren();
    count.textContent = "";
    chips.replaceChildren();
    if (empty) empty.textContent = "";
    const region = document.getElementById("live-out-notice");
    const unlock = document.getElementById("live-unlock");
    showNotice(region, "warning", OUT[why] ?? " ");
    if (why === "unlock") region.querySelector(".oc-notice__text")?.replaceChildren(unlock);
    unlock.hidden = why !== "unlock";
    document.getElementById("live-rejoin").hidden = why === "gone" || why === "unlock";
    out.hidden = false;
    out.focus();
  }

  // The first connect failed: the page is the plain form again.
  function plain() {
    mode = "plain";
    bar.hidden = true;
    save.hidden = false;
    back.textContent = backLabel;
  }

  async function copyMine() {
    const announce = (text) => {
      const region = document.getElementById("oc-live");
      if (region) region.textContent = text;
    };
    try {
      await navigator.clipboard.writeText(ta.value);
      announce("Copied");
    } catch {
      ta.focus();
      ta.select();
      announce(document.execCommand("copy") ? "Copied" : "Could not copy. Select the text instead.");
    }
  }

  function historyStep(redo) {
    if (mode !== "live" || composing) return false;
    if (redo) client.redo();
    else client.undo();
    caretMoved();
    return true;
  }

  ta.addEventListener("input", typed);
  ta.addEventListener("compositionstart", () => {
    composing = true;
  });
  ta.addEventListener("compositionend", () => {
    composing = false;
    typed();
    const waiting = held;
    held = [];
    for (const [name, data] of waiting) onEvent(name, data);
  });
  ta.addEventListener("beforeinput", (e) => {
    if (e.inputType !== "historyUndo" && e.inputType !== "historyRedo") return;
    if (historyStep(e.inputType === "historyRedo")) e.preventDefault();
  });
  ta.addEventListener("keydown", (e) => {
    const key = e.key.toLowerCase();
    const mod = e.ctrlKey || e.metaKey;
    const undo = mod && !e.shiftKey && !e.altKey && key === "z";
    const redo = (mod && e.shiftKey && !e.altKey && key === "z") || (e.ctrlKey && !e.shiftKey && key === "y");
    if ((undo || redo) && historyStep(redo)) e.preventDefault();
  });
  document.addEventListener("selectionchange", () => {
    if (document.activeElement === ta) caretMoved();
  });
  for (const name of ["select", "keyup", "pointerup"]) ta.addEventListener(name, caretMoved);
  select?.addEventListener("change", () => {
    if (mode === "live") request({ syntax: syntaxValue.send(select.value) }).catch(() => {});
  });
  form.addEventListener("submit", (e) => {
    if (mode !== "plain") e.preventDefault();
  });
  // An edit not yet applied would be lost by leaving now; Done waits for it.
  back.addEventListener("click", (e) => {
    if (mode !== "live" || !client.unsent) return;
    e.preventDefault();
    leaving = true;
  });
  // Leaving any other way while an edit waits would drop it; the browser asks first.
  window.addEventListener("beforeunload", (e) => {
    if (mode === "live" && client.unsent) e.preventDefault();
  });
  document.getElementById("live-copy").addEventListener("click", copyMine);
  document.getElementById("live-rejoin").addEventListener("click", () => window.location.reload());

  save.hidden = true;
  back.textContent = "Done";
  bar.hidden = false;
  setStatus("Connecting");
  connect();
}

if (typeof document !== "undefined") {
  const form = document.querySelector("form[data-bv-live]");
  if (form && typeof EventSource === "function") start(form);
}
