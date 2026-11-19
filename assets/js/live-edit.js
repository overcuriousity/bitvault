// The edit page as a live editor: the textarea follows the paste's session over the stream and
// sends each change as an operation. Without scripts, without EventSource, or when the first
// connect fails, the form stays the plain form that saves on submit.
import { LiveClient } from "./live-client.js";
import { showNotice } from "./notice.js";
import {
  backoff,
  downStatus,
  keepsAbove,
  lineStart,
  mapSelection,
  presence,
  rebase,
  rejoinLabel,
  streamUrl,
  syntaxValue,
} from "./live-edit-core.js";
import { cpLength, unitToCp } from "./ot.js";

const CARET_MS = 250;
// A POST that has not settled by then is given up and counts as a network error.
const POST_MS = 15000;
const EMPTY = "An empty paste is not saved.";
// How often a syntax change is sent again before the select goes back.
const SYNTAX_TRIES = 5;
const SYNTAX_REFUSED = "The syntax could not be changed.";
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
  // The stream's reconnects and the edit POST's retries back off on their own counts.
  let streamAttempt = 0;
  let postAttempt = 0;
  let reconnectTimer = 0;
  // Whether the stream is down and being reconnected, and how the last probe was answered.
  let down = false;
  let lastCode = 0;
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
  // The session's syntax as the stream last told it, which a refused change falls back to.
  let syntaxNow = null;
  let syntaxTimer = 0;
  // Counts syntax choices, so the answer to an older one is ignored.
  let syntaxChoice = 0;

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
    const abort = new AbortController();
    const timer = setTimeout(() => abort.abort(), POST_MS);
    return fetch(live, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Live-Client": clientId },
      body: JSON.stringify(body),
      credentials: "same-origin",
      cache: "no-store",
      signal: abort.signal,
    }).finally(() => clearTimeout(timer));
  }

  // How the stream would answer now, 0 when the server is out of reach.
  async function probe() {
    const url = streamUrl({ live, grant: grantInput?.value, client: clientId, last: client.rev });
    try {
      return (await fetch(url, { method: "HEAD", credentials: "same-origin", cache: "no-store" })).status;
    } catch {
      return 0;
    }
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
    caretSent = caretCp();
    // The caret in the text this edit makes, not in the textarea, which may hold typing since.
    const pos = client.sentPos(caretSent);
    let res = null;
    try {
      res = await request({ ...sent, pos });
    } catch {
      /* a network error or a timeout is retried below; the server ignores a seq it applied */
    }
    posting = false;
    if (mode !== "live") return;
    const code = res?.status ?? 0;
    if (code === 204) {
      if (pending === sent) pending = null;
      postAttempt = 0;
      pump();
    } else if (code === 0 || code === 429 || code === 503) {
      postTimer = setTimeout(() => {
        postTimer = 0;
        pump();
      }, backoff(postAttempt++));
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
    request({ pos: client.serverPos(pos) }).catch(() => {});
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
    syntaxNow = syntax;
    if (!select) return;
    const value = syntaxValue.show(syntax);
    const option = [...select.options].find((o) => o.value === value);
    if (!option || select.value === value) return;
    select.value = value;
    // The kit's listbox shows the chosen option on its button and rereads the rest when opened.
    const button = select.nextElementSibling?.querySelector(".oc-menu-button");
    if (button) button.textContent = option.textContent;
  }

  // The stream is up again: the status says Live.
  function up() {
    down = false;
    lastCode = 0;
    streamAttempt = 0;
    setStatus("Live", "success");
  }

  function onInit(d) {
    resuming = false;
    pending = null;
    postAttempt = 0;
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
    up();
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
        up();
        // The edit in flight goes again at once, not after a backoff begun while the stream was
        // down; a POST still out is given up after POST_MS and then sends what is pending.
        clearTimeout(postTimer);
        postTimer = 0;
        client.retry();
        pump();
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
      if (mode === "connecting") {
        plain();
        crowdedAtFirst();
      } else if (mode === "live") later();
    });
  }

  function close() {
    es?.close();
    es = null;
  }

  function showDown() {
    setStatus(downStatus({ online: navigator.onLine, code: lastCode }), "warning");
  }

  function reconnect() {
    close();
    down = true;
    showDown();
    connect();
  }

  // After the stream dropped: asks how the stream would answer, then waits or gives up. A 429
  // (too many streams from this address) keeps trying, and says so.
  function later() {
    down = true;
    showDown();
    clearTimeout(reconnectTimer);
    reconnectTimer = setTimeout(async () => {
      reconnectTimer = 0;
      const code = await probe();
      // A stream opened while the probe was out (a POST's 403) already answers for itself.
      if (mode !== "live" || es) return;
      lastCode = code;
      if (code === 200) connect();
      else if (code === 403) end(grantInput ? "unlock" : "stale");
      else if (code === 404) end("gone");
      else later();
    }, backoff(streamAttempt++));
  }

  // The first connect failed and the form is plain again; when the address has too many streams
  // open, the status line says so above the form.
  async function crowdedAtFirst() {
    const code = await probe();
    if (mode !== "plain" || code !== 429) return;
    setStatus(downStatus({ online: true, code }), "warning");
    bar.hidden = false;
  }

  // Leaves the live state for good: the text stays in the textarea, read-only and copyable.
  function end(why) {
    if (mode === "ended") return;
    // Text the session does not have yet, which a rejoin's reload would drop.
    const unsent = mode === "connecting" ? ta.value !== ta.defaultValue : client.unsent || ta.value !== client.text;
    mode = "ended";
    close();
    clearTimeout(reconnectTimer);
    clearTimeout(postTimer);
    clearTimeout(caretTimer);
    clearTimeout(syntaxTimer);
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
    const rejoin = document.getElementById("live-rejoin");
    rejoin.textContent = rejoinLabel(unsent);
    rejoin.hidden = why === "gone" || why === "unlock";
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
  // Sends the syntax the select shows; a network error, 429 or 503 is retried, and any other
  // answer, or too many retries, puts the select back to the session's syntax.
  async function sendSyntax(choice, attempt) {
    syntaxTimer = 0;
    if (mode !== "live" || !select || choice !== syntaxChoice) return;
    const syntax = syntaxValue.send(select.value);
    let code = 0;
    try {
      code = (await request({ syntax })).status;
    } catch {
      /* retried below */
    }
    // Another choice was made meanwhile; its own send answers for it.
    if (mode !== "live" || choice !== syntaxChoice) return;
    if (code === 204) return;
    if ((code === 0 || code === 429 || code === 503) && attempt < SYNTAX_TRIES) {
      syntaxTimer = setTimeout(() => sendSyntax(choice, attempt + 1), backoff(attempt));
      return;
    }
    showSyntax(syntaxNow);
    const region = document.getElementById("oc-live");
    if (region) region.textContent = SYNTAX_REFUSED;
  }

  select?.addEventListener("change", () => {
    clearTimeout(syntaxTimer);
    syntaxChoice += 1;
    sendSyntax(syntaxChoice, 0);
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
    if (mode !== "live" || !client.unsent) return;
    e.preventDefault();
    // Older browsers ask only when this is set.
    e.returnValue = "";
  });
  window.addEventListener("offline", () => {
    if (mode === "live" && down) showDown();
  });
  window.addEventListener("online", () => {
    if (mode !== "live" || !down) return;
    // Back online: the next probe goes now instead of after the backoff reached while offline.
    if (reconnectTimer) {
      streamAttempt = 0;
      later();
    } else showDown();
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
