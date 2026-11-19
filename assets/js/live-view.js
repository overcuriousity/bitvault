// A read view of a paste that is edited live: its Edit link becomes "Live edit" and shows how many
// are editing, and its text follows the stored text over the watch stream. Without scripts, or
// while the stream cannot be opened, the page stays the static page it was rendered as.
import { showNotice } from "./notice.js";

const RETRY_MS = 1000;
const RETRY_CAP_MS = 30000;
const SOMEONE = "Someone is editing this paste.";
const GONE = "This paste was deleted.";

// The Edit link's label while `editors` people edit the paste.
export function label(editors) {
  return editors > 0 ? `Live edit · ${editors} editing` : "Live edit";
}

// `href` with its `g` parameter set to `g`: replaced where it has one, added where not; the other
// parameters and the fragment stay as they are.
export function withGrant(href, g) {
  const hashAt = href.indexOf("#");
  const hash = hashAt === -1 ? "" : href.slice(hashAt);
  const rest = hashAt === -1 ? href : href.slice(0, hashAt);
  const queryAt = rest.indexOf("?");
  const path = queryAt === -1 ? rest : rest.slice(0, queryAt);
  const params = queryAt === -1 ? [] : rest.slice(queryAt + 1).split("&").filter(Boolean);
  const value = `g=${encodeURIComponent(g)}`;
  const at = params.findIndex((p) => p === "g" || p.startsWith("g="));
  if (at === -1) params.push(value);
  else params[at] = value;
  return `${path}?${params.join("&")}${hash}`;
}

// What a read view does with a `content` event's `html` when the page has (`hasText`) or lacks
// its text block: an empty text hides the block, any other shows it, building the block where
// the page has none. Never a reload: the page as loaded shows the stored row, which can differ
// from the session's text, so a reload would only bring the same event again.
export function contentStep(html, hasText) {
  if (!html) return hasText ? "hide" : "none";
  return hasText ? "show" : "create";
}

// How long to wait before the connect after `attempt` failed ones.
export function delay(attempt) {
  return Math.min(RETRY_MS * 2 ** attempt, RETRY_CAP_MS);
}

function start(article) {
  const watch = article.dataset.bvWatch;
  const link = article.querySelector("[data-bv-live-edit]");
  const says = document.getElementById("live-view-says");
  let grant = article.dataset.bvGrant ?? null;
  let es = null;
  let timer = 0;
  let attempt = 0;
  let stopped = false;
  let editors = 0;
  // The latest `content` not yet shown, held while the reader has text selected in it.
  let waiting = null;

  const address = () => (grant ? withGrant(watch, grant) : watch);

  function showEditors(n) {
    if (link) {
      link.replaceChildren(...[...link.querySelectorAll("svg")], label(n));
      link.toggleAttribute("data-live", n > 0);
    }
    if (says) {
      if (n > 0 && editors === 0) says.textContent = SOMEONE;
      else if (n === 0) says.textContent = "";
    }
    editors = n;
  }

  function selecting(pre) {
    const sel = document.getSelection();
    if (!sel || sel.isCollapsed) return false;
    for (let i = 0; i < sel.rangeCount; i += 1) {
      if (sel.getRangeAt(i).intersectsNode(pre)) return true;
    }
    return false;
  }

  // The text block where the page renders it, before the line of facts.
  function makeText() {
    const pre = document.createElement("pre");
    pre.className = "paste-text";
    pre.id = "paste-text";
    pre.append(document.createElement("code"));
    const meta = article.querySelector(".bv-meta");
    if (meta) meta.before(pre);
    else article.append(pre);
    return pre;
  }

  // Shows `waiting` unless the reader is selecting in the text. An empty text hides the block.
  function showContent() {
    if (!waiting) return;
    let pre = document.getElementById("paste-text");
    const step = contentStep(waiting.html, Boolean(pre?.querySelector("code")));
    if (step === "none") {
      waiting = null;
      return;
    }
    if (step === "create") pre = makeText();
    if (!pre.hidden && selecting(pre)) return;
    const { html, highlighted } = waiting;
    waiting = null;
    const code = pre.querySelector("code");
    const { scrollX, scrollY } = window;
    if (step === "hide") {
      code.replaceChildren();
      pre.classList.remove("bv-code");
      pre.hidden = true;
    } else {
      // The server's own escaped rendering of the text, parsed in an inert document and moved over.
      const doc = new DOMParser().parseFromString(`<pre><code>${html}</code></pre>`, "text/html");
      code.replaceChildren(...doc.querySelector("code").childNodes);
      pre.classList.toggle("bv-code", Boolean(highlighted));
      pre.hidden = false;
    }
    window.scrollTo(scrollX, scrollY);
  }

  function showGrant(g) {
    grant = g;
    article.dataset.bvGrant = g;
    // Only the page's own links: a URL paste's target may carry a `g` of its own.
    for (const a of article.querySelectorAll('a[href^="/"]:not([data-bv-target])')) {
      const href = a.getAttribute("href");
      if (/[?&]g=/.test(href)) a.setAttribute("href", withGrant(href, g));
    }
    for (const copy of article.querySelectorAll(".bv-files [data-oc-copy]")) {
      if (/[?&]g=/.test(copy.dataset.ocCopy)) copy.dataset.ocCopy = withGrant(copy.dataset.ocCopy, g);
    }
    for (const input of article.querySelectorAll("form input[name=g]")) input.value = g;
  }

  function gone() {
    stop();
    article.querySelector(".bv-delete")?.remove();
    if (says) says.textContent = GONE;
    const toolbar = article.querySelector(".bv-actions");
    if (!toolbar) return;
    const region = document.createElement("div");
    showNotice(region, "warning", GONE);
    toolbar.replaceWith(region);
  }

  function receive(source, name, raw) {
    if (source !== es) return;
    const data = JSON.parse(raw);
    if (name === "live") showEditors(data.editors);
    else if (name === "content") {
      waiting = data;
      showContent();
    } else if (name === "reload") window.location.reload();
    else if (name === "gone") gone();
    else if (name === "grant") showGrant(data.g);
  }

  function close() {
    es?.close();
    es = null;
    clearTimeout(timer);
    timer = 0;
  }

  // Closes the stream with no new one opened: nobody is shown editing until a stream says so.
  function pause() {
    close();
    showEditors(0);
  }

  function stop() {
    stopped = true;
    pause();
  }

  // At most one stream is open, and none while the tab is hidden.
  function connect() {
    close();
    if (stopped || document.hidden) return;
    const source = new EventSource(address());
    es = source;
    for (const name of ["live", "content", "reload", "gone", "grant"]) {
      source.addEventListener(name, (e) => receive(source, name, e.data));
    }
    source.addEventListener("open", () => {
      if (source === es) attempt = 0;
    });
    source.addEventListener("error", () => {
      // A replaced stream would go on reconnecting by itself with its old address.
      if (source !== es) return source.close();
      pause();
      later();
    });
  }

  // After a failed connect: asks how the stream would answer, then retries or stops for good. A
  // paste no longer live (404) or an unlock that expired (403) leaves the page static.
  function later() {
    timer = setTimeout(async () => {
      timer = 0;
      let code = 0;
      try {
        code = (await fetch(address(), { method: "HEAD", credentials: "same-origin", cache: "no-store" })).status;
      } catch {
        /* the server is out of reach; try again */
      }
      if (stopped || es || timer || document.hidden) return;
      if (code === 403 || code === 404) stop();
      else if (code === 200) connect();
      else later();
    }, delay(attempt++));
  }

  document.addEventListener("selectionchange", showContent);
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) pause();
    else if (!es && !timer) connect();
  });
  showEditors(0);
  connect();
}

if (typeof document !== "undefined") {
  const article = document.querySelector("article[data-bv-watch]");
  if (article && typeof EventSource === "function") start(article);
}
