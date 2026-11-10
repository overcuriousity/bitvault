// The one box on the home page. Text or a link is kept as a new paste; three paste words open the
// paste they name. The server decides on submit (see `web::home::create`); this script says which
// it will be before the button is pressed, names the button after it, offers the words that fit
// the one being typed (Tab takes the first), and tells create.js what to do on submit.
//
// Enter on a box that is one line of three words opens that paste, the quick way in. It only ever
// opens: words no paste has stay in the box with a note, and keeping them takes the button.
import { accept, addressLike, chips, choose, readAddress } from "./words.js";

// Long enough that a lookup waits for a pause in typing, short enough to answer before a press.
const LOOKUP_DELAY = 350;

function echoFor(state, address) {
  switch (state) {
    case "files":
      return "With files attached, this is kept as a new paste.";
    case "checking":
      return `Looking for the paste ${address}…`;
    case "found":
      return `Enter opens the paste ${address}.`;
    case "missing":
      return `No paste has the words ${address}, so they are kept as a new paste.`;
    case "ambiguous":
      return "These letters read as more than one address, so they are kept as a new paste. Put spaces or hyphens between the words to open one.";
    case "busy":
      return "Too many lookups from this address for now, so this is kept as a new paste. Wait a minute to open one.";
    default:
      return null;
  }
}

// Whether a paste has this address: "found", "missing" or "busy". POST /open answers 200 with
// HX-Redirect when it does, 422 when it does not, and 429 once this address has missed too often.
async function lookup(address) {
  const res = await fetch("/open", {
    method: "POST",
    headers: { "HX-Request": "true", "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ words: address }),
    credentials: "same-origin",
  });
  if (res.ok && res.headers.get("hx-redirect")) return "found";
  if (res.status === 429) return "busy";
  if (res.status === 422) return "missing";
  throw new Error(`lookup answered ${res.status}`);
}

/** Binds the box of `form` and returns `decide`, which create.js awaits on submit. */
export function bindBox(form) {
  const box = form.querySelector("#content");
  const echo = form.querySelector("#box-echo");
  const chipRow = form.querySelector("#box-chips");
  const submit = form.querySelector("#box-submit");
  const keep = form.querySelector("#box-keep");
  const files = form.querySelector("#files");
  if (!box || !echo || !submit) return { decide: async () => ({}) };

  const idleEcho = echo.textContent;
  const label = submit.querySelector(".bv-go__label") ?? submit;
  const idleLabel = label.textContent;
  const results = new Map();
  let words = null;
  let loading = null;
  let timer = null;

  const load = () => {
    loading ??= fetch(box.dataset.wordsSrc)
      .then((res) => (res.ok ? res.text() : ""))
      .then((text) => {
        words = text.split("\n").filter(Boolean);
        render();
      })
      .catch(() => {
        // Without the list the box still works: the server decides on submit.
      });
    return loading;
  };

  const hasFiles = () => (files?.files?.length ?? 0) > 0;

  // What the box reads as now, without waiting for a lookup.
  const reading = () => {
    if (!words) return { state: "idle" };
    const read = readAddress(box.value.trim(), words);
    if (!read) return { state: "idle" };
    if (read.ambiguous) return { state: "ambiguous" };
    if (hasFiles()) return { state: "files", address: read.address };
    return { state: results.get(read.address) ?? "checking", address: read.address };
  };

  const setText = (el, text) => {
    if (el.textContent !== text) el.textContent = text;
  };

  const renderChips = () => {
    const found = words && box.selectionEnd === box.value.length ? chips(box.value, words) : null;
    if (!chipRow) return;
    if (!found) {
      chipRow.hidden = true;
      chipRow.replaceChildren();
      return;
    }
    chipRow.replaceChildren(
      ...found.fits.map((word) => {
        const b = document.createElement("button");
        b.type = "button";
        b.className = "oc-btn bv-chip";
        b.textContent = word;
        b.addEventListener("click", () => {
          const next = choose(box.value, words, word);
          if (next !== null) box.value = next;
          box.focus();
          box.setSelectionRange(box.value.length, box.value.length);
          update();
        });
        return b;
      }),
    );
    chipRow.hidden = false;
  };

  // The form's look follows the box, for those who never read the line under it: "open" turns
  // the box and the button green with an arrow, "attention" amber. See app.css.
  const look = (state) => (state === "found" ? "open" : state === "ambiguous" || state === "busy" ? "attention" : "");

  // The box starts one line tall, like the address field it may be, and grows into the text area
  // once what is typed can no longer be three words. It stays grown until it is emptied, so it
  // never shrinks under someone editing text.
  let grown = !form.hasAttribute("data-compact");
  // The options follow: folded to their summary while the box is an address field, open once it
  // holds text or files. Only a change of need moves them, so a fold or unfold by hand holds.
  const options = form.querySelector("#options");
  let needed = null;
  const size = () => {
    if (!box.value.trim()) grown = false;
    else if (!grown && !addressLike(box.value, words)) grown = true;
    form.toggleAttribute("data-compact", !grown);
    const need = grown || hasFiles();
    if (options && need !== needed) {
      needed = need;
      options.open = need;
    }
  };

  function render() {
    size();
    const { state, address } = reading();
    setText(echo, echoFor(state, address) ?? idleEcho);
    const opens = state === "found";
    setText(label, opens ? "Open paste" : idleLabel);
    if (keep) keep.hidden = !opens;
    const shown = look(state);
    if (shown) form.dataset.box = shown;
    else delete form.dataset.box;
    renderChips();
  }

  // A short shake when Enter cannot open what is in the box.
  const nudge = () => {
    delete form.dataset.boxNudge;
    // Read layout so removing and setting the attribute restarts the animation.
    void box.offsetWidth;
    form.dataset.boxNudge = "";
    setTimeout(() => delete form.dataset.boxNudge, 400);
  };
  // The arrow leaves to the right while the paste loads.
  const opening = (address) => {
    form.dataset.box = "opening";
    window.location.assign(`/${address}`);
  };
  window.addEventListener("pageshow", (event) => {
    if (event.persisted) render();
  });

  function update() {
    render();
    clearTimeout(timer);
    const { state, address } = reading();
    if (state !== "checking") return;
    timer = setTimeout(() => {
      lookup(address)
        .then((result) => results.set(address, result))
        .catch(() => results.delete(address))
        .finally(render);
    }, LOOKUP_DELAY);
  }

  // Enter in an address-shaped box: open the paste, or say why not. Anything else gets its new
  // line. Decided before the word list or the lookup may be ready, so the line break is held back
  // first and put in by hand when the box turns out not to be an address.
  const newLine = () => {
    box.setRangeText("\n", box.selectionStart, box.selectionEnd, "end");
    box.dispatchEvent(new Event("input", { bubbles: true }));
  };
  const enter = async () => {
    await load();
    const read = words ? readAddress(box.value.trim(), words) : null;
    if (!read || hasFiles()) return newLine();
    if (read.ambiguous) {
      render();
      return nudge();
    }
    clearTimeout(timer);
    let result = results.get(read.address);
    if (!result) {
      setText(echo, echoFor("checking", read.address));
      try {
        result = await lookup(read.address);
        results.set(read.address, result);
      } catch {
        return render();
      }
    }
    if (result === "found") return opening(read.address);
    render();
    nudge();
    if (result === "missing") {
      setText(echo, `No paste has the words ${read.address}. Check them, or press Create paste to keep them as text.`);
    }
  };
  box.addEventListener("beforeinput", (event) => {
    if (event.inputType !== "insertLineBreak" || event.isComposing) return;
    const looksLikeWords = /^\s*[a-z]+(?:[\s-]+[a-z]+){0,2}\s*$/i.test(box.value) && box.value.length <= 64;
    if (!looksLikeWords || box.selectionEnd !== box.value.length) return;
    event.preventDefault();
    enter();
  });

  box.addEventListener("focus", load);
  if (document.activeElement === box) load();
  // A box the browser refilled (back, reload) is sized at once, by its shape until the list loads.
  size();
  box.addEventListener("input", () => {
    load();
    update();
  });
  // The caret moving away from the end hides the word list.
  box.addEventListener("keyup", renderChips);
  box.addEventListener("click", renderChips);
  files?.addEventListener("change", update);
  box.addEventListener("keydown", (event) => {
    // Enter stays a new line in the box; with Ctrl or Cmd it presses the button.
    if (event.key === "Enter" && (event.ctrlKey || event.metaKey) && !event.isComposing) {
      event.preventDefault();
      form.requestSubmit(submit);
      return;
    }
    if (event.key !== "Tab" || event.shiftKey || event.altKey || event.ctrlKey || event.metaKey) return;
    if (!words || event.isComposing || box.selectionEnd !== box.value.length) return;
    const next = accept(box.value, words);
    // Nothing to take: Tab moves focus as usual.
    if (next === null) return;
    event.preventDefault();
    box.value = next;
    box.setSelectionRange(next.length, next.length);
    update();
  });

  return {
    /**
     * What a submit should do: `{ open: "/words" }` to go to an existing paste, or
     * `{ intent: "create" }` once this script has decided to keep the text, so the server does
     * not look the words up a second time.
     */
    async decide(submitter) {
      if (submitter && submitter === keep) return { intent: "create" };
      await load();
      if (!words || hasFiles()) return {};
      const read = readAddress(box.value.trim(), words);
      if (!read) return {};
      if (read.ambiguous) return { intent: "create" };
      clearTimeout(timer);
      let result = results.get(read.address);
      if (!result) {
        try {
          result = await lookup(read.address);
          results.set(read.address, result);
        } catch {
          // Unknown: leave it to the server.
          return {};
        }
      }
      render();
      if (result === "found") form.dataset.box = "opening";
      return result === "found" ? { open: `/${read.address}` } : { intent: "create" };
    },
  };
}
