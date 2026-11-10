// Word help for "Open a paste". The list loads on the field's first focus.
//
// With a mouse and keyboard, the word being typed is completed in place: the rest of the first word it
// begins is added and selected, so typing on replaces it, Backspace or Escape removes it, and Tab
// takes it and adds a hyphen for the next word. Tab with nothing to take moves focus as usual.
// On touch screens there is no Tab key, so the field keeps its datalist: each suggestion is the
// whole value so far with the word being typed completed, because a datalist matches against
// the whole field.

const LIMIT = 12;
// Inline completion starts at the second letter; one letter fits too many words to guess.
const INLINE_FROM = 2;
// Up to two finished words with their separators, then the word being typed.
const PART = /^(\s*(?:[^\s-]+[\s-]+){0,2})([^\s-]+)$/;

/** The words of `words` that begin with the word being typed in `value`, in list order. */
function candidates(value, words) {
  const match = PART.exec(value);
  if (!match) return null;
  const [, done, part] = match;
  const prefix = part.toLowerCase();
  return { done, part, fits: words.filter((w) => w.startsWith(prefix)) };
}

export function suggestions(value, words, limit = LIMIT) {
  const found = candidates(value, words);
  if (!found) return [];
  const out = found.fits.slice(0, limit).map((w) => found.done + w);
  // A finished word suggests only itself, which would just repeat the field.
  return out.length === 1 && out[0] === value ? [] : out;
}

/** The letters that complete the word being typed to the first word it begins, or "". */
export function completion(value, words) {
  const found = candidates(value, words);
  if (!found || found.part.length < INLINE_FROM) return "";
  const word = found.fits[0];
  return word ? word.slice(found.part.length) : "";
}

/**
 * The value after Tab: the word being typed in full, followed by a separator unless it is the
 * third word. Null when Tab has nothing to complete, so it can move focus as usual.
 */
export function accept(value, words) {
  const found = candidates(value, words);
  if (!found) return null;
  const prefix = found.part.toLowerCase();
  // The typed word itself, or the only word it begins.
  const word = found.fits.includes(prefix) ? prefix : found.fits.length === 1 ? found.fits[0] : null;
  if (!word) return null;
  const count = found.done.split(/[\s-]+/).filter(Boolean).length + 1;
  const separator = count < 3 ? (/\s$/.test(found.done) ? " " : "-") : "";
  const next = found.done + found.part + word.slice(prefix.length) + separator;
  return next === value ? null : next;
}

if (typeof document !== "undefined") {
  const input = document.getElementById("words");
  const list = input && document.getElementById(input.getAttribute("list") ?? "");
  if (input && list && input.dataset.wordsSrc) {
    const keyboard = window.matchMedia("(hover: hover) and (pointer: fine)").matches;
    if (keyboard) {
      // The datalist's pop-up would compete with the completion in the field.
      input.removeAttribute("list");
      input.setAttribute("aria-autocomplete", "inline");
      const hint = document.getElementById("words-hint");
      if (hint) {
        hint.hidden = false;
        input.setAttribute("aria-describedby", hint.id);
      }
    }
    let words = null;
    let loading = null;
    const update = () => {
      if (!words || keyboard) return;
      list.replaceChildren(
        ...suggestions(input.value, words).map((v) => {
          const option = document.createElement("option");
          option.value = v;
          return option;
        }),
      );
    };
    const atEnd = () => input.selectionEnd === input.value.length;
    const pending = () => input.selectionStart < input.selectionEnd && atEnd();

    input.addEventListener("focus", () => {
      loading ??= fetch(input.dataset.wordsSrc)
        .then((res) => (res.ok ? res.text() : ""))
        .then((text) => {
          words = text.split("\n").filter(Boolean);
          update();
        })
        .catch(() => {
          // Without the list the field works the same, without suggestions.
        });
    });
    input.addEventListener("input", (event) => {
      update();
      // Only plain typing at the end: not deleting, pasting or composing with an input method.
      if (!keyboard || !words || event.isComposing || event.inputType !== "insertText" || !atEnd()) return;
      const rest = completion(input.value, words);
      if (rest) input.setRangeText(rest, input.value.length, input.value.length, "select");
    });
    input.addEventListener("keydown", (event) => {
      if (!keyboard || !words || event.altKey || event.ctrlKey || event.metaKey || event.isComposing) return;
      if (event.key === "Escape" && pending()) {
        event.preventDefault();
        input.setRangeText("", input.selectionStart, input.selectionEnd, "end");
      } else if (event.key === "Tab" && !event.shiftKey && atEnd()) {
        // A selected completion is always taken first, even when it already ends the address.
        const next = accept(input.value, words) ?? (pending() ? input.value : null);
        if (next === null) return;
        event.preventDefault();
        input.value = next;
        input.setSelectionRange(next.length, next.length);
        update();
      }
    });
  }
}
