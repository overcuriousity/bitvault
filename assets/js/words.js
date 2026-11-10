// Word suggestions for "Open a paste". The list loads on the field's first focus; each
// suggestion is the whole value so far with the word being typed completed, because a datalist
// matches against the whole field.

const LIMIT = 12;

export function suggestions(value, words, limit = LIMIT) {
  const match = /^(\s*(?:[^\s-]+[\s-]+){0,2})([^\s-]+)$/.exec(value);
  if (!match) return [];
  const [, done, part] = match;
  const prefix = part.toLowerCase();
  const out = [];
  for (const word of words) {
    if (!word.startsWith(prefix)) continue;
    out.push(done + word);
    if (out.length >= limit) break;
  }
  // A finished word suggests only itself, which would just repeat the field.
  return out.length === 1 && out[0] === value ? [] : out;
}

if (typeof document !== "undefined") {
  const input = document.getElementById("words");
  const list = input && document.getElementById(input.getAttribute("list") ?? "");
  if (input && list && input.dataset.wordsSrc) {
    let words = null;
    let loading = null;
    const update = () => {
      if (!words) return;
      list.replaceChildren(
        ...suggestions(input.value, words).map((v) => {
          const option = document.createElement("option");
          option.value = v;
          return option;
        }),
      );
    };
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
    input.addEventListener("input", update);
  }
}
