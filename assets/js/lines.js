// Puts text into a <pre> the way the server renders it: one <span class="line"> per line, which
// the stylesheet numbers. The line break stays inside its span, so the text content is the text.
export function splitLines(text) {
  const lines = text.split("\n").map((line, i, all) => (i < all.length - 1 ? `${line}\n` : line));
  // Text that ends in a line break has no line after it.
  if (lines.at(-1) === "") lines.pop();
  return lines;
}

export function fillLines(pre, text) {
  const code = pre.querySelector("code") ?? pre;
  code.replaceChildren(
    ...splitLines(text).map((line) => {
      const span = document.createElement("span");
      span.className = "line";
      span.textContent = line;
      return span;
    }),
  );
}
