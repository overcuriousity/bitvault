// Copy outside a secure context, where navigator.clipboard is missing and copy.js hides its
// buttons: a temporary off-screen textarea and execCommand("copy"). Inactive when the
// clipboard API is there.

export function needsFallback(secure, clipboard) {
  return !secure || !clipboard;
}

// What a copy button copies: the text of its target element, or its data-oc-copy value.
export function textFor(button, doc) {
  const target = button.dataset.bvCopyTarget;
  if (target) return doc.getElementById(target)?.textContent ?? "";
  return button.dataset.ocCopy ?? "";
}

function copyText(text, doc) {
  const area = doc.createElement("textarea");
  area.value = text;
  area.setAttribute("readonly", "");
  area.className = "bv-copy-scratch";
  doc.body.append(area);
  area.select();
  try {
    return doc.execCommand("copy");
  } catch {
    return false;
  } finally {
    area.remove();
  }
}

export function init(doc = document, win = window) {
  if (!needsFallback(win.isSecureContext, win.navigator.clipboard)) return;
  doc.documentElement.dataset.bvCopyFallback = "";
  // Capture on the document runs before copy.js's listener, and stopping there keeps it from
  // announcing a failure for the same click.
  doc.addEventListener(
    "click",
    (e) => {
      const button = e.target.closest?.("[data-oc-copy], [data-bv-copy-target]");
      if (!button) return;
      e.stopPropagation();
      const live = doc.getElementById("oc-live");
      if (copyText(textFor(button, doc), doc)) {
        button.dataset.copied = "";
        if (live) live.textContent = "Copied";
        setTimeout(() => delete button.dataset.copied, 1500);
      } else if (live) {
        live.textContent = "Could not copy. Select the text instead.";
      }
    },
    true,
  );
}

if (typeof document !== "undefined") init();
