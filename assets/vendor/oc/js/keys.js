// Letter shortcuts are shown in capitals but fire without Shift; other keys match exactly.
export function matchesShortcut(shortcut, key) {
  if (/^[A-Za-z]$/.test(shortcut)) return key.toLowerCase() === shortcut.toLowerCase();
  return key === shortcut;
}

export function shouldIgnore(target) {
  if (!target) return false;
  return ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName) || target.isContentEditable === true;
}

function visible(el) {
  return el.offsetParent !== null || el.getClientRects().length > 0;
}

function closeInnermost() {
  const menu = [...document.querySelectorAll(".oc-menu:not([hidden])")].pop();
  if (menu) {
    menu.hidden = true;
    return true;
  }
  const dialog = [...document.querySelectorAll("dialog[open]")].pop();
  if (dialog) {
    dialog.close();
    return true;
  }
  return false;
}

if (typeof document !== "undefined") {
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      if (closeInnermost()) e.preventDefault();
      return;
    }
    if (e.ctrlKey || e.metaKey || e.altKey || shouldIgnore(e.target)) return;
    if (e.key === "?") {
      const d = document.getElementById("oc-shortcuts");
      if (d) d.open ? d.close() : d.showModal();
      e.preventDefault();
      return;
    }
    if (e.key === "/") {
      const s = document.querySelector("[data-oc-search]");
      if (s && visible(s)) {
        e.preventDefault();
        s.focus();
        s.select?.();
      }
      return;
    }
    const scope = document.querySelector("tr.is-selected") ?? document;
    const match = (root) =>
      [...root.querySelectorAll(`[data-oc-shortcut]`)].find(
        (el) => matchesShortcut(el.dataset.ocShortcut, e.key) && el.tagName !== "INPUT" && (visible(el) || root !== document),
      );
    const el = match(scope) ?? match(document);
    if (el) {
      e.preventDefault();
      el.click();
    }
  });
}
