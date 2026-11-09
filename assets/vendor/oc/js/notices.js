export function remainingAfterPause(totalMs, elapsedMs) {
  return Math.max(0, totalMs - elapsedMs);
}

function bind(notice) {
  if (notice.dataset.ocBound) return;
  notice.dataset.ocBound = "1";
  let left = Number(notice.dataset.ocAutohide) || 6000;
  let started = Date.now();
  let timer = setTimeout(() => notice.remove(), left);
  const pause = () => {
    clearTimeout(timer);
    left = remainingAfterPause(left, Date.now() - started);
  };
  const resume = () => {
    if (notice.matches(":hover") || notice.contains(document.activeElement)) return;
    started = Date.now();
    timer = setTimeout(() => notice.remove(), left);
  };
  notice.addEventListener("mouseenter", pause);
  notice.addEventListener("focusin", pause);
  notice.addEventListener("mouseleave", resume);
  notice.addEventListener("focusout", () => setTimeout(resume));
  notice.addEventListener("htmx:afterRequest", () => notice.remove());
}

function scan(root) {
  if (root.matches?.("[data-oc-autohide]")) bind(root);
  for (const n of root.querySelectorAll?.("[data-oc-autohide]") ?? []) bind(n);
}

if (typeof document !== "undefined") {
  scan(document);
  new MutationObserver((records) => {
    for (const r of records) for (const n of r.addedNodes) if (n.nodeType === 1) scan(n);
  }).observe(document.body, { childList: true, subtree: true });
}
