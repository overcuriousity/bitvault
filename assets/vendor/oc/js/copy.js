function announce(text) {
  const live = document.getElementById("oc-live");
  if (live) live.textContent = text;
}

if (typeof document !== "undefined") {
  if (!window.isSecureContext || !navigator.clipboard) {
    document.documentElement.dataset.ocNoCopy = "";
  }
  document.addEventListener("click", async (e) => {
    const b = e.target.closest?.("[data-oc-copy]");
    if (!b) return;
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(b.dataset.ocCopy);
      b.dataset.copied = "";
      announce("Copied");
      setTimeout(() => delete b.dataset.copied, 1500);
    } catch {
      announce("Could not copy. Select the text instead.");
    }
  });
}
