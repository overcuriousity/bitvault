export function confirmEnabled(typed, name) {
  return name.length > 0 && typed === name;
}

if (typeof document !== "undefined") {
  document.addEventListener("click", (e) => {
    const opener = e.target.closest?.("[data-oc-dialog-open]");
    if (opener) {
      document.getElementById(opener.dataset.ocDialogOpen)?.showModal();
      return;
    }
    const closer = e.target.closest?.("[data-oc-dialog-close]");
    if (closer) closer.closest("dialog")?.close();
  });
  document.addEventListener("input", (e) => {
    const form = e.target.closest?.("form[data-oc-confirm-name]");
    if (!form) return;
    const submit = form.querySelector('button[type="submit"]');
    if (submit) submit.disabled = !confirmEnabled(e.target.value, form.dataset.ocConfirmName);
  });
  document.addEventListener("htmx:afterRequest", (e) => {
    if (e.detail.successful) e.detail.elt.closest?.("dialog")?.close();
  });
  document.addEventListener("close", (e) => {
    const form = e.target.querySelector?.("form[data-oc-confirm-name]");
    if (form) {
      form.reset();
      const submit = form.querySelector('button[type="submit"]');
      if (submit) submit.disabled = true;
    }
  }, true);
}
