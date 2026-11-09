const timers = new WeakMap();

if (typeof document !== "undefined") {
  document.addEventListener("htmx:beforeRequest", (e) => {
    const elt = e.detail.elt;
    if (!(elt instanceof HTMLButtonElement)) return;
    timers.set(elt, setTimeout(() => elt.setAttribute("aria-busy", "true"), 400));
  });
  document.addEventListener("htmx:afterRequest", (e) => {
    const elt = e.detail.elt;
    clearTimeout(timers.get(elt));
    elt.removeAttribute?.("aria-busy");
  });
}
