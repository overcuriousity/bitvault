// Offline support is optional: a failed registration leaves the app working as before.
if (typeof navigator !== "undefined" && "serviceWorker" in navigator && window.isSecureContext) {
  navigator.serviceWorker.register("/sw.js").catch(() => {});
}
