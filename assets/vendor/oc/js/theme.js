// Runs before first paint. Signed-in pages carry the user's choice from the server; this only covers signed-out pages.
(function () {
  var html = document.documentElement;
  if (html.dataset.prefs !== "local") return;
  try {
    var theme = localStorage.getItem("oc.theme");
    if (theme === "light" || theme === "dark") html.dataset.theme = theme;
    if (localStorage.getItem("oc.density") === "compact") html.dataset.density = "compact";
  } catch (e) {
    /* storage blocked: keep the defaults */
  }
})();
