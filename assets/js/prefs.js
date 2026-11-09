// Theme and text-size toggles. theme.js applies the stored choice before first paint; this handles the clicks.
const THEMES = ["system", "light", "dark"];
const THEME_LABEL = { system: "Use the system theme", light: "Switch to light theme", dark: "Switch to dark theme" };

export function nextTheme(current) {
  const i = Math.max(THEMES.indexOf(current), 0);
  return THEMES[(i + 1) % THEMES.length];
}

function apply(name, value) {
  const html = document.documentElement;
  if (name === "theme") {
    html.dataset.theme = value;
  } else if (value === "compact") {
    html.dataset.density = "compact";
  } else {
    delete html.dataset.density;
  }
}

function persist(name, value) {
  try {
    if (value === "system" || value === "default") localStorage.removeItem(`oc.${name}`);
    else localStorage.setItem(`oc.${name}`, value);
  } catch {
    /* storage blocked: the choice lasts for this page only */
  }
}

function syncButtons(name, value) {
  for (const b of document.querySelectorAll(`[data-oc-pref="${name}"]`)) {
    b.dataset.ocValue = value;
    if (name === "theme") {
      const label = THEME_LABEL[nextTheme(value)];
      b.setAttribute("aria-label", label);
      b.dataset.ocTip = label;
    } else {
      const compact = value === "compact";
      const label = compact ? "Use default text size" : "Use compact text size";
      b.setAttribute("aria-pressed", String(compact));
      b.setAttribute("aria-label", label);
      b.dataset.ocTip = label;
    }
  }
}

function set(name, value) {
  apply(name, value);
  syncButtons(name, value);
  persist(name, value);
}

if (typeof document !== "undefined") {
  syncButtons("theme", document.documentElement.dataset.theme);
  syncButtons("density", document.documentElement.dataset.density || "default");
  document.addEventListener("click", (e) => {
    const b = e.target.closest?.("[data-oc-pref]");
    if (!b) return;
    const name = b.dataset.ocPref;
    const current = b.dataset.ocValue;
    set(name, name === "theme" ? nextTheme(current) : current === "compact" ? "default" : "compact");
  });
}
