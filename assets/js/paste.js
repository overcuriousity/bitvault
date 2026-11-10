// The paste page: the buttons that need scripts, Share where the browser has it, Copy text from the shown content, and
// relative times that stay fresh. Everything here is an extra; the page works without it.

const MINUTE = 60;
const REFRESH_MS = 60 * 1000;

function withRest(big, bigUnit, small, smallUnit) {
  return small === 0 ? `${big} ${bigUnit}` : `${big} ${bigUnit} ${small} ${smallUnit}`;
}

// Mirrors `relative` in src/web/mod.rs: calm units, no seconds. `delta` is seconds from now.
export function relativeText(delta) {
  const secs = Math.abs(Math.trunc(delta));
  if (secs < MINUTE) return delta >= 0 ? "in less than a minute" : "just now";
  const minutes = Math.floor(secs / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(minutes / 1440);
  let amount;
  if (minutes < 60) amount = `${minutes} min`;
  else if (hours < 24) amount = withRest(hours, "h", minutes % 60, "min");
  else if (days < 30) amount = withRest(days, "d", hours % 24, "h");
  else if (days < 365) amount = `${days} d`;
  else amount = withRest(Math.floor(days / 365), "y", days % 365, "d");
  return delta >= 0 ? `in ${amount}` : `${amount} ago`;
}

// "expires" reads "Expired" once past; "ago" never reads as the future (clocks differ).
export function relativeFor(kind, delta) {
  if (kind === "expires" && delta <= 0) return "Expired";
  return relativeText(kind === "ago" ? Math.min(delta, -1) : delta);
}

function announce(text) {
  const live = document.getElementById("oc-live");
  if (live) live.textContent = text;
}

function refreshTimes(root, nowMs) {
  for (const el of root.querySelectorAll("time[data-bv-relative]")) {
    const at = Date.parse(el.getAttribute("datetime") ?? "");
    if (Number.isNaN(at)) continue;
    el.textContent = relativeFor(el.dataset.bvRelative, Math.round((at - nowMs) / 1000));
  }
}

async function copyTarget(button) {
  const source = document.getElementById(button.dataset.bvCopyTarget);
  if (!source) return;
  try {
    await navigator.clipboard.writeText(source.textContent);
    button.dataset.copied = "";
    announce("Copied");
    setTimeout(() => delete button.dataset.copied, 1500);
  } catch {
    announce("Could not copy. Select the text instead.");
  }
}

export function init(root = document) {
  refreshTimes(root, Date.now());
  setInterval(() => refreshTimes(root, Date.now()), REFRESH_MS);
  for (const needed of root.querySelectorAll("[data-bv-needs-js]")) needed.hidden = false;
  for (const share of root.querySelectorAll("[data-bv-share]")) {
    if (typeof navigator.share !== "function") continue;
    share.hidden = false;
    share.addEventListener("click", () => {
      // Dismissing the share sheet rejects; that is not an error worth showing.
      navigator.share({ url: share.dataset.bvShare }).catch(() => {});
    });
  }
  root.addEventListener("click", (e) => {
    const button = e.target.closest?.("[data-bv-copy-target]");
    if (button && navigator.clipboard) copyTarget(button);
  });
}

if (typeof document !== "undefined") init();
