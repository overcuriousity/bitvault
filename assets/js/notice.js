// Inline notices for the secret-paste scripts, in the same markup the server renders.

export function showNotice(region, kind, message) {
  if (!region) return;
  region.replaceChildren();
  if (!message) return;
  const box = document.createElement("div");
  box.className = `oc-notice oc-notice--${kind}`;
  box.setAttribute("role", "status");
  const text = document.createElement("span");
  text.className = "oc-notice__text";
  text.textContent = message;
  box.append(text);
  region.append(box);
}

// The server's own one-sentence error. Its HTML is parsed into an inert document and only the
// notice's text is taken, so nothing from the response is ever inserted as markup.
export async function serverMessage(res, fallback) {
  try {
    const body = await res.text();
    const type = res.headers.get("content-type") ?? "";
    if (type.startsWith("text/html")) {
      const doc = new DOMParser().parseFromString(body, "text/html");
      const text = doc.querySelector(".oc-notice__text")?.textContent?.trim();
      if (text) return text;
    } else if (type.startsWith("text/plain") && body.trim() && body.length < 300) {
      return body.trim();
    }
  } catch {
    /* an unreadable body falls back to the generic message */
  }
  return fallback;
}
