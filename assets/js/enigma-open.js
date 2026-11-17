// The way from a text that looks like Enigma output to the Enigma page: the text waits in session
// storage, which the page empties into its text box. Nothing is sent to the server.
export const ENIGMA_TEXT_KEY = "bv-enigma-text";

export function openInEnigma(text, storage = globalThis.sessionStorage, go = (to) => globalThis.location.assign(to)) {
  try {
    storage.setItem(ENIGMA_TEXT_KEY, text);
  } catch {
    // Without storage the page still opens, with an empty text box.
  }
  go("/enigma");
}
