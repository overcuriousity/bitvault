export const ROTORS = {
  I: { wiring: "EKMFLGDQVZNTOWYHXUSPAIBRCJ", notch: "Q" },
  II: { wiring: "AJDKSIRUXBLHWTMCQGZNPYFVOE", notch: "E" },
  III: { wiring: "BDFHJLCPRTXVZNYEIWGAKMUSQO", notch: "V" },
  IV: { wiring: "ESOVPZJAYQUIRHXLNFTGKDCMWB", notch: "J" },
  V: { wiring: "VZBRGITYUPSDNHLXAWMJQOFECK", notch: "Z" },
};

export const REFLECTORS = {
  B: "YRUHQSLDPXNGOKMIEBFZCWVJAT",
  C: "FVPJIAOYEDRZXWGCTKUQSBNMHL",
};

export function defaultKey() {
  return {
    rotors: ["I", "II", "III"],
    reflector: "B",
    rings: [0, 0, 0],
    start: [0, 0, 0],
    plugs: [],
  };
}

const letter = (value) => String.fromCharCode(value + 65);
const index = (value) => value.charCodeAt(0) - 65;

function rotor(contact, slot, key, pos, backwards = false) {
  const { wiring } = ROTORS[key.rotors[slot]];
  const offset = pos[slot] - key.rings[slot];
  const shifted = (contact + offset + 26) % 26;
  const target = backwards ? wiring.indexOf(letter(shifted)) : index(wiring[shifted]);
  return (target - offset + 26) % 26;
}

function plug(contact, plugs) {
  for (const [a, b] of plugs) {
    if (contact === a) return b;
    if (contact === b) return a;
  }
  return contact;
}

export function encipher(letters, key) {
  const pos = [...key.start];
  const records = [];
  const notches = key.rotors.map((name) => index(ROTORS[name].notch));

  for (const input of letters) {
    if (pos[1] === notches[1]) {
      pos[0] = (pos[0] + 1) % 26;
      pos[1] = (pos[1] + 1) % 26;
    } else if (pos[2] === notches[2]) {
      pos[1] = (pos[1] + 1) % 26;
    }
    pos[2] = (pos[2] + 1) % 26;

    let contact = plug(index(input), key.plugs);
    const path = [{ stage: "plug", letter: letter(contact) }];
    for (const slot of [2, 1, 0]) {
      contact = rotor(contact, slot, key, pos);
      path.push({ stage: key.rotors[slot], letter: letter(contact) });
    }
    contact = index(REFLECTORS[key.reflector][contact]);
    path.push({ stage: `reflector ${key.reflector}`, letter: letter(contact) });
    for (const slot of [0, 1, 2]) {
      contact = rotor(contact, slot, key, pos, true);
      path.push({ stage: key.rotors[slot], letter: letter(contact) });
    }
    contact = plug(contact, key.plugs);
    path.push({ stage: "plug", letter: letter(contact) });
    records.push({ in: input, out: letter(contact), pos: [...pos], path });
  }

  return { records, end: pos };
}


export function normalise(text) {
  return text
    .replaceAll("ß", "SS")
    .toUpperCase()
    .replace(/[ÄÖÜ]/g, (value) => ({ Ä: "AE", Ö: "OE", Ü: "UE" })[value])
    .normalize("NFD")
    .replace(/\p{M}/gu, "")
    .replace(/[^A-Z]/g, "");
}

// Splits off what one key press adds to the text box: the next letter and whatever lies before it.
export function nextKeystroke(waiting) {
  const chars = [...waiting];
  const at = chars.findIndex((character) => normalise(character) !== "");
  if (at === -1) return ["", ""];
  return [chars.slice(0, at + 1).join(""), chars.slice(at + 1).join("")];
}

export function group(letters) {
  return letters.match(/.{1,5}/g)?.join(" ") ?? "";
}

export function keyLine(key) {
  const plugs = key.plugs
    .map(([a, b]) => [a, b].sort((x, y) => x - y))
    .sort(([a], [b]) => a - b)
    .map((pair) => pair.map(letter).join(""))
    .join(" ");
  const rings = key.rings.map((value) => String(value + 1).padStart(2, "0")).join(" ");
  const start = key.start.map(letter).join(" ");
  return `Rotors ${key.rotors.join(" ")} · Reflector ${key.reflector} · Rings ${rings} · Start ${start} · Plugs ${plugs || "none"}`;
}

export function startedLine(key, count) {
  const unit = count === 1 ? "letter" : "letters";
  return `Started at ${key.start.map(letter).join(" ")}, ${count} ${unit} ago. Turning a rotor moves the start.`;
}

export function togglePlug(plugs, pending, letterIndex) {
  const joined = plugs.some(([a, b]) => a === letterIndex || b === letterIndex);
  if (joined) {
    return {
      plugs: plugs.filter(([a, b]) => a !== letterIndex && b !== letterIndex),
      pending: null,
    };
  }
  if (pending === null) return { plugs: [...plugs], pending: letterIndex };
  if (pending === letterIndex) return { plugs: [...plugs], pending: null };
  return { plugs: [...plugs, [pending, letterIndex]], pending: null };
}

export function swapRotor(rotors, slot, name) {
  const next = [...rotors];
  const other = next.indexOf(name);
  if (other !== -1 && other !== slot) next[other] = next[slot];
  next[slot] = name;
  return next;
}

export function turnStart(key, slot, by) {
  const start = [...key.start];
  start[slot] = ((start[slot] + by) % 26 + 26) % 26;
  return { ...key, start };
}

export function wheelSteps(acc, deltaY, deltaMode) {
  const total = acc + deltaY * (deltaMode === 1 ? 34 : 1);
  const steps = Math.trunc(total / 100);
  return { steps, acc: total - steps * 100 };
}

export function looksLikeEnigma(text) {
  return /^[A-Z]{5}(?:[ \r\n]+[A-Z]{5})*[ \r\n]+[A-Z]{1,5}$/.test(text.trim());
}
