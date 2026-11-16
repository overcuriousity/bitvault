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
