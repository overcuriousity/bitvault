import {
  ROTORS,
  defaultKey,
  encipher,
  group,
  keyLine,
  normalise,
  startedLine,
  swapRotor,
  togglePlug,
  turnStart,
  wheelSteps,
} from "./enigma.js";
import { createdLocation, summaryText } from "./create.js";
import { serverMessage, showNotice } from "./notice.js";

const root = document.getElementById("enigma");

if (root) {
  const text = document.getElementById("enigma-text");
  const result = document.getElementById("enigma-result");
  const trace = document.getElementById("enigma-trace");
  const started = document.getElementById("enigma-started");
  const keyText = document.getElementById("enigma-key");
  const keyCopy = document.getElementById("enigma-key-copy");
  const board = document.getElementById("enigma-board");
  const form = document.getElementById("enigma-form");
  const content = document.getElementById("enigma-content");
  const submit = document.getElementById("enigma-submit");
  const options = document.getElementById("options");
  const notice = document.getElementById("enigma-notice");
  const reflector = document.getElementById("enigma-reflector");
  const rotorSelects = [...root.querySelectorAll("[data-enigma-rotor]")];
  const windows = [...root.querySelectorAll("[data-enigma-window]")];
  const rings = [...root.querySelectorAll("[data-enigma-ring]")];
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const svgNS = "http://www.w3.org/2000/svg";
  let state = { ...defaultKey(), pending: null };
  let shown = [...state.start];
  let submitting = false;

  try {
    const arriving = sessionStorage.getItem("bv-enigma-text");
    if (arriving !== null) {
      text.value = arriving;
      sessionStorage.removeItem("bv-enigma-text");
    }
  } catch {
    // Storage is optional; the machine still works without it.
  }

  const wrap = (value) => ((value % 26) + 26) % 26;
  const signedDifference = (to, from) => wrap(to - from + 13) - 13;

  function syncMenu(select) {
    const wrap = select.nextElementSibling;
    if (!wrap?.classList.contains("oc-menu-wrap")) return;
    const button = wrap.querySelector(".oc-menu-button");
    button.textContent = select.options[select.selectedIndex]?.textContent ?? "";
    button.setAttribute("aria-label", select.getAttribute("aria-label") ?? "Choose an option");
    const items = wrap.querySelectorAll('[role="option"]');
    items.forEach((item, index) => item.setAttribute("aria-selected", String(index === select.selectedIndex)));
  }

  function drawWindow(window, slot, position) {
    const difference = signedDifference(position, shown[slot]);
    const strip = document.createElement("div");
    strip.className = "bv-enigma-strip";
    if (Math.abs(difference) === 1) {
      strip.classList.add(difference > 0 ? "bv-enigma-strip--forward" : "bv-enigma-strip--back");
    }
    const notch = ROTORS[state.rotors[slot]].notch;
    for (let offset = -3; offset <= 3; offset++) {
      const value = wrap(position + offset);
      const cell = document.createElement("span");
      cell.className = "bv-enigma-cell";
      cell.dataset.distance = String(Math.abs(offset));
      const label = document.createElement("span");
      label.textContent = alphabet[value];
      cell.append(label);
      if (slot > 0 && alphabet[value] === notch) {
        const tick = document.createElement("span");
        tick.className = "bv-enigma-notch";
        tick.setAttribute("aria-hidden", "true");
        tick.textContent = "‹";
        cell.append(tick);
      }
      strip.append(cell);
    }
    window.replaceChildren(strip);
    window.setAttribute("aria-valuenow", String(position + 1));
    window.setAttribute("aria-valuetext", alphabet[position]);
  }

  function drawResult(records) {
    const letters = records.map((record) => record.out).join("");
    const grouped = group(letters);
    const nodes = [];
    for (const character of grouped) {
      if (character === " ") {
        nodes.push(document.createTextNode(character));
      } else {
        const span = document.createElement("span");
        span.textContent = character;
        nodes.push(span);
      }
    }
    if (nodes.length) nodes.at(-1).className = "bv-enigma-result__last";
    result.replaceChildren(...nodes);
    if (content) content.value = grouped;
    if (submit) submit.disabled = submitting || !grouped;

    trace.replaceChildren();
    const last = records.at(-1);
    if (!last) return;
    trace.append(document.createTextNode(last.in));
    for (const part of last.path) {
      const stage = document.createElement("span");
      stage.className = "bv-enigma-trace__stage";
      stage.textContent = part.stage;
      const letter = document.createElement("span");
      letter.className = "bv-enigma-trace__letter";
      letter.textContent = part.letter;
      trace.append(document.createTextNode(" → "), stage, document.createTextNode(" "), letter);
    }
  }

  function partner(letter) {
    for (const [a, b] of state.plugs) {
      if (a === letter) return b;
      if (b === letter) return a;
    }
    return null;
  }

  function drawCables() {
    const svg = board.querySelector("svg");
    if (!svg) return;
    const box = board.getBoundingClientRect();
    const width = board.clientWidth;
    const height = board.clientHeight;
    svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
    svg.setAttribute("width", String(width));
    svg.setAttribute("height", String(height));
    svg.replaceChildren();
    const sockets = new Map();
    for (const button of board.querySelectorAll("button[data-letter]")) {
      const rect = button.getBoundingClientRect();
      const x = rect.left - box.left + rect.width / 2;
      const y = rect.top - box.top + rect.height - 6;
      const letter = Number(button.dataset.letter);
      sockets.set(letter, { x, y });
      for (const side of [-1, 1]) {
        const circle = document.createElementNS(svgNS, "circle");
        circle.setAttribute("cx", String(x + side * 4));
        circle.setAttribute("cy", String(y));
        circle.setAttribute("r", "2.5");
        circle.setAttribute("stroke", partner(letter) === null ? "var(--color-border-strong)" : "var(--color-accent)");
        circle.setAttribute("fill", partner(letter) === null ? "var(--color-bg-elevated)" : "var(--color-accent)");
        circle.setAttribute("stroke-width", "1");
        svg.append(circle);
      }
    }
    for (const [a, b] of state.plugs) {
      const one = sockets.get(a);
      const two = sockets.get(b);
      if (!one || !two) continue;
      const path = document.createElementNS(svgNS, "path");
      const distance = Math.hypot(two.x - one.x, two.y - one.y);
      const sag = 14 + distance * 0.12;
      const y = Math.max(one.y, two.y) + sag;
      path.setAttribute("d", `M ${one.x} ${one.y} Q ${(one.x + two.x) / 2} ${y} ${two.x} ${two.y}`);
      path.setAttribute("fill", "none");
      path.setAttribute("stroke", "var(--color-accent)");
      path.setAttribute("stroke-width", "3");
      path.setAttribute("stroke-linecap", "round");
      svg.append(path);
    }
  }

  function drawBoard() {
    const svg = document.createElementNS(svgNS, "svg");
    svg.classList.add("bv-enigma-cables");
    svg.setAttribute("aria-hidden", "true");
    const rows = ["QWERTZUIO", "ASDFGHJK", "PYXCVBNML"].map((letters) => {
      const row = document.createElement("div");
      row.className = "bv-enigma-board__row";
      for (const character of letters) {
        const value = alphabet.indexOf(character);
        const joined = partner(value);
        const button = document.createElement("button");
        button.type = "button";
        button.className = "oc-btn oc-btn--default bv-enigma-key-button";
        button.dataset.letter = String(value);
        button.setAttribute("aria-label", joined === null ? character : `${character}, joined to ${alphabet[joined]}`);
        button.setAttribute("aria-pressed", String(state.pending === value));
        const letter = document.createElement("span");
        letter.textContent = character;
        const mate = document.createElement("span");
        mate.className = "bv-enigma-key-button__partner";
        mate.textContent = joined === null ? "" : alphabet[joined];
        button.append(letter, mate);
        row.append(button);
      }
      return row;
    });
    board.replaceChildren(svg, ...rows);
    requestAnimationFrame(drawCables);
  }

  function render() {
    const normalised = normalise(text.value);
    const output = encipher(normalised, state);
    reflector.value = state.reflector;
    rotorSelects.forEach((select, slot) => {
      select.value = state.rotors[slot];
      syncMenu(select);
    });
    syncMenu(reflector);
    windows.forEach((window, slot) => drawWindow(window, slot, output.end[slot]));
    rings.forEach((ring, slot) => {
      ring.querySelector("[data-value]").textContent = String(state.rings[slot] + 1).padStart(2, "0");
    });
    shown = [...output.end];
    started.textContent = normalised.length
      ? startedLine(state, normalised.length)
      : "Set the start position: mouse wheel, drag, arrow keys, or type a letter.";
    const line = keyLine(state);
    keyText.textContent = line;
    keyCopy.dataset.ocCopy = line;
    drawResult(output.records);
    drawBoard();
  }

  function turn(slot, by) {
    if (!by) return;
    state = turnStart(state, slot, by);
    render();
  }

  function bindWheel(element, callback) {
    let acc = 0;
    let quiet;
    element.addEventListener("wheel", (event) => {
      event.preventDefault();
      const next = wheelSteps(acc, event.deltaY, event.deltaMode);
      acc = next.acc;
      clearTimeout(quiet);
      quiet = setTimeout(() => {
        acc = 0;
      }, 200);
      callback(next.steps);
    }, { passive: false });
  }

  windows.forEach((window, slot) => {
    bindWheel(window, (steps) => turn(slot, steps));
    let drag = null;
    window.addEventListener("pointerdown", (event) => {
      if (event.button !== 0) return;
      event.preventDefault();
      window.focus();
      window.setPointerCapture(event.pointerId);
      drag = { id: event.pointerId, y: event.clientY, acc: 0 };
    });
    window.addEventListener("pointermove", (event) => {
      if (!drag || drag.id !== event.pointerId) return;
      drag.acc += drag.y - event.clientY;
      drag.y = event.clientY;
      const steps = Math.trunc(drag.acc / 22);
      if (steps) {
        drag.acc -= steps * 22;
        turn(slot, steps);
      }
    });
    const endDrag = (event) => {
      if (!drag || drag.id !== event.pointerId) return;
      if (window.hasPointerCapture(event.pointerId)) window.releasePointerCapture(event.pointerId);
      drag = null;
    };
    window.addEventListener("pointerup", endDrag);
    window.addEventListener("pointercancel", endDrag);
    window.addEventListener("keydown", (event) => {
      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        event.preventDefault();
        turn(slot, event.key === "ArrowDown" ? 1 : -1);
      } else if (/^[a-z]$/i.test(event.key) && !event.ctrlKey && !event.metaKey && !event.altKey) {
        event.preventDefault();
        const target = alphabet.indexOf(event.key.toUpperCase());
        turn(slot, signedDifference(target, shown[slot]));
      }
    });
  });

  rings.forEach((ring, slot) => {
    const step = (by) => {
      const next = [...state.rings];
      next[slot] = wrap(next[slot] + by);
      state = { ...state, rings: next };
      render();
    };
    ring.querySelectorAll("button[data-step]").forEach((button) => {
      button.addEventListener("click", () => step(Number(button.dataset.step)));
    });
    bindWheel(ring, step);
  });

  reflector.addEventListener("change", () => {
    state = { ...state, reflector: reflector.value };
    render();
  });
  rotorSelects.forEach((select, slot) => {
    select.addEventListener("change", () => {
      state = { ...state, rotors: swapRotor(state.rotors, slot, select.value) };
      render();
    });
  });
  text.addEventListener("input", render);
  board.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-letter]");
    if (!button) return;
    const letter = button.dataset.letter;
    state = { ...state, ...togglePlug(state.plugs, state.pending, Number(letter)) };
    render();
    board.querySelector(`button[data-letter="${letter}"]`)?.focus({ preventScroll: true });
  });
  new ResizeObserver(drawCables).observe(board);

  if (form) {
    const privacy = form.querySelector("#privacy");
    const syncPrivacy = () => {
      form.dataset.privacy = privacy.value;
    };
    privacy.addEventListener("change", syncPrivacy);
    syncPrivacy();
    const chosen = (id) => {
      const select = form.querySelector(`#${id}`);
      return select?.options[select.selectedIndex]?.textContent ?? "";
    };
    const syncSummary = () => {
      form.querySelector("#options-summary").textContent = summaryText(
        chosen("privacy"),
        chosen("expiry"),
        form.querySelector("#burn")?.value,
      );
    };
    form.addEventListener("change", syncSummary);
    form.addEventListener("input", syncSummary);
    syncSummary();

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (submitting || !content.value) return;
      submitting = true;
      submit.disabled = true;
      const busyTimer = setTimeout(() => submit.setAttribute("aria-busy", "true"), 400);
      try {
        const response = await fetch("/", {
          method: "POST",
          body: new FormData(form),
          headers: { "HX-Request": "true" },
        });
        const location = response.ok ? createdLocation(response.headers) : null;
        if (location) {
          globalThis.location.assign(location);
          return;
        }
        options.open = true;
        showNotice(notice, "danger", await serverMessage(response, "The paste could not be created."));
      } catch {
        options.open = true;
        showNotice(notice, "danger", "Could not reach the server.");
      } finally {
        clearTimeout(busyTimer);
        submitting = false;
        submit.disabled = !content.value;
        submit.removeAttribute("aria-busy");
      }
    });
  }

  render();
}
