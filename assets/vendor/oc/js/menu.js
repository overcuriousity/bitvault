export function typeahead(labels, buffer, fromIndex) {
  const b = buffer.toLowerCase();
  for (let step = 1; step <= labels.length; step++) {
    const i = (fromIndex + step + labels.length) % labels.length;
    if (labels[i].toLowerCase().startsWith(b)) return i;
  }
  return -1;
}

let uid = 0;

function upgrade(select) {
  if (select.dataset.ocUpgraded) return;
  select.dataset.ocUpgraded = "1";
  const id = `oc-menu-${++uid}`;
  const wrap = document.createElement("div");
  wrap.className = "oc-menu-wrap";
  const button = document.createElement("button");
  button.type = "button";
  button.className = "oc-btn oc-menu-button";
  button.setAttribute("aria-haspopup", "listbox");
  button.setAttribute("aria-expanded", "false");
  button.setAttribute("aria-controls", id);
  const label = document.querySelector(`label[for="${select.id}"]`);
  if (label) {
    label.id ||= `${id}-label`;
    button.setAttribute("aria-labelledby", `${label.id} ${id}-button`);
    label.htmlFor = `${id}-button`;
  }
  button.id = `${id}-button`;
  const list = document.createElement("ul");
  list.className = "oc-menu";
  list.id = id;
  list.setAttribute("role", "listbox");
  list.hidden = true;
  const options = [...select.options];
  const items = options.map((o, i) => {
    const li = document.createElement("li");
    li.setAttribute("role", "option");
    li.id = `${id}-${i}`;
    li.textContent = o.textContent;
    li.addEventListener("click", () => choose(i));
    list.append(li);
    return li;
  });
  let active = select.selectedIndex;
  let buffer = "";
  let bufferTimer;

  const render = () => {
    button.textContent = options[select.selectedIndex]?.textContent ?? "";
    items.forEach((li, i) => {
      li.setAttribute("aria-selected", String(i === select.selectedIndex));
      li.classList.toggle("is-active", i === active);
    });
    list.setAttribute("aria-activedescendant", items[active]?.id ?? "");
  };
  const open = () => {
    list.hidden = false;
    button.setAttribute("aria-expanded", "true");
    active = select.selectedIndex;
    render();
    list.tabIndex = -1;
    list.focus();
  };
  const close = (refocus = true) => {
    list.hidden = true;
    button.setAttribute("aria-expanded", "false");
    if (refocus) button.focus();
  };
  const choose = (i) => {
    if (i !== select.selectedIndex) {
      select.selectedIndex = i;
      select.dispatchEvent(new Event("change", { bubbles: true }));
    }
    close();
    render();
  };

  button.addEventListener("click", () => (list.hidden ? open() : close()));
  button.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      open();
    }
  });
  list.addEventListener("keydown", (e) => {
    const last = items.length - 1;
    const keys = { ArrowDown: Math.min(active + 1, last), ArrowUp: Math.max(active - 1, 0), Home: 0, End: last };
    if (e.key in keys) {
      e.preventDefault();
      active = keys[e.key];
      render();
    } else if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      choose(active);
    } else if (e.key === "Escape" || e.key === "Tab") {
      e.preventDefault();
      e.stopPropagation();
      close();
    } else if (e.key.length === 1) {
      clearTimeout(bufferTimer);
      buffer += e.key;
      bufferTimer = setTimeout(() => (buffer = ""), 600);
      const i = typeahead(options.map((o) => o.textContent), buffer, buffer.length > 1 ? active - 1 : active);
      if (i >= 0) {
        active = i;
        render();
      }
    }
  });
  document.addEventListener("click", (e) => {
    if (!wrap.contains(e.target) && !list.hidden) close(false);
  });

  select.classList.add("oc-select-native");
  select.tabIndex = -1;
  select.setAttribute("aria-hidden", "true");
  select.after(wrap);
  wrap.append(button, list);
  render();
}

function scan(root) {
  for (const s of root.querySelectorAll?.("select[data-oc-menu]") ?? []) upgrade(s);
}

// Native pickers are required on touch and banned on desktop.
if (typeof document !== "undefined" && window.matchMedia("(pointer: fine)").matches) {
  scan(document);
  document.addEventListener("htmx:afterSwap", (e) => scan(e.target));
}
