// DOM helpers. Everything that comes from the graph is inserted as text, never as HTML:
// host names, finding titles and notes are written by scanners and agents and are not trusted.

export function h(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "dataset") Object.assign(node.dataset, value);
    else if (key === "style") Object.assign(node.style, value);
    else if (key.startsWith("on") && typeof value === "function") node.addEventListener(key.slice(2), value);
    else if (value === true) node.setAttribute(key, "");
    else node.setAttribute(key, String(value));
  }
  append(node, children);
  return node;
}

function append(node, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
}

export function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
  return node;
}

// Replace a node's content. Unlike the native append(), this skips null and flattens lists.
export function fill(node, ...children) {
  clear(node);
  append(node, children);
  return node;
}

// Add to a node's content, with the same rules.
export function add(node, ...children) {
  append(node, children);
  return node;
}

export function toast(message, kind) {
  const item = h("div", { class: `toast ${kind || ""}`, role: kind === "error" ? "alert" : "status" }, message);
  document.getElementById("toasts").append(item);
  setTimeout(() => item.remove(), kind === "error" ? 7000 : 3500);
}

export const spinner = () => h("span", { class: "spinner", role: "status", "aria-label": "Loading" });
export const empty = (text) => h("div", { class: "empty" }, text);

// Node types → colour. Grouped by plane so the graph reads at a glance.
const TYPE_COLORS = {
  Asset: "#2f7ed8", NetworkSegment: "#5aa9e6", Software: "#7a8ba3", Finding: "#e8833a", Vulnerability: "#d64545",
  Control: "#2e9e6b", Identity: "#8b62d6", Alert: "#e0b100", Incident: "#c77d00", Indicator: "#b5536c",
  Technique: "#a23e48", ThreatActor: "#7b1f2b", BusinessService: "#4b57c9", DataStore: "#2aa6a6",
  AIAgent: "#1f9d8f", AIModel: "#58b368", Tool: "#9aa72b", Attacker: "#111827",
};
export const typeColor = (type) => TYPE_COLORS[type] || "#8794a6";

export function typeBadge(type) {
  return h("span", { class: "type" }, h("span", { class: "dot", style: { background: typeColor(type) } }), type);
}

export function entityLink(entity, onOpen) {
  if (!entity || !entity.id) return h("span", {}, entity ? entity.name : "—");
  return h("a", { href: `#/explore/${entity.id}`, title: `${entity.type} ${entity.id}`, onclick: onOpen ? (event) => { event.preventDefault(); onOpen(entity.id); } : null }, entity.name || entity.id);
}

export const fmt = {
  p(value) {
    if (value === null || value === undefined) return "—";
    if (value > 0 && value < 0.001) return "<0.1%";
    return `${(value * 100).toFixed(value < 0.1 ? 1 : 0)}%`;
  },
  n(value) { return value === null || value === undefined ? "—" : Number(value).toLocaleString("en-IN"); },
  f(value, digits = 2) { return value === null || value === undefined ? "—" : Number(value).toFixed(digits); },
  when(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return String(value);
    return date.toLocaleString(undefined, { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
  },
  value(value) {
    if (value === null || value === undefined) return "—";
    if (typeof value === "boolean") return value ? "yes" : "no";
    if (Array.isArray(value)) return value.join(", ");
    if (typeof value === "object") return JSON.stringify(value);
    return String(value);
  },
};

// Probability with its proven bounds: band from lower to upper, tick at the estimate.
export function probabilityBar(p) {
  const estimate = p.estimate ?? p.upper;
  const bar = h("div", { class: "pbar", role: "img", "aria-label": `estimate ${fmt.p(estimate)}, between ${fmt.p(p.lower)} and ${fmt.p(p.upper)}`, title: `estimate ${fmt.p(estimate)} · proven bounds ${fmt.p(p.lower)} – ${fmt.p(p.upper)}${p.method ? ` · ${p.method.replace("_", " ")}` : ""}` });
  bar.append(
    h("span", { class: "band", style: { left: `${p.lower * 100}%`, width: `${Math.max((p.upper - p.lower) * 100, 0.8)}%` } }),
    h("span", { class: "tick", style: { left: `${estimate * 100}%` } }),
  );
  return bar;
}

export function shareBar(fraction) {
  return h("div", { class: "bar" }, h("span", { style: { width: `${Math.max(0, Math.min(1, fraction)) * 100}%` } }));
}

export function table(columns, rows, { onRow, selected, emptyText } = {}) {
  if (!rows.length) return empty(emptyText || "Nothing to show.");
  const head = h("tr", {}, columns.map((c) => h("th", { class: c.num ? "num" : null, scope: "col" }, c.label)));
  const body = rows.map((row) => h("tr", {
    class: [onRow ? "clickable" : "", selected && selected(row) ? "selected" : ""].join(" ").trim() || null,
    tabindex: onRow ? 0 : null,
    onclick: onRow ? () => onRow(row) : null,
    onkeydown: onRow ? (event) => { if (event.key === "Enter") onRow(row); } : null,
  }, columns.map((c) => h("td", { class: [c.num ? "num" : "", c.wrap ? "wrap" : "", c.nowrap ? "nowrap" : ""].join(" ").trim() || null }, c.render(row)))));
  return h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, head), h("tbody", {}, body)));
}

export function card(title, body, { actions, flush } = {}) {
  return h("section", { class: `card ${flush ? "flush" : ""}` },
    title ? h("div", { class: "card-head" }, h("h2", {}, title), actions ? h("div", { class: "row" }, actions) : null) : null,
    body);
}

export function kpi(label, value, hint) {
  return h("div", { class: "card kpi" }, h("div", { class: "label" }, label), h("div", { class: "value" }, value), hint ? h("div", { class: "hint" }, hint) : null);
}

export function pageHead(title, description, actions) {
  return h("div", { class: "page-head" }, h("div", {}, h("h1", {}, title), description ? h("p", {}, description) : null), actions ? h("div", { class: "row" }, actions) : null);
}

export function tabs(items, active, onSelect) {
  return h("div", { class: "tabs", role: "tablist" }, items.map(([key, label]) => h("button", {
    type: "button", role: "tab", class: key === active ? "active" : null, "aria-selected": key === active ? "true" : "false", onclick: () => onSelect(key),
  }, label)));
}

export function confirmAction(message) {
  return window.confirm(message);
}
