// A small force-directed graph view in SVG. No dependencies.
import { typeColor } from "/assets/ui.js";

const SVG = "http://www.w3.org/2000/svg";
const svg = (tag, attrs) => {
  const node = document.createElementNS(SVG, tag);
  for (const [key, value] of Object.entries(attrs || {})) node.setAttribute(key, value);
  return node;
};

export class GraphView {
  constructor(container, { onSelect, onExpand } = {}) {
    this.container = container;
    this.onSelect = onSelect || (() => {});
    this.onExpand = onExpand || (() => {});
    this.nodes = new Map();
    this.edges = new Map();
    this.selected = null;
    this.view = { x: 0, y: 0, k: 1 };
    this.frame = null;
    this.alpha = 0;
    this.autoFit = true; // until the analyst pans, zooms or drags, keep the whole graph in view
    this.pairs = new Map();

    this.svg = svg("svg", { role: "img", "aria-label": "Graph of the selected entity and its relationships" });
    const defs = svg("defs");
    const marker = svg("marker", { id: "arrow", viewBox: "0 0 10 10", refX: "9", refY: "5", markerWidth: "6", markerHeight: "6", orient: "auto-start-reverse" });
    const tip = svg("path", { d: "M0 0 10 5 0 10z" });
    tip.style.fill = "var(--graph-edge)";
    marker.append(tip);
    defs.append(marker);
    this.root = svg("g");
    this.edgeLayer = svg("g");
    this.nodeLayer = svg("g");
    this.root.append(this.edgeLayer, this.nodeLayer);
    this.svg.append(defs, this.root);
    container.append(this.svg);
    this.bind();
  }

  bind() {
    let pan = null;
    this.svg.addEventListener("pointerdown", (event) => {
      if (event.target.closest(".vertex")) return;
      pan = { x: event.clientX, y: event.clientY, vx: this.view.x, vy: this.view.y };
      this.autoFit = false;
      this.svg.setPointerCapture(event.pointerId);
      this.svg.classList.add("dragging");
    });
    this.svg.addEventListener("pointermove", (event) => {
      if (!pan) return;
      this.view.x = pan.vx + (event.clientX - pan.x);
      this.view.y = pan.vy + (event.clientY - pan.y);
      this.applyView();
    });
    const end = () => { pan = null; this.svg.classList.remove("dragging"); };
    this.svg.addEventListener("pointerup", end);
    this.svg.addEventListener("pointercancel", end);
    this.svg.addEventListener("wheel", (event) => {
      event.preventDefault();
      this.autoFit = false;
      this.zoom(event.deltaY < 0 ? 1.12 : 1 / 1.12, event.offsetX, event.offsetY);
    }, { passive: false });
  }

  zoom(factor, cx, cy) {
    const rect = this.svg.getBoundingClientRect();
    const x = cx ?? rect.width / 2;
    const y = cy ?? rect.height / 2;
    const k = Math.min(3, Math.max(0.25, this.view.k * factor));
    this.view.x = x - ((x - this.view.x) * k) / this.view.k;
    this.view.y = y - ((y - this.view.y) * k) / this.view.k;
    this.view.k = k;
    this.applyView();
  }

  applyView() {
    this.root.setAttribute("transform", `translate(${this.view.x},${this.view.y}) scale(${this.view.k})`);
  }

  center() {
    const rect = this.svg.getBoundingClientRect();
    this.view = { x: rect.width / 2, y: rect.height / 2, k: 1 };
    this.applyView();
  }

  // Scale and move so every node and its label is visible.
  fit() {
    const rect = this.svg.getBoundingClientRect();
    if (!this.nodes.size || !rect.width || !rect.height) { this.center(); return; }
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    for (const node of this.nodes.values()) {
      minX = Math.min(minX, node.x - 16);
      minY = Math.min(minY, node.y - 18);
      maxX = Math.max(maxX, node.x + 16 + node.labelWidth);
      maxY = Math.max(maxY, node.y + 18);
    }
    const margin = 24;
    const k = Math.min(1.15, Math.max(0.25, Math.min((rect.width - 2 * margin) / (maxX - minX), (rect.height - 2 * margin) / (maxY - minY))));
    this.view = { k, x: rect.width / 2 - ((minX + maxX) / 2) * k, y: rect.height / 2 - ((minY + maxY) / 2) * k };
    this.applyView();
  }

  clear() {
    this.nodes.clear();
    this.edges.clear();
    this.pairs.clear();
    this.edgeLayer.replaceChildren();
    this.nodeLayer.replaceChildren();
    this.selected = null;
    this.autoFit = true;
  }

  // Add nodes and edges; existing ones are kept where they are.
  add(nodes, edges, anchorId) {
    const anchor = anchorId ? this.nodes.get(anchorId) : null;
    let index = 0;
    for (const data of nodes) {
      if (this.nodes.has(data.id)) continue;
      const angle = (index++ / Math.max(nodes.length, 1)) * Math.PI * 2;
      const node = {
        data, vx: 0, vy: 0, pinned: false,
        x: (anchor ? anchor.x : 0) + Math.cos(angle) * 140 + (Math.random() - 0.5) * 20,
        y: (anchor ? anchor.y : 0) + Math.sin(angle) * 140 + (Math.random() - 0.5) * 20,
      };
      if (!anchor && data.id === anchorId) { node.x = 0; node.y = 0; }
      node.element = this.drawNode(node);
      this.nodes.set(data.id, node);
    }
    for (const data of edges) {
      if (this.edges.has(data.id) || !this.nodes.has(data.source) || !this.nodes.has(data.target)) continue;
      const line = svg("line", { class: "edge", "marker-end": "url(#arrow)" });
      // Several relationships between the same two entities share one label.
      const pairKey = [data.source, data.target].sort().join("|");
      let pair = this.pairs.get(pairKey);
      if (!pair) {
        pair = { types: [], label: svg("text", { class: "edge-label", "text-anchor": "middle" }) };
        this.pairs.set(pairKey, pair);
        this.edgeLayer.append(pair.label);
      }
      if (!pair.types.includes(data.type)) pair.types.push(data.type);
      pair.label.textContent = pair.types.join(" · ");
      this.edgeLayer.prepend(line);
      this.edges.set(data.id, { data, line, label: pair.label });
    }
    this.kick();
  }

  drawNode(node) {
    const group = svg("g", { class: `vertex${node.data.stub ? " stub" : ""}`, tabindex: "0", role: "button" });
    group.setAttribute("aria-label", `${node.data.type} ${node.data.name}`);
    const circle = svg("circle", { r: "9" });
    circle.style.fill = typeColor(node.data.type);
    const label = svg("text", { x: "13", y: "4" });
    const name = String(node.data.name || node.data.id);
    label.textContent = name.length > 28 ? `${name.slice(0, 27)}…` : name;
    node.labelWidth = label.textContent.length * 6.2;
    const title = svg("title");
    title.textContent = `${node.data.type}: ${name}`;
    group.append(title, circle, label);
    this.nodeLayer.append(group);

    let drag = null;
    group.addEventListener("pointerdown", (event) => {
      event.stopPropagation();
      drag = { x: event.clientX, y: event.clientY, nx: node.x, ny: node.y, moved: false };
      this.autoFit = false;
      group.setPointerCapture(event.pointerId);
    });
    group.addEventListener("pointermove", (event) => {
      if (!drag) return;
      const dx = (event.clientX - drag.x) / this.view.k;
      const dy = (event.clientY - drag.y) / this.view.k;
      if (Math.abs(dx) + Math.abs(dy) > 3) drag.moved = true;
      node.x = drag.nx + dx;
      node.y = drag.ny + dy;
      node.pinned = true;
      this.kick(0.3);
    });
    group.addEventListener("pointerup", () => {
      if (drag && !drag.moved) this.select(node.data.id, true);
      drag = null;
    });
    group.addEventListener("dblclick", () => this.onExpand(node.data.id));
    group.addEventListener("keydown", (event) => {
      if (event.key === "Enter") this.select(node.data.id, true);
      if (event.key === " ") { event.preventDefault(); this.onExpand(node.data.id); }
    });
    return group;
  }

  select(id, notify) {
    this.selected = id;
    for (const [nodeId, node] of this.nodes) node.element.classList.toggle("selected", nodeId === id);
    if (notify) this.onSelect(id);
  }

  kick(alpha = 1) {
    this.alpha = Math.max(this.alpha, alpha);
    if (!this.frame) this.frame = requestAnimationFrame(() => this.tick());
  }

  tick() {
    this.frame = null;
    const nodes = [...this.nodes.values()];
    const count = nodes.length;
    // repulsion (all pairs: the view is capped at a few hundred nodes)
    for (let i = 0; i < count; i++) {
      const a = nodes[i];
      for (let j = i + 1; j < count; j++) {
        const b = nodes[j];
        let dx = a.x - b.x;
        let dy = a.y - b.y;
        let d2 = dx * dx + dy * dy;
        if (d2 < 0.01) { dx = Math.random() - 0.5; dy = Math.random() - 0.5; d2 = 1; }
        const force = Math.min(9000 / d2, 14);
        const d = Math.sqrt(d2);
        const fx = (dx / d) * force;
        const fy = (dy / d) * force;
        a.vx += fx; a.vy += fy; b.vx -= fx; b.vy -= fy;
      }
    }
    // springs
    for (const edge of this.edges.values()) {
      const a = this.nodes.get(edge.data.source);
      const b = this.nodes.get(edge.data.target);
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const d = Math.sqrt(dx * dx + dy * dy) || 1;
      const force = (d - 150) * 0.02;
      const fx = (dx / d) * force;
      const fy = (dy / d) * force;
      a.vx += fx; a.vy += fy; b.vx -= fx; b.vy -= fy;
    }
    let energy = 0;
    for (const node of nodes) {
      node.vx -= node.x * 0.002; // gentle pull to the centre
      node.vy -= node.y * 0.003;
      node.vx *= 0.82;
      node.vy *= 0.82;
      if (!node.pinned) {
        node.x += node.vx * this.alpha;
        node.y += node.vy * this.alpha;
      }
      energy += node.vx * node.vx + node.vy * node.vy;
    }
    this.draw();
    if (this.autoFit) this.fit();
    this.alpha *= 0.985;
    if (this.alpha > 0.02 && energy > 0.02) this.frame = requestAnimationFrame(() => this.tick());
    else this.alpha = 0;
  }

  draw() {
    for (const node of this.nodes.values()) node.element.setAttribute("transform", `translate(${node.x},${node.y})`);
    for (const edge of this.edges.values()) {
      const a = this.nodes.get(edge.data.source);
      const b = this.nodes.get(edge.data.target);
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const d = Math.sqrt(dx * dx + dy * dy) || 1;
      const pad = 11;
      edge.line.setAttribute("x1", a.x + (dx / d) * pad);
      edge.line.setAttribute("y1", a.y + (dy / d) * pad);
      edge.line.setAttribute("x2", b.x - (dx / d) * (pad + 2));
      edge.line.setAttribute("y2", b.y - (dy / d) * (pad + 2));
      edge.label.setAttribute("x", (a.x + b.x) / 2);
      edge.label.setAttribute("y", (a.y + b.y) / 2 - 3);
      edge.label.style.display = this.edges.size > 40 ? "none" : "";
    }
  }

  destroy() {
    if (this.frame) cancelAnimationFrame(this.frame);
    this.frame = null;
  }
}
