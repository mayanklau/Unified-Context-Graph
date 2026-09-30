// Security Graph console.
import { ApiError, api, del, get, patch, post, session, setUnauthorizedHandler } from "/assets/api.js";
import { GraphView } from "/assets/graphview.js";
import {
  card, clear, confirmAction, empty, entityLink, fill, fmt, h, kpi, pageHead, probabilityBar, shareBar, spinner, table,
  tabs, toast, typeBadge, typeColor,
} from "/assets/ui.js";

const main = document.getElementById("main");
const state = { me: null, ontology: null, view: null, graph: null };
const can = (permission) => Boolean(state.me && state.me.permissions.includes(permission));
const fullGraph = () => Boolean(state.me && state.me.node_types === null);

const SECTIONS = [
  { id: "overview", label: "Overview", show: () => can("graph:read") },
  { id: "explore", label: "Explore", show: () => can("graph:read") },
  { id: "paths", label: "Attack paths", show: () => can("analytics:read") && fullGraph() },
  { id: "priorities", label: "Fix first", show: () => can("analytics:read") && fullGraph() },
  { id: "memory", label: "Memory", show: () => can("memory:read") },
  { id: "data", label: "Data quality", show: () => can("graph:curate") || can("graph:write") },
  { id: "admin", label: "Administration", show: () => can("admin:keys") || can("admin:users") || can("audit:read") },
  { id: "model", label: "Model", show: () => can("graph:read") },
];

// ---------------------------------------------------------------------------
// Shell
// ---------------------------------------------------------------------------
function applyTheme(theme) {
  if (theme) document.documentElement.dataset.theme = theme;
  else delete document.documentElement.dataset.theme;
}
function initTheme() {
  let stored = null;
  try { stored = localStorage.getItem("secgraph.theme"); } catch { /* ignore */ }
  applyTheme(stored);
  document.getElementById("theme").addEventListener("click", () => {
    const dark = document.documentElement.dataset.theme
      ? document.documentElement.dataset.theme === "dark"
      : window.matchMedia("(prefers-color-scheme: dark)").matches;
    const next = dark ? "light" : "dark";
    applyTheme(next);
    try { localStorage.setItem("secgraph.theme", next); } catch { /* ignore */ }
  });
}

function showLogin(message) {
  document.getElementById("shell").hidden = true;
  document.getElementById("login").hidden = false;
  const error = document.getElementById("login-error");
  error.hidden = !message;
  error.textContent = message || "";
}

function initLogin() {
  const form = document.getElementById("login-form");
  let mode = "password";
  for (const button of form.querySelectorAll("[data-mode]")) {
    button.addEventListener("click", () => {
      mode = button.dataset.mode;
      for (const other of form.querySelectorAll("[data-mode]")) other.classList.toggle("active", other === button);
      for (const pane of form.querySelectorAll("[data-pane]")) pane.hidden = pane.dataset.pane !== mode;
    });
  }
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    const submit = form.querySelector("button[type=submit]");
    submit.disabled = true;
    try {
      if (mode === "key") {
        session.set({ kind: "key", value: String(data.get("apikey") || "").trim() });
      } else {
        const result = await api("POST", "/api/v1/auth/token", {
          body: { username: String(data.get("username") || ""), password: String(data.get("password") || "") },
        });
        session.set({ kind: "token", value: result.access_token });
      }
      await start();
      form.reset();
    } catch (error) {
      session.clear();
      showLogin(error instanceof ApiError && error.status === 401 ? "Those credentials were not accepted." : error.message);
    } finally {
      submit.disabled = false;
    }
  });
  document.getElementById("logout").addEventListener("click", () => {
    session.clear();
    state.me = null;
    showLogin();
  });
}

async function start() {
  state.me = await get("/api/v1/auth/me");
  state.ontology = can("graph:read") ? await get("/api/v1/ontology") : null;
  document.getElementById("login").hidden = true;
  document.getElementById("shell").hidden = false;
  fill(document.getElementById("whoami"),
    h("div", {}, h("strong", {}, state.me.name)),
    h("div", {}, `${state.me.roles.join(", ") || "no roles"} · tenant ${state.me.tenant}`),
  );
  const nav = clear(document.getElementById("nav"));
  for (const section of SECTIONS.filter((s) => s.show())) {
    nav.append(h("a", { href: `#/${section.id}`, dataset: { section: section.id } }, section.label));
  }
  if (!location.hash || location.hash === "#/") location.hash = `#/${(SECTIONS.find((s) => s.show()) || SECTIONS[0]).id}`;
  else route();
}

async function route() {
  if (!state.me) return;
  const [section, ...rest] = location.hash.replace(/^#\/?/, "").split("?")[0].split("/");
  const known = SECTIONS.find((s) => s.id === section && s.show());
  if (!known) { location.hash = `#/${(SECTIONS.find((s) => s.show()) || SECTIONS[0]).id}`; return; }
  for (const link of document.querySelectorAll("#nav a")) {
    const active = link.dataset.section === section;
    link.classList.toggle("active", active);
    if (active) link.setAttribute("aria-current", "page"); else link.removeAttribute("aria-current");
  }
  if (state.graph) { state.graph.destroy(); state.graph = null; }
  const token = Symbol(section);
  state.view = token;
  main.dataset.section = section;
  main.setAttribute("aria-busy", "true");
  fill(main, h("p", { class: "muted" }, spinner(), " Loading…"));
  try {
    const content = await VIEWS[section](rest.map(decodeURIComponent));
    if (state.view !== token) return;
    fill(main, content);
    main.focus({ preventScroll: true });
  } catch (error) {
    if (state.view !== token) return;
    fill(main, pageHead(known.label), h("div", { class: "callout danger" }, error.message));
  }
  main.setAttribute("aria-busy", "false");
}

async function guarded(action, success) {
  try {
    const result = await action();
    if (success) toast(success);
    return result;
  } catch (error) {
    toast(error.message, "error");
    return undefined;
  }
}

// Opening an entity keeps the search that found it.
const openEntity = (id) => {
  const query = location.hash.startsWith("#/explore") ? location.hash.split("?")[1] || "" : "";
  location.hash = `#/explore/${id}${query ? `?${query}` : ""}`;
};

// ---------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------
async function overviewView() {
  const analytics = can("analytics:read") && fullGraph();
  const [stats, overview] = await Promise.all([
    get("/api/v1/stats"),
    analytics ? get("/api/v1/analytics/overview", { limit: 12 }).catch((error) => ({ error: error.message })) : null,
  ]);
  const page = h("div", {}, pageHead("Overview", "What is in the graph, and how exposed the things that matter are."));
  if (!stats.node_total) {
    page.append(h("div", { class: "callout" },
      h("strong", {}, "The graph is empty. "),
      "Load data from the Data quality page, the API, or run ", h("code", {}, "secgraph seed-demo"),
      " on the server to load a demonstration estate."));
    return page;
  }
  const kpis = h("div", { class: "grid kpis" },
    kpi("Entities", fmt.n(stats.node_total), `${Object.keys(stats.nodes).length} types`),
    kpi("Relationships", fmt.n(stats.edge_total), `${Object.keys(stats.edges).length} types`));
  page.append(kpis);
  if (overview && !overview.error) {
    const risk = overview.risk;
    kpis.append(
      kpi("Entry points", fmt.n(overview.entry_points), "where an outside attacker can start"),
      kpi("Crown jewels at risk", `${overview.targets_at_risk} / ${overview.targets}`, "reachable by some attack path"),
      kpi("Expected impact", fmt.f(risk.estimate ?? risk.upper, 1), `of ${fmt.f(overview.total_impact, 0)} · bounds ${fmt.f(risk.lower, 1)}–${fmt.f(risk.upper, 1)}`),
      kpi("Open findings", fmt.n(overview.exposure.open_findings), `${overview.exposure.known_exploited} known-exploited · ${overview.exposure.risk_accepted} risk-accepted`),
    );
  }
  const grid = h("div", { class: "grid two" });
  if (overview && !overview.error) {
    grid.append(card("Most exposed crown jewels", table([
      { label: "Target", render: (t) => entityLink(t) },
      { label: "Type", render: (t) => typeBadge(t.type) },
      { label: "Impact", num: true, render: (t) => fmt.f(t.impact, 0) },
      { label: "Compromise probability", render: (t) => h("div", { class: "pcell" }, probabilityBar(t.probability), h("span", { class: "num" }, fmt.p(t.probability.estimate ?? t.probability.upper))) },
      { label: "Expected", num: true, render: (t) => fmt.f(t.expected_impact, 1) },
    ], overview.top_targets, { onRow: (t) => { location.hash = `#/paths/${t.id}`; }, emptyText: "No crown jewels are defined yet." }), { flush: true }));
  } else if (overview && overview.error) {
    grid.append(card("Attack model", h("div", { class: "callout warn" }, overview.error)));
  }
  const counts = Object.entries(stats.nodes).sort((a, b) => b[1] - a[1]);
  const max = counts.length ? counts[0][1] : 1;
  grid.append(card("Entities by type", table([
    { label: "Type", render: ([type]) => h("a", { href: `#/explore?type=${type}` }, typeBadge(type)) },
    { label: "Count", num: true, render: ([, count]) => fmt.n(count) },
    { label: "", render: ([, count]) => shareBar(count / max) },
  ], counts), { flush: true }));
  page.append(grid);
  return page;
}

// ---------------------------------------------------------------------------
// Explore
// ---------------------------------------------------------------------------
async function exploreView(args) {
  const [first] = args;
  const query = new URLSearchParams((location.hash.split("?")[1] || ""));
  const selectedId = first || null;
  const page = h("div", {}, pageHead("Explore", "Search the graph, open an entity, and walk its relationships."));
  const types = Object.keys(state.ontology.node_types).filter((t) => state.me.node_types === null || state.me.node_types.includes(t));
  const search = h("input", { type: "search", placeholder: "Name, host, IP, CVE, account…", "aria-label": "Search", value: query.get("q") || "" });
  const typeSelect = h("select", { "aria-label": "Type" }, h("option", { value: "" }, "All types"), types.map((t) => h("option", { value: t, selected: query.get("type") === t }, t)));
  const results = h("div", { class: "scroll" });
  const detail = h("div", {}, selectedId ? h("p", { class: "muted" }, spinner(), " Loading…") : empty("Select an entity to see its details and relationships."));

  async function runSearch() {
    fill(results, h("p", { class: "muted", style: { padding: "12px 16px" } }, spinner(), " Searching…"));
    const text = search.value.trim();
    try {
      let items = [];
      let total = 0;
      if (text) {
        const exact = await get("/api/v1/lookup", { value: text });
        items = exact.items.filter((i) => !typeSelect.value || i.type === typeSelect.value);
      }
      const found = await get("/api/v1/nodes", { q: text || null, type: typeSelect.value || null, limit: 50 });
      const seen = new Set(items.map((i) => i.id));
      items = items.concat(found.items.filter((i) => !seen.has(i.id)));
      total = Math.max(found.total, items.length);
      fill(results, 
        table([
          { label: "Name", wrap: true, render: (n) => h("span", {}, n.name, n.stub ? h("span", { class: "chip", style: { marginLeft: "6px" } }, "stub") : null) },
          { label: "Type", render: (n) => typeBadge(n.type) },
        ], items, { onRow: (n) => openEntity(n.id), selected: (n) => n.id === selectedId, emptyText: "No entity matches." }),
        total > items.length ? h("p", { class: "muted small", style: { padding: "8px 12px", margin: 0 } }, `Showing ${items.length} of ${fmt.n(total)}. Narrow the search to see others.`) : null,
      );
    } catch (error) {
      fill(results, h("div", { class: "callout danger", style: { margin: "12px" } }, error.message));
    }
  }
  function rememberSearch() {
    const params = new URLSearchParams();
    if (search.value.trim()) params.set("q", search.value.trim());
    if (typeSelect.value) params.set("type", typeSelect.value);
    const text = params.toString();
    history.replaceState(null, "", `#/explore${selectedId ? `/${selectedId}` : ""}${text ? `?${text}` : ""}`);
  }
  const form = h("form", { class: "row", onsubmit: (event) => { event.preventDefault(); rememberSearch(); runSearch(); } },
    h("div", { class: "grow" }, search), typeSelect, h("button", { class: "button primary", type: "submit" }, "Search"));
  search.style.width = "100%";
  page.append(h("div", { class: "grid split" },
    h("div", { class: "grid" }, card(null, form), card("Results", results, { flush: true })),
    detail));
  runSearch();
  if (selectedId) renderEntity(detail, selectedId);
  return page;
}

async function renderEntity(container, id) {
  let node;
  try {
    node = await get(`/api/v1/nodes/${id}`);
  } catch (error) {
    fill(container, h("div", { class: "callout danger" }, error.message));
    return;
  }
  let active = "graph";
  const body = h("div", {});
  const header = h("div", { class: "card" },
    h("div", { class: "spread" },
      h("div", {}, h("div", { class: "muted small" }, typeBadge(node.type)), h("h1", {}, node.name)),
      h("div", { class: "row" },
        node.stub ? h("span", { class: "chip warn", title: "Only referenced by other records; no source has described it yet" }, "stub") : null,
        h("span", { class: "chip" }, `v${node.version}`),
        h("code", { class: "muted", title: "Graph id" }, node.id))),
    node.requested_id ? h("p", { class: "muted small", style: { marginTop: "6px" } }, `The entity you asked for (${node.requested_id}) was merged into this one.`) : null);
  const tabItems = [["graph", "Graph"], ["details", "Details"], ["relations", "Relationships"], ["history", "History"], ["context", "Context pack"]];
  if (can("analytics:read") && fullGraph() && state.ontology.attack_semantics.compromisable.includes(node.type)) tabItems.splice(1, 0, ["exposure", "Exposure"]);
  const tabBar = h("div", {});
  const drawTabs = () => fill(tabBar, tabs(tabItems, active, (key) => { active = key; drawTabs(); show(); }));

  async function show() {
    if (state.graph) { state.graph.destroy(); state.graph = null; }
    fill(body, h("p", { class: "muted" }, spinner(), " Loading…"));
    try {
      const content = await ENTITY_TABS[active](node);
      fill(body, content);
    } catch (error) {
      fill(body, h("div", { class: "callout danger" }, error.message));
    }
  }
  drawTabs();
  fill(container, h("div", { class: "grid" }, header, h("div", { class: "card" }, tabBar, body)));
  show();
}

const ENTITY_TABS = {
  async graph(node) {
    const holder = h("div", { class: "graph" });
    const info = h("p", { class: "muted small", style: { marginTop: "8px" } }, "Click a node to open it · double-click to expand its neighbours · drag to arrange · scroll to zoom.");
    const legendTypes = new Set();
    const legend = h("div", { class: "legend" });
    const view = new GraphView(holder, {
      onSelect: (id) => { if (id !== node.id) openEntity(id); },
      onExpand: (id) => expand(id),
    });
    state.graph = view;
    holder.append(h("div", { class: "graph-tools" },
      h("button", { class: "button small", type: "button", "aria-label": "Zoom in", onclick: () => view.zoom(1.25) }, "+"),
      h("button", { class: "button small", type: "button", "aria-label": "Zoom out", onclick: () => view.zoom(0.8) }, "−"),
      h("button", { class: "button small", type: "button", onclick: () => { view.autoFit = true; view.fit(); } }, "Fit")));
    async function expand(id) {
      const data = await guarded(() => post("/api/v1/query/subgraph", { seeds: [id], depth: 1, max_nodes: 60 }));
      if (!data) return;
      view.autoFit = true;
      view.add(data.nodes, data.edges, id);
      for (const n of data.nodes) legendTypes.add(n.type);
      fill(legend, [...legendTypes].sort().map((t) => typeBadge(t)));
      if (data.truncated) info.textContent = "Only part of the neighbourhood is shown: this entity has many relationships. Use the Relationships tab for the full list.";
    }
    requestAnimationFrame(async () => { view.center(); await expand(node.id); view.select(node.id, false); });
    return h("div", {}, holder, legend, info);
  },

  async details(node) {
    const props = Object.entries(node.properties).sort(([a], [b]) => a.localeCompare(b));
    const identifiers = Object.entries(node.identifiers || {});
    return h("div", { class: "grid" },
      h("div", {}, h("h3", {}, "Properties"), props.length
        ? h("dl", { class: "props" }, props.map(([key, value]) => [h("dt", {}, key), h("dd", {}, fmt.value(value))]))
        : h("p", { class: "muted" }, "No properties recorded.")),
      h("div", {}, h("h3", {}, "Identifiers"), identifiers.length
        ? h("dl", { class: "props" }, identifiers.map(([kind, values]) => [h("dt", {}, kind), h("dd", { class: "mono" }, values.join(", "))]))
        : h("p", { class: "muted" }, "None.")),
      h("div", {}, h("h3", {}, "Provenance"), h("dl", { class: "props" },
        h("dt", {}, "First seen"), h("dd", {}, fmt.when(node.first_seen)),
        h("dt", {}, "Last seen"), h("dd", {}, fmt.when(node.last_seen)),
        h("dt", {}, "Sources"), h("dd", {}, Object.entries(node.sources || {}).map(([source, when]) => h("span", { class: "chip", style: { marginRight: "4px" }, title: `last reported ${fmt.when(when)}` }, source))),
        h("dt", {}, "Confidence"), h("dd", {}, fmt.f(node.confidence, 2)))));
  },

  async exposure(node) {
    const e = await get(`/api/v1/analytics/nodes/${node.id}/exposure`);
    const p = e.compromise_probability;
    const out = h("div", { class: "grid" });
    out.append(h("div", { class: "grid kpis", style: { marginBottom: 0 } },
      kpi("Compromise probability", fmt.p(p.estimate), `proven bounds ${fmt.p(p.lower)} – ${fmt.p(p.upper)}`),
      kpi("Entry point", e.is_entry_point ? "Yes" : "No", "reachable directly from outside"),
      kpi("Crown jewels reachable", fmt.n(e.targets_reachable_count), "from here, if compromised"),
      kpi("Detection per attempt", fmt.p(e.detection_per_attempt), "from detective controls")));
    out.append(h("div", {}, h("h3", {}, `Open findings (${e.open_finding_count})`), table([
      { label: "Finding", wrap: true, render: (f) => h("a", { href: `#/explore/${f.finding_id}` }, f.vulnerability || f.title) },
      { label: "Exploit probability", num: true, render: (f) => fmt.p(f.probability) },
      { label: "Basis", render: (f) => f.basis.replace("_", " ") },
      { label: "Flags", render: (f) => h("div", { class: "row" },
        f.kev ? h("span", { class: "chip danger" }, "known-exploited") : null,
        f.status === "risk_accepted" ? h("span", { class: "chip warn" }, `risk accepted${f.exception_until ? ` until ${f.exception_until.slice(0, 10)}` : ""}`) : null,
        !f.remotely_exploitable ? h("span", { class: "chip" }, "local only") : null,
        (f.compensating_controls || []).map((c) => h("span", { class: "chip ok" }, `compensated: ${c.control_type}`))) },
    ], e.open_findings, { emptyText: "No open findings." })));
    out.append(h("div", {}, h("h3", {}, "Controls"), e.controls.length
      ? h("div", { class: "row" }, e.controls.map((c) => h("a", { class: "chip ok", href: `#/explore/${c.id}`, title: c.name }, `${c.control_type} · ${fmt.p(c.effectiveness)}`)))
      : h("p", { class: "muted" }, "No controls are recorded as protecting this entity.")));
    if (e.most_likely_path) out.append(h("div", {}, h("h3", {}, `Most likely path to here (${fmt.p(e.most_likely_path.probability)})`), renderPath(e.most_likely_path)));
    if (e.targets_reachable.length) {
      out.append(h("div", {}, h("h3", {}, "Crown jewels reachable from here"), table([
        { label: "Target", render: (t) => entityLink(t) },
        { label: "Type", render: (t) => typeBadge(t.type) },
        { label: "Impact", num: true, render: (t) => fmt.f(t.impact, 0) },
        { label: "Path probability", num: true, render: (t) => fmt.p(t.path_probability) },
      ], e.targets_reachable)));
    }
    return out;
  },

  async relations(node) {
    const data = await get(`/api/v1/nodes/${node.id}/neighbors`, { limit: 500 });
    const rows = data.neighbors.slice().sort((a, b) => a.edge.type.localeCompare(b.edge.type) || a.node.name.localeCompare(b.node.name));
    return h("div", {},
      data.truncated ? h("div", { class: "callout warn" }, "Only the 500 most recently observed relationships are listed.") : null,
      table([
        { label: "Relationship", nowrap: true, render: (r) => h("code", {}, r.direction === "out" ? `${r.edge.type} →` : `← ${r.edge.type}`) },
        { label: "Entity", wrap: true, render: (r) => entityLink(r.node) },
        { label: "Type", render: (r) => typeBadge(r.node.type) },
        { label: "Properties", wrap: true, render: (r) => h("span", { class: "muted small" }, Object.entries(r.edge.properties).map(([k, v]) => `${k}=${fmt.value(v)}`).join(" · ")) },
      ], rows, { emptyText: "No relationships." }));
  },

  async history(node) {
    const data = await get(`/api/v1/nodes/${node.id}/history`);
    return table([
      { label: "Version", num: true, render: (v) => v.version },
      { label: "From", nowrap: true, render: (v) => fmt.when(v.valid_from) },
      { label: "Until", nowrap: true, render: (v) => (v.valid_to ? fmt.when(v.valid_to) : h("span", { class: "chip ok" }, "current")) },
      { label: "Changed by", render: (v) => v.changed_by || "—" },
      { label: "State", wrap: true, render: (v) => (v.deleted ? h("span", { class: "chip danger" }, "deleted") : h("span", { class: "muted small" }, Object.entries(v.properties).map(([k, val]) => `${k}=${fmt.value(val)}`).join(" · ") || "no properties")) },
    ], data.versions);
  },

  async context(node) {
    const budget = h("select", { "aria-label": "Token budget" }, [500, 1000, 2000, 4000, 8000].map((n) => h("option", { value: n, selected: n === 2000 }, `${n} tokens`)));
    const output = h("pre", {});
    const meta = h("span", { class: "muted small" });
    async function load() {
      output.textContent = "Loading…";
      try {
        const pack = await get(`/api/v1/context/${node.id}`, { budget_tokens: budget.value });
        output.textContent = pack.text;
        meta.textContent = `≈ ${pack.token_estimate} tokens${pack.truncated ? " · truncated to fit the budget" : ""}`;
      } catch (error) { output.textContent = error.message; }
    }
    budget.addEventListener("change", load);
    load();
    return h("div", {},
      h("p", { class: "muted" }, "What an agent receives when it asks for this entity: a briefing in priority order that stops at the token budget."),
      h("div", { class: "row", style: { marginBottom: "8px" } }, budget, meta,
        h("button", { class: "button small", type: "button", onclick: () => navigator.clipboard && navigator.clipboard.writeText(output.textContent).then(() => toast("Copied")) }, "Copy")),
      output);
  },
};

// ---------------------------------------------------------------------------
// Attack paths
// ---------------------------------------------------------------------------
function renderPath(path) {
  const steps = [];
  const first = path.steps[0];
  steps.push(h("div", { class: "step" },
    h("div", { class: "rail" }, h("span", { class: "node", style: { background: typeColor(first.from.type) } }), h("span", { class: "line" })),
    h("div", { class: "body" }, h("strong", {}, first.from.id ? entityLink(first.from) : first.from.name), " ", h("span", { class: "muted small" }, first.from.type))));
  path.steps.forEach((step, index) => {
    const last = index === path.steps.length - 1;
    const basis = step.basis;
    const evidence = [];
    if (basis.model === "exploitability") {
      for (const f of basis.findings || []) {
        evidence.push(h("li", {}, h("a", { href: `#/explore/${f.finding_id}` }, f.vulnerability || f.title), ` — exploit ${fmt.p(f.probability)} by ${f.basis.replace("_", " ")}`,
          f.kev ? h("span", { class: "chip danger", style: { marginLeft: "6px" } }, "known-exploited") : null,
          f.status === "risk_accepted" ? h("span", { class: "chip warn", style: { marginLeft: "6px" } }, "risk accepted") : null,
          (f.compensating_controls || []).map((c) => h("span", { class: "chip ok", style: { marginLeft: "6px" } }, `compensated: ${c.control_type}`))));
      }
      if (!evidence.length) evidence.push(h("li", {}, `No known exploitable finding; residual probability ${fmt.p(basis.floor)} for an exposed service.`));
      if (basis.finding_count > (basis.findings || []).length) evidence.push(h("li", { class: "muted" }, `… and ${basis.finding_count - basis.findings.length} more findings`));
    } else if (basis.base !== null && basis.base !== undefined) {
      evidence.push(h("li", {}, `Base probability ${fmt.p(basis.base)}${basis.property ? ` (from ${basis.property})` : ""}`));
    }
    steps.push(h("div", { class: "step" },
      h("div", { class: "rail" }, h("span", { class: "node", style: { background: typeColor(step.to.type) } }), last ? null : h("span", { class: "line" })),
      h("div", { class: "body" },
        h("div", {}, h("strong", {}, entityLink(step.to)), " ", h("span", { class: "muted small" }, step.to.type),
          step.to.impact ? h("span", { class: "chip accent", style: { marginLeft: "6px" } }, `crown jewel · impact ${fmt.f(step.to.impact, 0)}`) : null),
        h("div", { class: "move" },
          h("div", { class: "head" }, h("span", { class: "chip danger" }, fmt.p(step.probability)), h("code", {}, step.technique), h("span", { class: "muted small" }, step.description)),
          evidence.length ? h("ul", { class: "small" }, evidence) : null,
          step.controls_applied.length ? h("div", { class: "row small", style: { marginTop: "6px" } }, h("span", { class: "muted" }, "In place:"), step.controls_applied.map((c) => h("span", { class: "chip ok", title: c.name }, `${c.control_type} −${fmt.p(c.effectiveness)}`))) : null,
          step.recommended_controls.length ? h("div", { class: "row small", style: { marginTop: "6px" } }, h("span", { class: "muted" }, "Would reduce this step:"), step.recommended_controls.map((c) => h("span", { class: "chip" }, c.replace(/_/g, " ")))) : null))));
  });
  return h("div", { class: "path" }, steps);
}

async function pathsView(args) {
  const targetId = args[0] || null;
  const data = await get("/api/v1/analytics/attack-paths", targetId ? { target_id: targetId, k: 5 } : { limit: 15 });
  const page = h("div", {}, pageHead("Attack paths",
    targetId ? "The most probable routes to this target, best first. Every step shows the evidence behind its probability."
      : "The single most probable route to each crown jewel, ranked by probability × impact. Select one to see its steps.",
    targetId ? h("a", { class: "button", href: "#/paths" }, "All crown jewels") : null));
  if (!data.paths.length) {
    page.append(h("div", { class: "callout" }, targetId ? "No attack path reaches this target." : "No attack path reaches any crown jewel. Either nothing is exposed, or entry points and crown jewels are not yet marked (see the Model page)."));
    return page;
  }
  let selected = 0;
  const detail = h("div", {});
  const list = h("div", {});
  function draw() {
    fill(list, table([
      { label: "#", num: true, render: (p) => p.rank },
      { label: "Target", wrap: true, render: (p) => h("span", {}, p.target.name) },
      { label: "Type", render: (p) => typeBadge(p.target.type) },
      { label: "Path", num: true, render: (p) => fmt.p(p.probability) },
      { label: "Steps", num: true, render: (p) => p.length },
      { label: "Risk", num: true, render: (p) => (p.risk === null ? "—" : fmt.f(p.risk, 2)) },
    ], data.paths, { onRow: (p) => { selected = data.paths.indexOf(p); draw(); }, selected: (p) => data.paths.indexOf(p) === selected }));
    const path = data.paths[selected];
    const c = path.target_compromise;
    fill(detail, card(`To ${path.target.name}`, h("div", {},
      h("div", { class: "row", style: { marginBottom: "12px" } },
        h("span", { class: "chip danger" }, `this path ${fmt.p(path.probability)}`),
        c ? h("span", { class: "chip", title: "All routes combined: estimate with proven bounds" }, `all routes ${fmt.p(c.estimate)} (${fmt.p(c.lower)}–${fmt.p(c.upper)})`) : null,
        !targetId ? h("a", { class: "button small", href: `#/paths/${path.target.id}` }, "Other routes to this target") : null,
        h("a", { class: "button small", href: `#/explore/${path.target.id}` }, "Open target")),
      renderPath(path))));
  }
  draw();
  page.append(h("div", { class: "grid split" }, card(targetId ? "Routes" : "Crown jewels", list, { flush: true }), detail));
  page.append(h("p", { class: "muted small", style: { marginTop: "12px" } }, data.note));
  return page;
}

// ---------------------------------------------------------------------------
// Fix first
// ---------------------------------------------------------------------------
async function prioritiesView(args) {
  const by = ["finding", "vulnerability", "asset"].includes(args[0]) ? args[0] : "vulnerability";
  const [priorities, chokes, race] = await Promise.all([
    get("/api/v1/analytics/remediation-priorities", { by, limit: 25 }),
    get("/api/v1/analytics/choke-points", { limit: 10 }),
    get("/api/v1/analytics/detection-race"),
  ]);
  const page = h("div", {}, pageHead("Fix first", "Each candidate fix is scored by recomputing the attack graph as if it had been applied. The number is the share of crown-jewel risk it removes."));
  const switcher = h("div", { class: "segmented" }, [["vulnerability", "By vulnerability"], ["finding", "By finding"], ["asset", "By asset"]].map(([key, label]) =>
    h("button", { type: "button", class: key === by ? "active" : null, onclick: () => { location.hash = `#/priorities/${key}`; } }, label)));
  const max = priorities.items.length ? priorities.items[0].risk_reduction : 1;
  const label = (item) => {
    if (by === "finding") return h("a", { href: `#/explore/${item.key}` }, item.finding.vulnerability || item.finding.title);
    if (by === "vulnerability") return item.vulnerability_id ? h("a", { href: `#/explore/${item.vulnerability_id}` }, item.vulnerability) : item.vulnerability;
    return entityLink(item.assets[0]);
  };
  page.append(card("Remediation priorities", h("div", {},
    priorities.partial ? h("div", { class: "callout warn", style: { margin: "12px" } }, `Only ${priorities.evaluated} of ${priorities.candidates} candidates were evaluated within the time budget.`) : null,
    table([
      { label: by === "asset" ? "Asset" : by === "finding" ? "Finding" : "Vulnerability", wrap: true, render: (i) => h("span", {}, label(i), i.known_exploited ? h("span", { class: "chip danger", style: { marginLeft: "6px" } }, "known-exploited") : null) },
      { label: "On", wrap: true, render: (i) => (by === "asset" ? `${i.findings} findings` : h("span", {}, entityLink(i.assets[0]), i.asset_count > 1 ? ` +${i.asset_count - 1}` : "")) },
      { label: "Risk removed", num: true, render: (i) => `${fmt.f(i.risk_reduction_percent, 1)}%` },
      { label: "", render: (i) => shareBar(max > 0 ? i.risk_reduction / max : 0) },
      { label: "Protects most", wrap: true, render: (i) => h("span", { class: "small" }, i.protects.map((t, n) => [n ? ", " : "", entityLink(t)])) },
    ], priorities.items, { emptyText: "No open finding contributes to crown-jewel risk." })), { flush: true, actions: switcher }));
  page.append(h("div", { class: "grid two", style: { marginTop: "14px" } },
    card("Choke points", h("div", {}, h("p", { class: "muted small", style: { padding: "10px 16px 0", margin: 0 } }, "States on the most likely paths whose hardening removes the most downstream risk."),
      table([
        { label: "Entity", wrap: true, render: (c) => entityLink(c) },
        { label: "Type", render: (c) => typeBadge(c.type) },
        { label: "Risk removed", num: true, render: (c) => `${fmt.f(c.risk_reduction_percent, 1)}%` },
        { label: "Controls that would help", wrap: true, render: (c) => h("div", { class: "row" }, c.recommended_controls.map((x) => h("span", { class: "chip" }, x.replace(/_/g, " ")))) },
      ], chokes.items, { emptyText: "No choke points: no path reaches a crown jewel." })), { flush: true }),
    card("Detection race", race.any_target ? h("div", {},
      h("div", { class: "grid kpis", style: { gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))" } },
        kpi("Attacker wins", fmt.p(race.any_target.reach_before_detection), "reaches a crown jewel first"),
        kpi("Detected first", fmt.p(race.any_target.detected_first), "a detective control fires"),
        kpi("Contained", fmt.p(race.any_target.contained), "attacker runs out of moves"),
        kpi("Expected attempts", fmt.f(race.any_target.expected_attempts, 1), "before the attack ends")),
      h("p", { class: "muted small" }, race.note)) : empty("No crown jewel is reachable."))));
  return page;
}

// ---------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------
// Notes carry entity ids; names are looked up once and cached for the session.
const entityNames = new Map();
function entityChip(id) {
  const chip = h("a", { class: "chip accent", href: `#/explore/${id}` }, "entity");
  if (!entityNames.has(id)) entityNames.set(id, get(`/api/v1/nodes/${id}`).then((node) => node.name || node.type, () => null));
  entityNames.get(id).then((name) => { if (name) chip.textContent = name; });
  return chip;
}

async function memoryView() {
  const page = h("div", {}, pageHead("Memory", "Notes that agents and analysts leave on the graph: observations, decisions, lessons and playbooks. Proven notes are suggested first when a similar situation comes up."));
  const search = h("input", { type: "search", placeholder: "Search notes…", "aria-label": "Search notes" });
  const kind = h("select", { "aria-label": "Kind" }, h("option", { value: "" }, "All kinds"), ["observation", "decision", "lesson", "playbook", "hypothesis"].map((k) => h("option", { value: k }, k)));
  const list = h("div", { class: "grid" });
  async function load() {
    fill(list, h("p", { class: "muted" }, spinner(), " Loading…"));
    try {
      const data = await get("/api/v1/memory", { q: search.value.trim() || null, kind: kind.value || null, limit: 50 });
      clear(list);
      if (!data.items.length) { list.append(empty("No notes match.")); return; }
      for (const note of data.items) {
        const trials = note.successes + note.failures;
        list.append(h("article", { class: "card" },
          h("div", { class: "spread" },
            h("div", { class: "row" }, h("span", { class: "chip accent" }, note.kind), h("strong", {}, note.title)),
            h("div", { class: "row small muted" },
              trials ? h("span", { class: `chip ${note.successes >= note.failures ? "ok" : "danger"}` }, `worked ${note.successes}/${trials}`) : h("span", { class: "chip" }, "not yet tried"),
              h("span", {}, `${note.author_kind} · ${fmt.when(note.created_at)}`))),
          note.body ? h("p", { style: { margin: "8px 0", whiteSpace: "pre-wrap" } }, note.body) : null,
          h("div", { class: "spread" },
            h("div", { class: "row" }, note.tags.map((t) => h("span", { class: "chip" }, `#${t}`)), note.entity_ids.map((id) => entityChip(id))),
            can("memory:write") ? h("div", { class: "row" },
              h("button", { class: "button small", type: "button", onclick: async () => { if (await guarded(() => post(`/api/v1/memory/${note.id}/feedback`, { outcome: "success" }), "Recorded: it worked")) load(); } }, "It worked"),
              h("button", { class: "button small", type: "button", onclick: async () => { if (await guarded(() => post(`/api/v1/memory/${note.id}/feedback`, { outcome: "failure" }), "Recorded: it did not work")) load(); } }, "It did not"),
              h("button", { class: "button small ghost", type: "button", onclick: async () => { if (confirmAction("Archive this note?")) { await guarded(() => del(`/api/v1/memory/${note.id}`), "Archived"); load(); } } }, "Archive")) : null)));
      }
    } catch (error) { fill(list, h("div", { class: "callout danger" }, error.message)); }
  }
  page.append(card(null, h("form", { class: "row", onsubmit: (event) => { event.preventDefault(); load(); } }, h("div", { class: "grow" }, search), kind, h("button", { class: "button primary", type: "submit" }, "Search"))));
  search.style.width = "100%";
  if (can("memory:write")) {
    const form = h("form", { class: "form" },
      h("div", { class: "form inline" },
        h("label", {}, "Kind", h("select", { name: "kind" }, ["observation", "decision", "lesson", "playbook", "hypothesis"].map((k) => h("option", { value: k }, k)))),
        h("label", {}, "Title", h("input", { name: "title", required: true, maxlength: 256 })),
        h("label", {}, "Entity ids (comma-separated)", h("input", { name: "entities", placeholder: "optional" })),
        h("label", {}, "Tags (comma-separated)", h("input", { name: "tags", placeholder: "optional" }))),
      h("label", {}, "Note", h("textarea", { name: "body" })),
      h("div", {}, h("button", { class: "button primary", type: "submit" }, "Add note")));
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const data = new FormData(form);
      const split = (value) => String(value || "").split(",").map((s) => s.trim()).filter(Boolean);
      const created = await guarded(() => post("/api/v1/memory", { kind: data.get("kind"), title: data.get("title"), body: data.get("body"), entity_ids: split(data.get("entities")), tags: split(data.get("tags")) }), "Note added");
      if (created) {
        if (created.redacted) toast(`Secrets were redacted from the note (${created.redacted.join(", ")}).`);
        form.reset();
        load();
      }
    });
    page.append(h("div", { style: { margin: "14px 0" } }, card("Add a note", form)));
  }
  page.append(h("div", { style: { marginTop: "14px" } }, list));
  load();
  return page;
}

// ---------------------------------------------------------------------------
// Data quality
// ---------------------------------------------------------------------------
async function dataView(args) {
  const active = ["ingest", "quarantine", "conflicts"].includes(args[0]) ? args[0] : (can("graph:write") ? "ingest" : "quarantine");
  const page = h("div", {}, pageHead("Data quality", "Load data, and deal with what ingestion refused to guess about."));
  const items = [];
  if (can("graph:write")) items.push(["ingest", "Load data"]);
  if (can("graph:curate")) items.push(["quarantine", "Quarantine"], ["conflicts", "Identity conflicts"]);
  page.append(tabs(items, active, (key) => { location.hash = `#/data/${key}`; }));
  page.append(await DATA_TABS[active]());
  return page;
}

const DATA_TABS = {
  async ingest() {
    const [mappings, batches] = await Promise.all([get("/api/v1/ingest/mappings"), get("/api/v1/ingest/batches", { limit: 25 })]);
    const select = h("select", { name: "mapping" }, mappings.items.map((m) => h("option", { value: m.name }, `${m.name} — ${m.description}`)));
    const file = h("input", { type: "file", name: "file", required: true });
    const params = h("div", { class: "form inline" });
    const drawParams = () => {
      const mapping = mappings.items.find((m) => m.name === select.value);
      fill(params, Object.entries(mapping.parameters).map(([name, description]) => h("label", {}, `${name} — ${description}`, h("input", { name: `param.${name}`, required: mapping.required_parameters.includes(name) }))));
    };
    select.addEventListener("change", drawParams);
    drawParams();
    const result = h("div", {});
    const form = h("form", { class: "form" }, h("label", {}, "Source format", select), params, h("label", {}, "File", file), h("div", {}, h("button", { class: "button primary", type: "submit" }, "Load file")));
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const chosen = file.files[0];
      if (!chosen) return;
      const query = {};
      for (const input of params.querySelectorAll("input")) if (input.value.trim()) query[input.name] = input.value.trim();
      fill(result, h("p", { class: "muted" }, spinner(), " Loading…"));
      try {
        const out = await api("POST", `/api/v1/ingest/source/${select.value}`, { raw: chosen, query, headers: { "Content-Type": "application/octet-stream" } });
        fill(result, h("div", { class: `callout ${out.quarantined_total ? "warn" : ""}` },
          h("strong", {}, `${fmt.n(out.source_records)} source records read. `),
          `Entities: ${out.nodes.created} new, ${out.nodes.updated} changed, ${out.nodes.unchanged} unchanged. `,
          `Relationships: ${out.edges.created} new, ${out.edges.updated} changed. `,
          out.quarantined_total ? h("span", {}, `${out.quarantined_total} records were quarantined — `, h("a", { href: "#/data/quarantine" }, "review them"), ".") : "Nothing was quarantined.",
          out.conflicts ? h("span", {}, ` ${out.conflicts} identity conflicts — `, h("a", { href: "#/data/conflicts" }, "review them"), ".") : null));
      } catch (error) { fill(result, h("div", { class: "callout danger" }, error.message)); }
    });
    return h("div", { class: "grid" }, card("Load a source file", h("div", { class: "grid" }, form, result)),
      card("Recent batches", table([
        { label: "Started", nowrap: true, render: (b) => fmt.when(b.started_at) },
        { label: "Source", render: (b) => b.source },
        { label: "Mapping", render: (b) => b.mapping || "canonical" },
        { label: "Status", render: (b) => h("span", { class: `chip ${b.status === "completed" ? "ok" : b.status === "failed" ? "danger" : ""}` }, b.status) },
        { label: "Entities +/~", num: true, render: (b) => (b.counts.nodes ? `${b.counts.nodes.created} / ${b.counts.nodes.updated}` : "—") },
        { label: "Relationships +/~", num: true, render: (b) => (b.counts.edges ? `${b.counts.edges.created} / ${b.counts.edges.updated}` : "—") },
        { label: "Quarantined", num: true, render: (b) => b.counts.quarantined ?? "—" },
        { label: "By", render: (b) => b.principal },
      ], batches.items, { emptyText: "Nothing has been ingested yet." }), { flush: true }));
  },

  async quarantine() {
    const data = await get("/api/v1/quarantine", { limit: 200 });
    const chosen = new Set();
    const act = async (path, label) => {
      if (!chosen.size) { toast("Select at least one record."); return; }
      const out = await guarded(() => post(path, { ids: [...chosen] }), label);
      if (out) route();
    };
    return card(`Quarantined records (${data.total})`, h("div", {},
      h("p", { class: "muted small", style: { padding: "10px 16px 0", margin: 0 } }, "Records that failed validation are kept here with the reason, never dropped. Fix the mapping, the ontology or the source, then replay."),
      table([
        { label: "", render: (r) => h("input", { type: "checkbox", "aria-label": "Select record", onclick: (event) => event.stopPropagation(), onchange: (event) => { if (event.target.checked) chosen.add(r.id); else chosen.delete(r.id); } }) },
        { label: "When", nowrap: true, render: (r) => fmt.when(r.created_at) },
        { label: "Source", render: (r) => r.source },
        { label: "Kind", render: (r) => r.kind.replace("_", " ") },
        { label: "Reason", wrap: true, render: (r) => r.reason },
        { label: "Record", wrap: true, render: (r) => h("code", { class: "small" }, JSON.stringify(r.record).slice(0, 300)) },
      ], data.items, { emptyText: "Nothing is quarantined." })), {
      flush: true,
      actions: [
        can("graph:write") ? h("button", { class: "button small", type: "button", onclick: () => act("/api/v1/quarantine/replay", "Replayed") }, "Replay selected") : null,
        h("button", { class: "button small danger", type: "button", onclick: () => { if (confirmAction("Discard the selected records? They will not be ingested.")) act("/api/v1/quarantine/discard", "Discarded"); } }, "Discard selected"),
      ],
    });
  },

  async conflicts() {
    const data = await get("/api/v1/conflicts", { limit: 200 });
    const reasons = {
      ambiguous_weak_match: "A record known only by a weak identifier (such as a short host name) could be any of these entities.",
      exclusive_mismatch: "A record matched an entity on one identifier but contradicts it on another that an entity can only have one of.",
      multiple_strong_matches: "One record carries strong identifiers that belong to different entities.",
    };
    return card(`Identity conflicts (${data.total})`, h("div", {},
      h("p", { class: "muted small", style: { padding: "10px 16px 0", margin: 0 } }, "When entity resolution would have to guess, it asks instead. Choose the entity the records belong to — the decision is remembered — or dismiss if they really are different things."),
      table([
        { label: "Type", render: (c) => typeBadge(c.node_type) },
        { label: "What happened", wrap: true, render: (c) => h("div", {}, h("div", {}, reasons[c.reason] || c.reason), h("div", { class: "muted small mono" }, Object.entries(c.detail.identifiers || {}).map(([k, v]) => `${k}=${v}`).join("  "))) },
        { label: "Seen", num: true, render: (c) => `${c.occurrences}×` },
        { label: "Belongs to", render: (c) => h("div", { class: "row" }, c.node_ids.map((id) => h("span", { class: "row" },
          h("a", { href: `#/explore/${id}`, class: "mono small" }, id.slice(0, 8)),
          h("button", { class: "button small", type: "button", onclick: async () => { if (await guarded(() => post(`/api/v1/conflicts/${c.id}/resolve`, { node_id: id }), "Resolved")) route(); } }, "This one")))) },
        { label: "", render: (c) => h("button", { class: "button small ghost", type: "button", onclick: async () => { await guarded(() => post(`/api/v1/conflicts/${c.id}/dismiss`), "Dismissed"); route(); } }, "Dismiss") },
      ], data.items, { emptyText: "No open conflicts." })), { flush: true });
  },
};

// ---------------------------------------------------------------------------
// Administration
// ---------------------------------------------------------------------------
async function adminView(args) {
  const available = [];
  if (can("admin:keys")) available.push(["keys", "API keys"]);
  if (can("admin:users")) available.push(["users", "Users"]);
  if (can("admin:webhooks")) available.push(["webhooks", "Webhooks"]);
  if (can("audit:read")) available.push(["audit", "Audit"]);
  const active = available.some(([key]) => key === args[0]) ? args[0] : available[0][0];
  const page = h("div", {}, pageHead("Administration"), tabs(available, active, (key) => { location.hash = `#/admin/${key}`; }));
  page.append(await ADMIN_TABS[active]());
  return page;
}

function secretCallout(label, value) {
  return h("div", { class: "callout warn" }, h("strong", {}, `${label} — copy it now; it cannot be shown again.`), h("pre", { style: { marginTop: "8px" } }, value));
}

const ADMIN_TABS = {
  async keys() {
    const [keys, roles] = await Promise.all([get("/api/v1/api-keys"), get("/api/v1/roles")]);
    const created = h("div", {});
    const form = h("form", { class: "form inline" },
      h("label", {}, "Name", h("input", { name: "name", required: true, placeholder: "e.g. hal-o triage agent" })),
      h("label", {}, "Used by", h("select", { name: "kind" }, h("option", { value: "agent" }, "an agent"), h("option", { value: "service" }, "a service"))),
      h("label", {}, "Role", h("select", { name: "role" }, Object.keys(roles.roles).filter((r) => r !== "platform_admin").map((r) => h("option", { value: r, selected: r === "agent" }, r)))),
      h("label", {}, "Expires after (days)", h("input", { name: "days", type: "number", min: 1, max: 3650, placeholder: "never" })),
      h("button", { class: "button primary", type: "submit" }, "Create key"));
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const data = new FormData(form);
      const out = await guarded(() => post("/api/v1/api-keys", { name: data.get("name"), kind: data.get("kind"), roles: [data.get("role")], expires_in_days: data.get("days") ? Number(data.get("days")) : null }));
      if (out) { fill(created, secretCallout("API key created", out.api_key)); form.reset(); show((await get("/api/v1/api-keys")).items); }
    });
    const list = h("div", {});
    const show = (items) => fill(list, table([
        { label: "Name", wrap: true, render: (k) => k.name },
        { label: "Kind", render: (k) => k.kind },
        { label: "Roles", render: (k) => k.roles.join(", ") },
        { label: "Scope", render: (k) => (k.node_types ? k.node_types.join(", ") : "all types") },
        { label: "Last used", nowrap: true, render: (k) => fmt.when(k.last_used_at) },
        { label: "Expires", nowrap: true, render: (k) => (k.expires_at ? fmt.when(k.expires_at) : "never") },
        { label: "", render: (k) => (k.revoked_at ? h("span", { class: "chip danger" }, "revoked") : h("button", { class: "button small danger", type: "button", onclick: async () => { if (confirmAction(`Revoke “${k.name}”? Anything using it stops working immediately.`)) { await guarded(() => del(`/api/v1/api-keys/${k.id}`), "Revoked"); route(); } } }, "Revoke")) },
      ], items, { emptyText: "No API keys yet." }));
    show(keys.items);
    return h("div", { class: "grid" }, card("Create an API key", h("div", { class: "grid" }, form, created)), card("API keys", list, { flush: true }));
  },

  async users() {
    const [users, roles] = await Promise.all([get("/api/v1/users"), get("/api/v1/roles")]);
    const form = h("form", { class: "form inline" },
      h("label", {}, "Username", h("input", { name: "username", required: true, autocomplete: "off" })),
      h("label", {}, "Password (12+ characters)", h("input", { name: "password", type: "password", required: true, autocomplete: "new-password" })),
      h("label", {}, "Role", h("select", { name: "role" }, Object.keys(roles.roles).filter((r) => r !== "platform_admin").map((r) => h("option", { value: r, selected: r === "analyst" }, r)))),
      h("button", { class: "button primary", type: "submit" }, "Create user"));
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const data = new FormData(form);
      if (await guarded(() => post("/api/v1/users", { username: data.get("username"), password: data.get("password"), roles: [data.get("role")] }), "User created")) route();
    });
    return h("div", { class: "grid" }, card("Create a user", form),
      card("Users", table([
        { label: "Username", render: (u) => u.username },
        { label: "Roles", render: (u) => u.roles.join(", ") },
        { label: "Last sign-in", nowrap: true, render: (u) => fmt.when(u.last_login_at) },
        { label: "State", render: (u) => (u.disabled ? h("span", { class: "chip danger" }, "disabled") : u.locked ? h("span", { class: "chip warn" }, "locked") : h("span", { class: "chip ok" }, "active")) },
        { label: "", render: (u) => h("button", { class: "button small", type: "button", onclick: async () => { await guarded(() => patch(`/api/v1/users/${encodeURIComponent(u.username)}`, { disabled: !u.disabled }), u.disabled ? "Enabled" : "Disabled"); route(); } }, u.disabled ? "Enable" : "Disable") },
      ], users.items), { flush: true }),
      card("What each role may do", table([
        { label: "Role", render: ([name]) => h("code", {}, name) },
        { label: "Permissions", wrap: true, render: ([, permissions]) => h("span", { class: "small" }, permissions.join(" · ")) },
      ], Object.entries(roles.roles)), { flush: true }));
  },

  async webhooks() {
    const hooks = await get("/api/v1/webhooks");
    const created = h("div", {});
    const form = h("form", { class: "form inline" },
      h("label", {}, "Name", h("input", { name: "name", required: true, placeholder: "e.g. Remediation OS" })),
      h("label", {}, "URL", h("input", { name: "url", type: "url", required: true, placeholder: "https://…" })),
      h("label", {}, "Event kinds (comma-separated, blank = all)", h("input", { name: "kinds", placeholder: "node.created, edge.deleted" })),
      h("label", {}, "Entity types (blank = all)", h("input", { name: "types", placeholder: "Finding, Alert" })),
      h("button", { class: "button primary", type: "submit" }, "Subscribe"));
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const data = new FormData(form);
      const split = (value) => String(value || "").split(",").map((s) => s.trim()).filter(Boolean);
      const out = await guarded(() => post("/api/v1/webhooks", { name: data.get("name"), url: data.get("url"), event_kinds: split(data.get("kinds")), entity_types: split(data.get("types")) }));
      if (out) { fill(created, secretCallout("Signing secret", out.secret)); form.reset(); show((await get("/api/v1/webhooks")).items); }
    });
    const list = h("div", {});
    const show = (items) => fill(list, table([
        { label: "Name", render: (w) => w.name },
        { label: "URL", wrap: true, render: (w) => h("code", { class: "small" }, w.url) },
        { label: "Filter", wrap: true, render: (w) => h("span", { class: "small" }, [...w.event_kinds, ...w.entity_types].join(", ") || "everything") },
        { label: "State", render: (w) => (w.active ? (w.failures ? h("span", { class: "chip warn", title: w.last_error || "" }, `retrying (${w.failures})`) : h("span", { class: "chip ok" }, "active")) : h("span", { class: "chip danger", title: w.last_error || "" }, "disabled")) },
        { label: "Last delivery", nowrap: true, render: (w) => fmt.when(w.last_delivery_at) },
        { label: "", render: (w) => h("div", { class: "row" },
          h("button", { class: "button small", type: "button", onclick: async () => { await guarded(() => patch(`/api/v1/webhooks/${w.id}`, { active: !w.active }), w.active ? "Disabled" : "Enabled"); route(); } }, w.active ? "Disable" : "Enable"),
          h("button", { class: "button small danger", type: "button", onclick: async () => { if (confirmAction(`Delete the subscription “${w.name}”?`)) { await guarded(() => del(`/api/v1/webhooks/${w.id}`), "Deleted"); route(); } } }, "Delete")) },
      ], items, { emptyText: "No subscriptions." }));
    show(hooks.items);
    return h("div", { class: "grid" }, card("Subscribe a URL to graph changes", h("div", { class: "grid" }, form, created)), card("Subscriptions", list, { flush: true }));
  },

  async audit() {
    const [log, verdict] = await Promise.all([get("/api/v1/audit", { limit: 200 }), get("/api/v1/audit/verify")]);
    return h("div", { class: "grid" },
      h("div", { class: `callout ${verdict.ok ? "" : "danger"}` }, verdict.ok
        ? h("span", {}, h("strong", {}, "The audit chain is intact. "), `${fmt.n(verdict.entries)} entries verified; head `, h("code", {}, verdict.head.slice(0, 16)), "…")
        : h("span", {}, h("strong", {}, "The audit chain is broken. "), `${verdict.reason} at entry ${verdict.broken_at_seq}. Treat the log after that point as untrustworthy and investigate.`)),
      card("Audit log", table([
        { label: "#", num: true, render: (e) => e.seq },
        { label: "When", nowrap: true, render: (e) => fmt.when(e.ts) },
        { label: "Who", render: (e) => e.actor },
        { label: "Action", render: (e) => h("code", {}, e.action) },
        { label: "Target", wrap: true, render: (e) => e.target || "—" },
        { label: "Detail", wrap: true, render: (e) => h("span", { class: "muted small" }, JSON.stringify(e.detail).slice(0, 220)) },
      ], log.items, { emptyText: "No audit entries yet." }), { flush: true }));
  },
};

// ---------------------------------------------------------------------------
// Model: the ontology and the numbers behind the analytics
// ---------------------------------------------------------------------------
async function modelView() {
  const o = state.ontology;
  const sem = o.attack_semantics;
  const page = h("div", {}, pageHead("Model", `Ontology ${o.ontology.name} ${o.ontology.version}. Everything the graph accepts, and every rule and number the attack-path results depend on, is defined here — in one reviewed file.`));
  const probability = (m) => (m.model === "fixed" ? fmt.p(m.value) : m.model === "by_property" ? `by ${m.property}: ${Object.entries(m.values).map(([k, v]) => `${k} ${fmt.p(v)}`).join(", ")}` : `exploitability of the target${m.floor ? ` (at least ${fmt.p(m.floor)})` : ""}`);
  page.append(h("div", { class: "grid" },
    card("Entity types", table([
      { label: "Type", render: ([name]) => typeBadge(name) },
      { label: "Plane", render: ([, t]) => t.plane },
      { label: "What it is", wrap: true, render: ([, t]) => t.description },
      { label: "Recognised by", wrap: true, render: ([, t]) => h("span", { class: "small mono" }, t.identifiers.map((i) => i.kind + (i.weak ? "*" : "")).join(", ")) },
    ], Object.entries(o.node_types)), { flush: true }),
    card("Relationship types", table([
      { label: "Relationship", render: ([name]) => h("code", {}, name) },
      { label: "From → to", wrap: true, render: ([, e]) => `${e.source.join(", ")} → ${e.target.join(", ")}` },
      { label: "Meaning", wrap: true, render: ([, e]) => e.description },
    ], Object.entries(o.edge_types)), { flush: true }),
    card("How an attacker moves", table([
      { label: "Step", render: (r) => h("code", {}, r.name) },
      { label: "Along", render: (r) => h("code", {}, r.edge) },
      { label: "Probability", wrap: true, render: (r) => probability(r.probability) },
      { label: "Reduced by", wrap: true, render: (r) => h("span", { class: "small" }, r.mitigated_by.join(", ").replace(/_/g, " ") || "—") },
      { label: "What it models", wrap: true, render: (r) => r.description },
    ], sem.transitions), { flush: true }),
    h("div", { class: "grid two" },
      card("Where an attacker starts", table([
        { label: "Rule", render: (r) => h("span", {}, h("code", {}, r.name), r.enabled ? null : h("span", { class: "chip", style: { marginLeft: "6px" } }, "off")) },
        { label: "Applies to", wrap: true, render: (r) => `${r.node_type} ${JSON.stringify(r.where)}` },
        { label: "Probability", wrap: true, render: (r) => probability(r.probability) },
      ], sem.entries), { flush: true }),
      card("What counts as a crown jewel", table([
        { label: "Rule", render: (r) => h("code", {}, r.name) },
        { label: "Applies to", wrap: true, render: (r) => `${r.node_type} ${JSON.stringify(r.where)}` },
        { label: "Impact", render: (r) => (r.impact.property ? `by ${r.impact.property}` : fmt.f(r.impact.default, 0)) },
      ], sem.targets), { flush: true })),
    card("Exploitability of a finding", h("div", {},
      h("pre", {}, "p = min(cap, max(KEV floor if known-exploited, EPSS × weight, CVSS term, default))\n    × Π (1 − effectiveness of each compensating control)"),
      h("dl", { class: "props", style: { marginTop: "10px" } },
        h("dt", {}, "Known-exploited floor"), h("dd", {}, fmt.p(sem.exploitability.kev_floor)),
        h("dt", {}, "EPSS weight"), h("dd", {}, sem.exploitability.epss_weight),
        h("dt", {}, "CVSS vector / score weight"), h("dd", {}, `${sem.exploitability.cvss_vector_weight} / ${sem.exploitability.cvss_score_weight}`),
        h("dt", {}, "Default"), h("dd", {}, fmt.p(sem.exploitability.unknown_default)),
        h("dt", {}, "Counted as open"), h("dd", {}, sem.exploitability.open_statuses.join(", ")),
        h("dt", {}, "Cap"), h("dd", {}, fmt.p(sem.exploitability.max_probability))),
      h("p", { class: "muted small", style: { marginTop: "10px" } }, "These are priors, meant to be calibrated per organisation. Change them in the ontology file; results follow.")))));
  return page;
}

const VIEWS = {
  overview: overviewView, explore: exploreView, paths: pathsView, priorities: prioritiesView, memory: memoryView,
  data: dataView, admin: adminView, model: modelView,
};

// ---------------------------------------------------------------------------
setUnauthorizedHandler(() => {
  session.clear();
  state.me = null;
  showLogin("Your session has ended. Sign in again.");
});
window.addEventListener("hashchange", route);
initTheme();
initLogin();
if (session.current) {
  start().catch(() => { session.clear(); showLogin(); });
} else {
  showLogin();
}
