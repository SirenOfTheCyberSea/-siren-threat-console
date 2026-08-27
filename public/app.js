const state = {
  page: 0,
  pageSize: 25,
  filters: { q: "", severity: "", source: "", type: "" },
};

const el = (id) => document.getElementById(id);

function timeAgo(iso) {
  const diffMs = Date.now() - new Date(iso.replace(" ", "T")).getTime();
  const mins = Math.floor(diffMs / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) throw new Error(`${path} -> ${res.status}`);
  return res.json();
}

function renderStats(stats) {
  const cards = [
    { label: "Total tracked", value: stats.total, cls: "" },
    { label: "New (24h)", value: stats.last24h, cls: "" },
    { label: "New (7d)", value: stats.last7d, cls: "" },
    { label: "Critical", value: stats.bySeverity.critical || 0, cls: "critical" },
    { label: "High", value: stats.bySeverity.high || 0, cls: "high" },
    { label: "Sources", value: stats.bySource.length, cls: "" },
  ];
  el("statsRow").innerHTML = cards
    .map(
      (c) => `<div class="stat-card ${c.cls}"><div class="value">${c.value}</div><div class="label">${c.label}</div></div>`
    )
    .join("");

  const sourceSelect = el("sourceFilter");
  const currentSource = sourceSelect.value;
  sourceSelect.innerHTML =
    `<option value="">All sources</option>` +
    stats.bySource.map((s) => `<option value="${s.source}">${s.source} (${s.c})</option>`).join("");
  sourceSelect.value = currentSource;

  const typeSelect = el("typeFilter");
  const currentType = typeSelect.value;
  typeSelect.innerHTML =
    `<option value="">All types</option>` +
    stats.byType.map((t) => `<option value="${t.type}">${t.type} (${t.c})</option>`).join("");
  typeSelect.value = currentType;
}

function renderSyncIndicator(stats) {
  const dot = el("syncDot");
  const text = el("syncText");
  if (!stats.lastIngest) {
    dot.className = "dot";
    text.textContent = "No sync yet";
    return;
  }
  dot.className = `dot ${stats.lastIngest.status === "error" ? "error" : "ok"}`;
  text.textContent = `Last sync ${timeAgo(stats.lastIngest.ran_at + "Z")}`;
}

function renderBanner(stats) {
  const banner = el("banner");
  if (stats.bySource.some((s) => s.source === "demo-seed") && stats.bySource.length === 1) {
    banner.textContent =
      "Showing bundled demo data — live sources haven't returned results yet (check network access or wait for the next sync).";
    banner.classList.remove("hidden");
  } else {
    banner.classList.add("hidden");
  }
}

function renderTimeline(days) {
  const maxVisible = 60;
  const byDay = new Map(days.map((d) => [d.day, d]));
  const today = new Date();
  const bars = [];
  for (let i = maxVisible - 1; i >= 0; i--) {
    const d = new Date(today.getTime() - i * 86400000);
    const key = d.toISOString().slice(0, 10);
    bars.push(byDay.get(key) || { day: key, total: 0 });
  }

  const max = Math.max(1, ...bars.map((b) => b.total));
  const severities = ["critical", "high", "medium", "low", "unknown"];

  el("timelineChart").innerHTML = bars
    .map((b) => {
      const segs = severities
        .filter((s) => b[s])
        .map((s) => `<div class="tl-seg ${s}" style="height:${(b[s] / max) * 100}%" title="${s}: ${b[s]}"></div>`)
        .join("");
      return `<div class="timeline-bar-wrap" title="${b.day}: ${b.total} threats" style="height:${Math.max(2, (b.total / max) * 100)}%">${segs}</div>`;
    })
    .join("");
}

function threatItemHtml(t) {
  const sev = t.severity || "unknown";
  return `
    <div class="threat-item ${sev}">
      <div class="threat-item-top">
        <span class="badge ${sev}">${sev}</span>
        <span class="badge">${t.type}</span>
        <span class="badge">${t.source}</span>
        ${t.cvssScore ? `<span class="badge">CVSS ${t.cvssScore}</span>` : ""}
      </div>
      <div class="threat-title">
        ${t.url ? `<a href="${t.url}" target="_blank" rel="noopener noreferrer">${escapeHtml(t.title)}</a>` : escapeHtml(t.title)}
      </div>
      <div class="threat-desc">${escapeHtml(t.description || "")}</div>
      <div class="threat-meta">
        <span>${timeAgo(t.publishedAt)}</span>
        ${t.vendor ? `<span>${escapeHtml(t.vendor)}${t.product ? " / " + escapeHtml(t.product) : ""}</span>` : ""}
      </div>
    </div>`;
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

async function loadThreats() {
  const { q, severity, source, type } = state.filters;
  const params = new URLSearchParams({
    limit: state.pageSize,
    offset: state.page * state.pageSize,
  });
  if (q) params.set("q", q);
  if (severity) params.set("severity", severity);
  if (source) params.set("source", source);
  if (type) params.set("type", type);

  const { rows, total } = await api(`/api/threats?${params}`);

  el("threatList").innerHTML = rows.length
    ? rows.map(threatItemHtml).join("")
    : `<div class="empty-state">No threats match the current filters.</div>`;

  el("feedCount").textContent = `${total} matching`;
  const totalPages = Math.max(1, Math.ceil(total / state.pageSize));
  el("pageInfo").textContent = `Page ${state.page + 1} / ${totalPages}`;
  el("prevPage").disabled = state.page === 0;
  el("nextPage").disabled = state.page + 1 >= totalPages;
}

function renderSyncLog(entries) {
  el("syncLog").innerHTML = entries.length
    ? entries
        .map(
          (e) => `
      <div class="sync-log-item">
        <span class="src">${e.source}</span>
        <span class="status ${e.status}">${e.status}${e.status !== "error" ? ` (+${e.items_new})` : ""}</span>
        <span class="ts">${timeAgo(e.ran_at + "Z")}</span>
      </div>`
        )
        .join("")
    : `<div class="empty-state">No syncs recorded yet.</div>`;
}

async function refreshAll() {
  const [stats, timeline, syncLog] = await Promise.all([
    api("/api/stats"),
    api("/api/timeline?days=60"),
    api("/api/sync-log?limit=30"),
  ]);
  renderStats(stats);
  renderSyncIndicator(stats);
  renderBanner(stats);
  renderTimeline(timeline);
  renderSyncLog(syncLog);
  await loadThreats();
}

function wireControls() {
  let searchTimer;
  el("searchInput").addEventListener("input", (e) => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      state.filters.q = e.target.value.trim();
      state.page = 0;
      loadThreats();
    }, 250);
  });

  el("severityFilter").addEventListener("change", (e) => {
    state.filters.severity = e.target.value;
    state.page = 0;
    loadThreats();
  });
  el("sourceFilter").addEventListener("change", (e) => {
    state.filters.source = e.target.value;
    state.page = 0;
    loadThreats();
  });
  el("typeFilter").addEventListener("change", (e) => {
    state.filters.type = e.target.value;
    state.page = 0;
    loadThreats();
  });

  el("prevPage").addEventListener("click", () => {
    if (state.page > 0) {
      state.page--;
      loadThreats();
    }
  });
  el("nextPage").addEventListener("click", () => {
    state.page++;
    loadThreats();
  });

  el("syncBtn").addEventListener("click", async () => {
    const btn = el("syncBtn");
    btn.disabled = true;
    btn.textContent = "Syncing…";
    el("syncDot").className = "dot pending";
    el("syncText").textContent = "Sync in progress…";
    try {
      await api("/api/ingest", { method: "POST" });
    } finally {
      btn.disabled = false;
      btn.textContent = "Sync Now";
      await refreshAll();
    }
  });
}

wireControls();
refreshAll();
setInterval(refreshAll, 60000);
