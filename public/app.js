const state = {
  page: 0,
  pageSize: 25,
  filters: { q: "", severity: "", source: "", type: "", sector: "", company: "", assetType: "", tactic: "" },
  groupBy: "",
  threatsById: new Map(),
  collapsedGroups: new Set(),
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

function fillSelect(select, options, allLabel) {
  const current = select.value;
  select.innerHTML = `<option value="">${allLabel}</option>` + options;
  select.value = current;
}

function renderStats(stats) {
  const cards = [
    { label: "Total tracked", value: stats.total, cls: "" },
    { label: "New (24h)", value: stats.last24h, cls: "" },
    { label: "New (7d)", value: stats.last7d, cls: "" },
    { label: "Critical", value: stats.bySeverity.critical || 0, cls: "critical" },
    { label: "High", value: stats.bySeverity.high || 0, cls: "high" },
    { label: "Sectors", value: stats.bySector.length, cls: "" },
    { label: "Companies", value: stats.byCompany.length, cls: "" },
  ];
  el("statsRow").innerHTML = cards
    .map(
      (c) => `<div class="stat-card ${c.cls}"><div class="value">${c.value}</div><div class="label">${c.label}</div></div>`
    )
    .join("");

  fillSelect(
    el("sourceFilter"),
    stats.bySource.map((s) => `<option value="${s.source}">${s.source} (${s.c})</option>`).join(""),
    "All sources"
  );
  fillSelect(
    el("typeFilter"),
    stats.byType.map((t) => `<option value="${t.type}">${t.type} (${t.c})</option>`).join(""),
    "All types"
  );
  fillSelect(
    el("sectorFilter"),
    stats.bySector.map((s) => `<option value="${escapeHtml(s.sector)}">${escapeHtml(s.sector)} (${s.c})</option>`).join(""),
    "All sectors"
  );
  fillSelect(
    el("companyFilter"),
    stats.byCompany.map((c) => `<option value="${escapeHtml(c.company)}">${escapeHtml(c.company)} (${c.c})</option>`).join(""),
    "All companies"
  );
  fillSelect(
    el("tacticFilter"),
    stats.byTactic.map((t) => `<option value="${escapeHtml(t.tactic)}">${escapeHtml(t.tactic)} (${t.c})</option>`).join(""),
    "All MITRE ATT&CK tactics"
  );
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

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

function mitreBadges(t) {
  return (t.mitreTechniques || [])
    .map((m) => `<span class="badge mitre" title="${escapeHtml(m.tactic)}">ATT&amp;CK ${escapeHtml(m.techniqueId)}</span>`)
    .join("");
}

function nistBadges(t) {
  return (t.nistControls || [])
    .map((n) => `<span class="badge nist" title="${escapeHtml(n.name)}">NIST ${escapeHtml(n.id)}</span>`)
    .join("");
}

function threatItemHtml(t) {
  const sev = t.severity || "unknown";
  return `
    <div class="threat-item ${sev}" data-id="${t.id}" tabindex="0" role="button">
      <div class="threat-item-top">
        <span class="badge ${sev}">${sev}</span>
        <span class="badge">${escapeHtml(t.type)}</span>
        <span class="badge">${escapeHtml(t.source)}</span>
        ${t.cvssScore ? `<span class="badge">CVSS ${t.cvssScore}</span>` : ""}
        ${t.sector ? `<span class="badge chip" data-filter="sector" data-value="${escapeHtml(t.sector)}">${escapeHtml(t.sector)}</span>` : ""}
        ${t.assetType && t.assetType !== "unknown" ? `<span class="badge chip" data-filter="assetType" data-value="${t.assetType}">${t.assetType}</span>` : ""}
        ${mitreBadges(t)}
        ${nistBadges(t)}
      </div>
      <div class="threat-title">${escapeHtml(t.title)}</div>
      <div class="threat-desc">${escapeHtml(t.description || "")}</div>
      <div class="threat-meta">
        <span>${timeAgo(t.publishedAt)}</span>
        ${t.vendor ? `<span class="chip" data-filter="company" data-value="${escapeHtml(t.vendor)}">${escapeHtml(t.vendor)}${t.product ? " / " + escapeHtml(t.product) : ""}</span>` : ""}
      </div>
    </div>`;
}

function cacheThreats(rows) {
  for (const t of rows) state.threatsById.set(String(t.id), t);
}

function wireThreatListDelegation(container) {
  container.addEventListener("click", (e) => {
    const chip = e.target.closest(".chip");
    if (chip) {
      e.stopPropagation();
      const filterKey = chip.dataset.filter;
      state.filters[filterKey] = chip.dataset.value;
      syncFilterControlsFromState();
      state.page = 0;
      loadThreats();
      return;
    }
    const card = e.target.closest(".threat-item");
    if (card) openThreatModal(card.dataset.id);
  });
  container.addEventListener("keydown", (e) => {
    if (e.key !== "Enter" && e.key !== " ") return;
    const card = e.target.closest(".threat-item");
    if (card) {
      e.preventDefault();
      openThreatModal(card.dataset.id);
    }
  });
}

function syncFilterControlsFromState() {
  el("severityFilter").value = state.filters.severity;
  el("sourceFilter").value = state.filters.source;
  el("typeFilter").value = state.filters.type;
  el("sectorFilter").value = state.filters.sector;
  el("companyFilter").value = state.filters.company;
  el("assetTypeFilter").value = state.filters.assetType;
  el("tacticFilter").value = state.filters.tactic;
  el("searchInput").value = state.filters.q;
}

function openThreatModal(id) {
  const t = state.threatsById.get(String(id));
  if (!t) return;
  const sev = t.severity || "unknown";

  const mitreRows = (t.mitreTechniques || [])
    .map(
      (m) => `<div class="detail-row"><span class="badge mitre">ATT&amp;CK ${escapeHtml(m.techniqueId)}</span> ${escapeHtml(m.techniqueName)} <span class="detail-dim">(${escapeHtml(m.tactic)})</span></div>`
    )
    .join("") || `<div class="detail-dim">No ATT&amp;CK technique inferred.</div>`;

  const nistRows = (t.nistControls || [])
    .map((n) => `<div class="detail-row"><span class="badge nist">NIST ${escapeHtml(n.id)}</span> ${escapeHtml(n.name)}</div>`)
    .join("") || `<div class="detail-dim">No NIST control inferred.</div>`;

  el("modalBody").innerHTML = `
    <div class="threat-item-top">
      <span class="badge ${sev}">${sev}</span>
      <span class="badge">${escapeHtml(t.type)}</span>
      <span class="badge">${escapeHtml(t.source)}</span>
      ${t.cvssScore ? `<span class="badge">CVSS ${t.cvssScore}</span>` : ""}
    </div>
    <h2 class="modal-title">${escapeHtml(t.title)}</h2>
    <p class="threat-desc">${escapeHtml(t.description || "No description provided by the source feed.")}</p>

    <div class="modal-grid">
      <div><span class="detail-label">Sector</span><div>${escapeHtml(t.sector || "Unknown")}</div></div>
      <div><span class="detail-label">Company / Vendor</span><div>${escapeHtml(t.vendor || "—")}</div></div>
      <div><span class="detail-label">Product</span><div>${escapeHtml(t.product || "—")}</div></div>
      <div><span class="detail-label">Asset type</span><div>${escapeHtml(t.assetType || "unknown")}</div></div>
      <div><span class="detail-label">Published</span><div>${timeAgo(t.publishedAt)}</div></div>
      <div><span class="detail-label">Ingested</span><div>${timeAgo(t.ingestedAt + "Z")}</div></div>
    </div>

    <div class="modal-section">
      <h3>MITRE ATT&amp;CK (inferred)</h3>
      ${mitreRows}
    </div>
    <div class="modal-section">
      <h3>NIST 800-53 controls (inferred)</h3>
      ${nistRows}
    </div>

    ${t.url ? `<a class="btn" href="${t.url}" target="_blank" rel="noopener noreferrer">Open source reference ↗</a>` : ""}
  `;
  el("threatModal").classList.remove("hidden");
}

function closeModal() {
  el("threatModal").classList.add("hidden");
}

function renderGroupHeaderHtml(group, groupBy) {
  const label = groupBy === "company" ? group.key || "Unknown company" : group.key;
  const collapsed = state.collapsedGroups.has(`${groupBy}:${group.key}`);
  const truncNote = group.total > group.rows.length ? ` — showing ${group.rows.length} of ${group.total}` : "";
  return `
    <div class="group-header" data-group-key="${escapeHtml(group.key)}">
      <span class="group-toggle">${collapsed ? "▶" : "▼"}</span>
      <span class="group-title">${escapeHtml(label)}</span>
      <span class="group-count">${group.total}${truncNote}</span>
    </div>`;
}

async function loadGroupedThreats() {
  const { q, severity, source, type, sector, company, assetType, tactic } = state.filters;
  const params = new URLSearchParams({ groupBy: state.groupBy });
  if (q) params.set("q", q);
  if (severity) params.set("severity", severity);
  if (source) params.set("source", source);
  if (type) params.set("type", type);
  if (sector) params.set("sector", sector);
  if (company) params.set("company", company);
  if (assetType) params.set("assetType", assetType);
  if (tactic) params.set("tactic", tactic);

  const { groups, groupBy } = await api(`/api/threats/grouped?${params}`);

  let matchTotal = 0;
  const html = groups
    .map((g) => {
      matchTotal += g.total;
      cacheThreats(g.rows);
      const groupKey = `${groupBy}:${g.key}`;
      const collapsed = state.collapsedGroups.has(groupKey);
      return `
        <div class="threat-group">
          ${renderGroupHeaderHtml(g, groupBy)}
          <div class="group-body ${collapsed ? "hidden" : ""}">
            ${g.rows.map(threatItemHtml).join("")}
          </div>
        </div>`;
    })
    .join("");

  el("threatList").innerHTML = groups.length ? html : `<div class="empty-state">No threats match the current filters.</div>`;
  el("feedCount").textContent = `${matchTotal} matching in ${groups.length} groups`;
  el("pager").classList.add("hidden");

  el("threatList").querySelectorAll(".group-header").forEach((header) => {
    header.addEventListener("click", () => {
      const groupKey = `${state.groupBy}:${header.dataset.groupKey}`;
      if (state.collapsedGroups.has(groupKey)) {
        state.collapsedGroups.delete(groupKey);
      } else {
        state.collapsedGroups.add(groupKey);
      }
      header.nextElementSibling.classList.toggle("hidden");
      header.querySelector(".group-toggle").textContent = state.collapsedGroups.has(groupKey) ? "▶" : "▼";
    });
  });
}

async function loadThreats() {
  if (state.groupBy) {
    await loadGroupedThreats();
    return;
  }
  el("pager").classList.remove("hidden");

  const { q, severity, source, type, sector, company, assetType, tactic } = state.filters;
  const params = new URLSearchParams({
    limit: state.pageSize,
    offset: state.page * state.pageSize,
  });
  if (q) params.set("q", q);
  if (severity) params.set("severity", severity);
  if (source) params.set("source", source);
  if (type) params.set("type", type);
  if (sector) params.set("sector", sector);
  if (company) params.set("company", company);
  if (assetType) params.set("assetType", assetType);
  if (tactic) params.set("tactic", tactic);

  const { rows, total } = await api(`/api/threats?${params}`);
  cacheThreats(rows);

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
  syncFilterControlsFromState();
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

  const filterSelects = {
    severityFilter: "severity",
    sourceFilter: "source",
    typeFilter: "type",
    sectorFilter: "sector",
    companyFilter: "company",
    assetTypeFilter: "assetType",
    tacticFilter: "tactic",
  };
  for (const [id, key] of Object.entries(filterSelects)) {
    el(id).addEventListener("change", (e) => {
      state.filters[key] = e.target.value;
      state.page = 0;
      loadThreats();
    });
  }

  el("groupBySelect").addEventListener("change", (e) => {
    state.groupBy = e.target.value;
    state.page = 0;
    loadThreats();
  });

  el("clearFiltersBtn").addEventListener("click", () => {
    state.filters = { q: "", severity: "", source: "", type: "", sector: "", company: "", assetType: "", tactic: "" };
    state.page = 0;
    syncFilterControlsFromState();
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

  el("modalClose").addEventListener("click", closeModal);
  el("threatModal").addEventListener("click", (e) => {
    if (e.target.id === "threatModal") closeModal();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeModal();
  });

  wireThreatListDelegation(el("threatList"));
}

wireControls();
refreshAll();
setInterval(refreshAll, 60000);
