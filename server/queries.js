import { db } from "./db.js";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "unknown"];
const GROUPABLE_FIELDS = { sector: "sector", company: "vendor", severity: "severity" };

function parseThreatRow(r) {
  return {
    ...r,
    mitreTechniques: r.mitreTechniques ? JSON.parse(r.mitreTechniques) : [],
    nistControls: r.nistControls ? JSON.parse(r.nistControls) : [],
  };
}

const THREAT_COLUMNS = `id, source, external_id AS externalId, type, title, description, severity,
       cvss_score AS cvssScore, vendor, product, url, published_at AS publishedAt, ingested_at AS ingestedAt,
       sector, asset_type AS assetType, mitre_tactics AS mitreTactics,
       mitre_techniques AS mitreTechniques, nist_controls AS nistControls`;

function buildFilters({ source, severity, type, q, since, sector, company, assetType, tactic } = {}) {
  const clauses = [];
  const params = {};

  if (source) {
    clauses.push("source = @source");
    params.source = source;
  }
  if (severity) {
    clauses.push("severity = @severity");
    params.severity = severity.toLowerCase();
  }
  if (type) {
    clauses.push("type = @type");
    params.type = type;
  }
  if (since) {
    clauses.push("published_at >= @since");
    params.since = since;
  }
  if (sector) {
    clauses.push("sector = @sector");
    params.sector = sector;
  }
  if (company) {
    clauses.push("vendor = @company");
    params.company = company;
  }
  if (assetType) {
    clauses.push("asset_type = @assetType");
    params.assetType = assetType;
  }
  if (tactic) {
    clauses.push("mitre_tactics LIKE @tactic");
    params.tactic = `%${tactic}%`;
  }
  if (q) {
    clauses.push(
      "(title LIKE @q OR description LIKE @q OR product LIKE @q OR vendor LIKE @q OR sector LIKE @q OR mitre_tactics LIKE @q)"
    );
    params.q = `%${q}%`;
  }

  return { where: clauses.length ? `WHERE ${clauses.join(" AND ")}` : "", params };
}

export function listThreats({ limit = 50, offset = 0, ...filters } = {}) {
  const { where, params } = buildFilters(filters);
  params.limit = Math.min(Number(limit) || 50, 200);
  params.offset = Number(offset) || 0;

  const rows = db
    .prepare(
      `SELECT ${THREAT_COLUMNS}
       FROM threats
       ${where}
       ORDER BY published_at DESC
       LIMIT @limit OFFSET @offset`
    )
    .all(params)
    .map(parseThreatRow);

  const total = db.prepare(`SELECT COUNT(*) AS c FROM threats ${where}`).get(params).c;

  return { rows, total };
}

/**
 * Fetches (up to `cap`) matching threats and buckets them by sector, company
 * (vendor), or severity. Each group is capped at `perGroup` rows to keep the
 * response bounded; `group.total` still reports the true group size.
 */
export function listThreatsGrouped({ groupBy, perGroup = 25, cap = 1000, ...filters } = {}) {
  const column = GROUPABLE_FIELDS[groupBy];
  if (!column) throw new Error(`Invalid groupBy: ${groupBy}`);

  const { where, params } = buildFilters(filters);
  params.cap = Math.min(Number(cap) || 1000, 2000);

  const rows = db
    .prepare(
      `SELECT ${THREAT_COLUMNS}
       FROM threats
       ${where}
       ORDER BY ${column} IS NULL, ${column} ASC, published_at DESC
       LIMIT @cap`
    )
    .all(params)
    .map(parseThreatRow);

  const buckets = new Map();
  for (const row of rows) {
    const key = row[groupBy === "company" ? "vendor" : groupBy] || "Unknown";
    if (!buckets.has(key)) buckets.set(key, []);
    buckets.get(key).push(row);
  }

  const groups = [...buckets.entries()]
    .map(([key, items]) => ({ key, total: items.length, rows: items.slice(0, perGroup) }))
    .sort((a, b) => b.total - a.total || a.key.localeCompare(b.key));

  return { groupBy, groups, truncated: rows.length >= params.cap };
}

export function getStats() {
  const total = db.prepare(`SELECT COUNT(*) AS c FROM threats`).get().c;

  const bySeverity = Object.fromEntries(
    db
      .prepare(`SELECT severity, COUNT(*) AS c FROM threats GROUP BY severity`)
      .all()
      .map((r) => [r.severity, r.c])
  );

  const bySource = db
    .prepare(`SELECT source, COUNT(*) AS c FROM threats GROUP BY source ORDER BY c DESC`)
    .all();

  const byType = db
    .prepare(`SELECT type, COUNT(*) AS c FROM threats GROUP BY type ORDER BY c DESC`)
    .all();

  const bySector = db
    .prepare(`SELECT sector, COUNT(*) AS c FROM threats WHERE sector IS NOT NULL GROUP BY sector ORDER BY c DESC`)
    .all();

  const byCompany = db
    .prepare(`SELECT vendor AS company, COUNT(*) AS c FROM threats WHERE vendor IS NOT NULL GROUP BY vendor ORDER BY c DESC LIMIT 50`)
    .all();

  const byAssetType = db
    .prepare(`SELECT asset_type AS assetType, COUNT(*) AS c FROM threats WHERE asset_type IS NOT NULL GROUP BY asset_type ORDER BY c DESC`)
    .all();

  const tacticCounts = new Map();
  for (const { mitre_tactics } of db.prepare(`SELECT mitre_tactics FROM threats WHERE mitre_tactics IS NOT NULL AND mitre_tactics != ''`).all()) {
    for (const tactic of mitre_tactics.split(",").map((t) => t.trim()).filter(Boolean)) {
      tacticCounts.set(tactic, (tacticCounts.get(tactic) || 0) + 1);
    }
  }
  const byTactic = [...tacticCounts.entries()]
    .map(([tactic, c]) => ({ tactic, c }))
    .sort((a, b) => b.c - a.c);

  const last24h = db
    .prepare(`SELECT COUNT(*) AS c FROM threats WHERE published_at >= datetime('now', '-1 day')`)
    .get().c;

  const last7d = db
    .prepare(`SELECT COUNT(*) AS c FROM threats WHERE published_at >= datetime('now', '-7 day')`)
    .get().c;

  const lastIngest = db
    .prepare(`SELECT ran_at, status FROM sync_log ORDER BY ran_at DESC LIMIT 1`)
    .get();

  return {
    total,
    last24h,
    last7d,
    bySeverity,
    bySource,
    byType,
    bySector,
    byCompany,
    byAssetType,
    byTactic,
    severityOrder: SEVERITY_ORDER,
    lastIngest: lastIngest || null,
  };
}

export function getTimeline(days = 30) {
  const rows = db
    .prepare(
      `SELECT date(published_at) AS day, severity, COUNT(*) AS c
       FROM threats
       WHERE published_at >= date('now', @range)
       GROUP BY day, severity
       ORDER BY day ASC`
    )
    .all({ range: `-${Number(days) || 30} day` });

  const byDay = new Map();
  for (const r of rows) {
    if (!byDay.has(r.day)) byDay.set(r.day, { day: r.day, total: 0 });
    const entry = byDay.get(r.day);
    entry[r.severity] = (entry[r.severity] || 0) + r.c;
    entry.total += r.c;
  }

  return [...byDay.values()].sort((a, b) => a.day.localeCompare(b.day));
}
