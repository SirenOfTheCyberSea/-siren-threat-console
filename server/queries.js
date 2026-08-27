import { db } from "./db.js";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "unknown"];

export function listThreats({ source, severity, type, q, since, limit = 50, offset = 0 } = {}) {
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
  if (q) {
    clauses.push("(title LIKE @q OR description LIKE @q OR product LIKE @q OR vendor LIKE @q)");
    params.q = `%${q}%`;
  }

  const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
  params.limit = Math.min(Number(limit) || 50, 200);
  params.offset = Number(offset) || 0;

  const rows = db
    .prepare(
      `SELECT id, source, external_id AS externalId, type, title, description, severity,
              cvss_score AS cvssScore, vendor, product, url, published_at AS publishedAt, ingested_at AS ingestedAt
       FROM threats
       ${where}
       ORDER BY published_at DESC
       LIMIT @limit OFFSET @offset`
    )
    .all(params);

  const total = db
    .prepare(`SELECT COUNT(*) AS c FROM threats ${where}`)
    .get(params).c;

  return { rows, total };
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
