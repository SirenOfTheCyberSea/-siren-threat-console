import Database from "better-sqlite3";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.join(__dirname, "..", "data");
const DB_PATH = process.env.DB_PATH || path.join(DATA_DIR, "threats.db");

fs.mkdirSync(DATA_DIR, { recursive: true });

export const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    external_id TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'vulnerability',
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL DEFAULT 'unknown',
    cvss_score REAL,
    vendor TEXT,
    product TEXT,
    url TEXT,
    published_at TEXT NOT NULL,
    ingested_at TEXT NOT NULL DEFAULT (datetime('now')),
    raw JSON,
    UNIQUE(source, external_id)
  );

  CREATE INDEX IF NOT EXISTS idx_threats_published_at ON threats(published_at DESC);
  CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity);
  CREATE INDEX IF NOT EXISTS idx_threats_source ON threats(source);

  CREATE TABLE IF NOT EXISTS sync_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    status TEXT NOT NULL,
    message TEXT,
    items_fetched INTEGER NOT NULL DEFAULT 0,
    items_new INTEGER NOT NULL DEFAULT 0,
    ran_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

/**
 * Upsert a normalized threat record. Returns true if it was a new row.
 */
export function upsertThreat(threat) {
  const row = {
    source: threat.source,
    external_id: threat.externalId,
    type: threat.type || "vulnerability",
    title: threat.title,
    description: threat.description || null,
    severity: (threat.severity || "unknown").toLowerCase(),
    cvss_score: threat.cvssScore ?? null,
    vendor: threat.vendor || null,
    product: threat.product || null,
    url: threat.url || null,
    published_at: threat.publishedAt,
    raw: threat.raw ? JSON.stringify(threat.raw) : null,
  };
  const existing = db
    .prepare(`SELECT id FROM threats WHERE source = ? AND external_id = ?`)
    .get(row.source, row.external_id);

  db.prepare(`
    INSERT INTO threats (source, external_id, type, title, description, severity, cvss_score, vendor, product, url, published_at, raw)
    VALUES (@source, @external_id, @type, @title, @description, @severity, @cvss_score, @vendor, @product, @url, @published_at, @raw)
    ON CONFLICT(source, external_id) DO UPDATE SET
      title = excluded.title,
      description = excluded.description,
      severity = excluded.severity,
      cvss_score = excluded.cvss_score,
      vendor = excluded.vendor,
      product = excluded.product,
      url = excluded.url,
      published_at = excluded.published_at,
      raw = excluded.raw
  `).run(row);

  return !existing;
}

export function logSync({ source, status, message = null, itemsFetched = 0, itemsNew = 0 }) {
  db.prepare(`
    INSERT INTO sync_log (source, status, message, items_fetched, items_new)
    VALUES (?, ?, ?, ?, ?)
  `).run(source, status, message, itemsFetched, itemsNew);
}

export function getRecentSyncLog(limit = 20) {
  return db.prepare(`SELECT * FROM sync_log ORDER BY ran_at DESC LIMIT ?`).all(limit);
}

export function countThreats() {
  return db.prepare(`SELECT COUNT(*) AS c FROM threats`).get().c;
}
