import Database from "better-sqlite3";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { enrichThreat } from "./enrich.js";

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

// --- Migration: add enrichment columns to pre-existing databases ---------
const existingColumns = new Set(db.prepare(`PRAGMA table_info(threats)`).all().map((c) => c.name));
const NEW_COLUMNS = {
  sector: "TEXT",
  asset_type: "TEXT",
  mitre_tactics: "TEXT",
  mitre_techniques: "JSON",
  nist_controls: "JSON",
};
for (const [name, decl] of Object.entries(NEW_COLUMNS)) {
  if (!existingColumns.has(name)) {
    db.exec(`ALTER TABLE threats ADD COLUMN ${name} ${decl}`);
  }
}
db.exec(`
  CREATE INDEX IF NOT EXISTS idx_threats_sector ON threats(sector);
  CREATE INDEX IF NOT EXISTS idx_threats_asset_type ON threats(asset_type);
`);

// --- Prepared statements, created once and reused ------------------------
// (rather than re-preparing on every call, which churns through native
// Statement objects and can crash better-sqlite3 during process teardown —
// see the shutdown handling below).
const statements = {
  findThreatId: db.prepare(`SELECT id FROM threats WHERE source = ? AND external_id = ?`),
  upsertThreat: db.prepare(`
    INSERT INTO threats (
      source, external_id, type, title, description, severity, cvss_score, vendor, product, url,
      published_at, raw, sector, asset_type, mitre_tactics, mitre_techniques, nist_controls
    )
    VALUES (
      @source, @external_id, @type, @title, @description, @severity, @cvss_score, @vendor, @product, @url,
      @published_at, @raw, @sector, @asset_type, @mitre_tactics, @mitre_techniques, @nist_controls
    )
    ON CONFLICT(source, external_id) DO UPDATE SET
      title = excluded.title,
      description = excluded.description,
      severity = excluded.severity,
      cvss_score = excluded.cvss_score,
      vendor = excluded.vendor,
      product = excluded.product,
      url = excluded.url,
      published_at = excluded.published_at,
      raw = excluded.raw,
      sector = excluded.sector,
      asset_type = excluded.asset_type,
      mitre_tactics = excluded.mitre_tactics,
      mitre_techniques = excluded.mitre_techniques,
      nist_controls = excluded.nist_controls
  `),
  selectUnenriched: db.prepare(`
    SELECT id, source, external_id AS externalId, type, title, description, severity, vendor, product
    FROM threats WHERE sector IS NULL
  `),
  updateEnrichment: db.prepare(`
    UPDATE threats
    SET sector = @sector, asset_type = @asset_type, mitre_tactics = @mitre_tactics,
        mitre_techniques = @mitre_techniques, nist_controls = @nist_controls
    WHERE id = @id
  `),
  insertSyncLog: db.prepare(`
    INSERT INTO sync_log (source, status, message, items_fetched, items_new)
    VALUES (?, ?, ?, ?, ?)
  `),
  recentSyncLog: db.prepare(`SELECT * FROM sync_log ORDER BY ran_at DESC LIMIT ?`),
  countThreats: db.prepare(`SELECT COUNT(*) AS c FROM threats`),
};

/**
 * Upsert a normalized threat record. Returns true if it was a new row.
 * Sector / asset-type / MITRE ATT&CK / NIST tags are computed here so every
 * ingestion path (live sources, demo seed) gets them for free.
 */
export function upsertThreat(threat) {
  const { sector, assetType, mitreTactics, mitreTechniques, nistControls } = enrichThreat(threat);

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
    sector,
    asset_type: assetType,
    mitre_tactics: mitreTactics,
    mitre_techniques: JSON.stringify(mitreTechniques),
    nist_controls: JSON.stringify(nistControls),
  };
  const existing = statements.findThreatId.get(row.source, row.external_id);
  statements.upsertThreat.run(row);

  return !existing;
}

/**
 * Recomputes enrichment for rows stored before this feature existed
 * (sector IS NULL). Safe to call on every boot — it's a no-op once caught up.
 */
export function backfillEnrichment() {
  const rows = statements.selectUnenriched.all();
  if (!rows.length) return 0;

  const applyAll = db.transaction((items) => {
    for (const item of items) {
      const { sector, assetType, mitreTactics, mitreTechniques, nistControls } = enrichThreat(item);
      statements.updateEnrichment.run({
        id: item.id,
        sector,
        asset_type: assetType,
        mitre_tactics: mitreTactics,
        mitre_techniques: JSON.stringify(mitreTechniques),
        nist_controls: JSON.stringify(nistControls),
      });
    }
  });
  applyAll(rows);

  return rows.length;
}

backfillEnrichment();

export function logSync({ source, status, message = null, itemsFetched = 0, itemsNew = 0 }) {
  statements.insertSyncLog.run(source, status, message, itemsFetched, itemsNew);
}

export function getRecentSyncLog(limit = 20) {
  return statements.recentSyncLog.all(limit);
}

export function countThreats() {
  return statements.countThreats.get().c;
}

// better-sqlite3 finalizes all prepared statements synchronously inside
// close(). Without this, an abrupt process exit (Ctrl-C, `node --watch`
// restarting on a file change, a supervisor sending SIGTERM) can leave
// Statement objects to be finalized by GC *after* Node has already torn
// down the environment, which crashes the process natively. Closing
// explicitly on the way out avoids that race.
let closed = false;
function closeDb() {
  if (closed) return;
  closed = true;
  try {
    db.close();
  } catch {
    // already closed
  }
}
process.once("exit", closeDb);
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.once(signal, () => {
    closeDb();
    process.exit(0);
  });
}
