# SIREN — Threat Vector Console

A self-hosted console that tracks historical and incoming threat vectors by
ingesting public threat-intelligence feeds on a schedule, storing them in
SQLite, and surfacing them in a live dashboard.

## What it tracks

| Source | What it provides | Feed |
| --- | --- | --- |
| CISA Known Exploited Vulnerabilities (KEV) | Vulnerabilities with confirmed active exploitation | JSON, no key required |
| NVD CVE API 2.0 | Recently published CVEs with CVSS severity | JSON, no key required (optional API key raises the rate limit) |
| CISA Cybersecurity Advisories | ICS advisories, alerts, general advisories | RSS |
| abuse.ch URLhaus | Recently reported malware-distribution URLs | JSON, no key required |

Each source is fetched independently — if one is unreachable or rate-limited,
the others still ingest, and the failure is recorded in the ingestion log
instead of crashing the sync.

## Running it

```bash
npm install
cp .env.example .env   # optional: tune PORT, INGEST_CRON, NVD_API_KEY
npm start
```

Open `http://localhost:3000`. On boot the server performs an initial ingest
and then re-syncs on the schedule in `INGEST_CRON` (default: every 30
minutes). You can also trigger a sync manually from the "Sync Now" button in
the UI, or via:

```bash
npm run ingest   # one-off sync from the CLI
curl -X POST http://localhost:3000/api/ingest
```

For development, `npm run dev` runs the server under `node --watch-path=server`
so it restarts on code changes — scoped to `server/` so the SQLite file
under `data/` (which ingestion writes to constantly) doesn't itself trigger
restarts.

## Architecture

```
server/
  db.js                SQLite schema + upsert/log helpers (better-sqlite3)
  queries.js            Read-side queries used by the API (list/filter, stats, timeline)
  ingest.js             Orchestrates all sources, tolerates per-source failure
  scheduler.js           node-cron periodic ingestion
  seedDemo.js            Bundled demo dataset, loaded only if the store is
                          empty and every live source has failed, so the
                          console is never blank on a fresh install
  sources/
    cisaKev.js, nvdCve.js, cisaAdvisories.js, urlhaus.js
public/                  Static dashboard (vanilla HTML/CSS/JS, no build step)
```

Threats are deduped and upserted on `(source, external_id)`, so re-running
ingestion is safe and only new/changed items move the "new" counters.

### Sector / company / MITRE ATT&CK / NIST tagging

None of the ingested feeds carry sector, asset-type, MITRE ATT&CK, or NIST
800-53 classifications, so `server/enrich.js` + `server/mitreNist.js` derive
a best-effort tag for each threat from keyword matching against its
title/description/vendor/product at ingest time (see `upsertThreat` in
`server/db.js`). These are heuristics for triage and grouping, not an
authoritative classification — labeled as "(inferred)" in the UI.

- **Sector** — one of CISA's 16 critical infrastructure sectors, guessed
  from the vendor and text (defaults to "Information Technology").
- **Asset type** — `software` / `hardware` / `unknown`, guessed from
  keywords (firmware, router, appliance… vs. application, plugin, OS…).
- **MITRE ATT&CK** — up to 4 technique/tactic guesses from a keyword
  rule table, with feed-specific defaults (e.g. CISA KEV entries default to
  Initial Access / T1190 since inclusion implies active exploitation).
- **NIST 800-53** — a small set of relevant control IDs derived from the
  threat's type, severity, and inferred ATT&CK tactics.

The threat feed UI lets you click any card to see the full detail
(including these tags), group the feed by sector/company/severity, and
filter/search by software vs. hardware or by ATT&CK tactic — click a
sector/company tag on a card to filter to it directly.

## API

- `GET /api/threats?source=&severity=&type=&q=&since=&sector=&company=&assetType=&tactic=&limit=&offset=`
- `GET /api/threats/grouped?groupBy=sector|company|severity&...same filters as above&perGroup=&cap=`
- `GET /api/stats` — now also returns `bySector`, `byCompany`, `byAssetType`, `byTactic`
- `GET /api/timeline?days=30`
- `GET /api/sync-log?limit=20`
- `POST /api/ingest` — trigger a sync immediately

## Note on network access

Live ingestion requires outbound HTTPS to `cisa.gov`, `nvd.nist.gov`, and
`abuse.ch`. In network-restricted environments (locked-down CI, sandboxed
dev containers, corporate egress policies) those hosts may be blocked; the
console detects this (each source logs its own error) and falls back to a
small bundled demo dataset, with a banner in the UI explaining why. Once
deployed somewhere with normal outbound access, live data flows in on the
next scheduled sync no code changes needed.
