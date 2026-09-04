import "dotenv/config";
import express from "express";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { listThreats, listThreatsGrouped, getStats, getTimeline } from "./queries.js";
import { getRecentSyncLog } from "./db.js";
import { runIngest } from "./ingest.js";
import { startScheduler } from "./scheduler.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3000;

const app = express();
app.use(express.static(path.join(__dirname, "..", "public")));

app.get("/api/health", (req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

app.get("/api/threats", (req, res) => {
  const { source, severity, type, q, since, sector, company, assetType, tactic, limit, offset } = req.query;
  res.json(listThreats({ source, severity, type, q, since, sector, company, assetType, tactic, limit, offset }));
});

app.get("/api/threats/grouped", (req, res) => {
  const { groupBy, source, severity, type, q, since, sector, company, assetType, tactic, perGroup, cap } = req.query;
  if (!["sector", "company", "severity"].includes(groupBy)) {
    return res.status(400).json({ error: "groupBy must be one of: sector, company, severity" });
  }
  res.json(
    listThreatsGrouped({ groupBy, source, severity, type, q, since, sector, company, assetType, tactic, perGroup, cap })
  );
});

app.get("/api/stats", (req, res) => {
  res.json(getStats());
});

app.get("/api/timeline", (req, res) => {
  res.json(getTimeline(req.query.days ? Number(req.query.days) : 30));
});

app.get("/api/sync-log", (req, res) => {
  res.json(getRecentSyncLog(req.query.limit ? Number(req.query.limit) : 20));
});

let ingestInFlight = null;
app.post("/api/ingest", (req, res) => {
  if (!ingestInFlight) {
    ingestInFlight = runIngest().finally(() => {
      ingestInFlight = null;
    });
  }
  ingestInFlight.then((results) => res.json({ triggered: true, results }));
});

app.listen(PORT, () => {
  console.log(`SIREN Threat Console listening on http://localhost:${PORT}`);
  startScheduler();
});
