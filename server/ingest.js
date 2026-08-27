import "dotenv/config";
import { upsertThreat, logSync, countThreats } from "./db.js";
import { fetchCisaKev, SOURCE_NAME as KEV_SOURCE } from "./sources/cisaKev.js";
import { fetchNvdCve, SOURCE_NAME as NVD_SOURCE } from "./sources/nvdCve.js";
import { fetchCisaAdvisories, SOURCE_NAME as ADVISORY_SOURCE } from "./sources/cisaAdvisories.js";
import { fetchUrlhaus, SOURCE_NAME as URLHAUS_SOURCE } from "./sources/urlhaus.js";
import { DEMO_SEED } from "./seedDemo.js";

const SOURCES = [
  { name: KEV_SOURCE, fetch: fetchCisaKev },
  { name: NVD_SOURCE, fetch: () => fetchNvdCve({ days: 7, apiKey: process.env.NVD_API_KEY || undefined }) },
  { name: ADVISORY_SOURCE, fetch: fetchCisaAdvisories },
  { name: URLHAUS_SOURCE, fetch: fetchUrlhaus },
];

async function runSource({ name, fetch }) {
  try {
    const threats = await fetch();
    let itemsNew = 0;
    for (const threat of threats) {
      if (!threat.externalId || !threat.publishedAt) continue;
      if (upsertThreat(threat)) itemsNew++;
    }
    logSync({ source: name, status: "success", itemsFetched: threats.length, itemsNew });
    return { name, ok: true, itemsFetched: threats.length, itemsNew };
  } catch (err) {
    const message = err?.message || String(err);
    logSync({ source: name, status: "error", message });
    return { name, ok: false, error: message };
  }
}

/**
 * Runs every configured source, tolerating individual failures. If the
 * store is still empty afterwards (fresh install with no network access to
 * the live feeds yet), loads the bundled demo dataset so the console isn't
 * blank, clearly labeled with source "demo-seed".
 */
export async function runIngest() {
  const results = [];
  for (const source of SOURCES) {
    results.push(await runSource(source));
  }

  if (countThreats() === 0) {
    for (const threat of DEMO_SEED) upsertThreat(threat);
    logSync({
      source: "demo-seed",
      status: "info",
      message: "Loaded bundled demo dataset because no live sources returned data yet.",
      itemsFetched: DEMO_SEED.length,
      itemsNew: DEMO_SEED.length,
    });
  }

  return results;
}

// Allow `npm run ingest` for a one-off manual sync.
if (import.meta.url === `file://${process.argv[1]}`) {
  const results = await runIngest();
  for (const r of results) {
    if (r.ok) {
      console.log(`[${r.name}] ok — ${r.itemsFetched} fetched, ${r.itemsNew} new`);
    } else {
      console.error(`[${r.name}] FAILED — ${r.error}`);
    }
  }
  process.exit(0);
}
