import { fetchJson } from "./fetchUtil.js";

const FEED_URL = "https://urlhaus.abuse.ch/downloads/json_recent/";

export const SOURCE_NAME = "urlhaus";

/**
 * abuse.ch URLhaus: recently reported malware-distribution URLs.
 * The feed is a map of id -> [entry], not a flat array.
 */
export async function fetchUrlhaus() {
  const data = await fetchJson(FEED_URL);
  const entries = Object.values(data || {})
    .map((v) => (Array.isArray(v) ? v[0] : v))
    .filter(Boolean);

  return entries.map((e) => {
    const tags = Array.isArray(e.tags) ? e.tags.join(", ") : e.tags || "";
    return {
      source: SOURCE_NAME,
      externalId: String(e.id ?? e.url),
      type: "malware-url",
      title: `Malicious URL: ${e.host || e.url}`,
      description: [e.threat, tags ? `Tags: ${tags}` : null].filter(Boolean).join(" — "),
      severity: e.url_status === "online" ? "high" : "medium",
      cvssScore: null,
      vendor: null,
      product: null,
      url: e.urlhaus_reference || e.url,
      publishedAt: e.dateadded ? e.dateadded.replace(" ", "T") + "Z" : new Date().toISOString(),
      raw: e,
    };
  });
}
