import { XMLParser } from "fast-xml-parser";
import { fetchText } from "./fetchUtil.js";

const FEED_URL = "https://www.cisa.gov/cybersecurity-advisories/all.xml";

export const SOURCE_NAME = "cisa-advisories";

const parser = new XMLParser({ ignoreAttributes: false });

function guessSeverity(title = "") {
  const t = title.toLowerCase();
  if (t.includes("critical")) return "critical";
  if (t.includes("ics advisory") || t.includes("ics medical advisory")) return "high";
  return "medium";
}

function extractId(link = "", guid = "") {
  const source = guid || link;
  const match = source.match(/([A-Z]{2,4}-\d{2}-\d{2,3}-\d{2,3})/i) || source.match(/\/([^/]+)\/?$/);
  return match ? match[1] : source;
}

/**
 * CISA's public "all cybersecurity advisories" RSS feed: ICS advisories,
 * alerts, and general advisories as CISA publishes them.
 */
export async function fetchCisaAdvisories() {
  const xml = await fetchText(FEED_URL);
  const doc = parser.parse(xml);
  const items = doc?.rss?.channel?.item;
  const list = Array.isArray(items) ? items : items ? [items] : [];

  return list.map((item) => {
    const title = String(item.title ?? "");
    const link = String(item.link ?? "");
    const guid = typeof item.guid === "object" ? item.guid["#text"] : item.guid;
    const publishedAt = item.pubDate ? new Date(item.pubDate).toISOString() : new Date().toISOString();

    return {
      source: SOURCE_NAME,
      externalId: extractId(link, guid ? String(guid) : ""),
      type: "advisory",
      title,
      description: String(item.description ?? ""),
      severity: guessSeverity(title),
      cvssScore: null,
      vendor: null,
      product: null,
      url: link,
      publishedAt,
      raw: item,
    };
  });
}
