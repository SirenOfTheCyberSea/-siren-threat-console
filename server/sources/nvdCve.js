import { fetchJson } from "./fetchUtil.js";

const API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";

export const SOURCE_NAME = "nvd";

function isoNoMillis(date) {
  return date.toISOString().replace("Z", "");
}

function pickCvss(metrics = {}) {
  const preference = ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"];
  for (const key of preference) {
    const entries = metrics[key];
    if (entries && entries.length) {
      const data = entries[0].cvssData;
      return {
        score: data.baseScore ?? null,
        severity: (entries[0].baseSeverity || data.baseSeverity || "unknown").toLowerCase(),
      };
    }
  }
  return { score: null, severity: "unknown" };
}

/**
 * Recently published CVEs from the National Vulnerability Database.
 * NVD's public API allows unauthenticated access at a low rate limit,
 * so this pulls a bounded recent window rather than the full catalog.
 */
export async function fetchNvdCve({ days = 7, resultsPerPage = 200, apiKey } = {}) {
  const end = new Date();
  const start = new Date(end.getTime() - days * 24 * 60 * 60 * 1000);

  const params = new URLSearchParams({
    pubStartDate: isoNoMillis(start),
    pubEndDate: isoNoMillis(end),
    resultsPerPage: String(resultsPerPage),
  });

  const data = await fetchJson(`${API_URL}?${params}`, {
    headers: apiKey ? { apiKey } : {},
  });

  const items = data.vulnerabilities || [];

  return items.map(({ cve }) => {
    const { score, severity } = pickCvss(cve.metrics);
    const description =
      cve.descriptions?.find((d) => d.lang === "en")?.value || cve.descriptions?.[0]?.value || "";
    const cpe = cve.configurations?.[0]?.nodes?.[0]?.cpeMatch?.[0]?.criteria;

    return {
      source: SOURCE_NAME,
      externalId: cve.id,
      type: "vulnerability",
      title: `${cve.id}`,
      description,
      severity,
      cvssScore: score,
      vendor: cpe ? cpe.split(":")[3] : null,
      product: cpe ? cpe.split(":")[4] : null,
      url: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
      publishedAt: cve.published,
      raw: cve,
    };
  });
}
