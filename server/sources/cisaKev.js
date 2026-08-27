import { fetchJson } from "./fetchUtil.js";

const FEED_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

export const SOURCE_NAME = "cisa-kev";

/**
 * CISA Known Exploited Vulnerabilities catalog: vulnerabilities with confirmed
 * active exploitation in the wild. Every entry is treated as critical/incoming
 * since inclusion itself is the signal.
 */
export async function fetchCisaKev() {
  const data = await fetchJson(FEED_URL);
  const vulns = data.vulnerabilities || [];

  return vulns.map((v) => ({
    source: SOURCE_NAME,
    externalId: v.cveID,
    type: "vulnerability",
    title: `${v.cveID}: ${v.vulnerabilityName}`,
    description: [v.shortDescription, v.requiredAction ? `Required action: ${v.requiredAction}` : null]
      .filter(Boolean)
      .join(" "),
    severity: "critical",
    cvssScore: null,
    vendor: v.vendorProject,
    product: v.product,
    url: `https://nvd.nist.gov/vuln/detail/${v.cveID}`,
    publishedAt: v.dateAdded,
    raw: v,
  }));
}
