/**
 * Small bundled dataset used only when the console has zero threats stored
 * AND every live source failed (e.g. no network access yet). It lets the
 * dashboard render something meaningful instead of an empty screen, and is
 * clearly labeled as demo data in the UI (source: "demo-seed").
 */
const now = Date.now();
const daysAgo = (n) => new Date(now - n * 24 * 60 * 60 * 1000).toISOString();

export const DEMO_SEED = [
  {
    source: "demo-seed",
    externalId: "DEMO-2024-0001",
    type: "vulnerability",
    title: "CVE-2024-3400: PAN-OS GlobalProtect command injection",
    description:
      "Actively exploited command injection in Palo Alto Networks PAN-OS GlobalProtect gateway, added to CISA KEV shortly after disclosure.",
    severity: "critical",
    cvssScore: 10.0,
    vendor: "Palo Alto Networks",
    product: "PAN-OS",
    url: "https://nvd.nist.gov/vuln/detail/CVE-2024-3400",
    publishedAt: daysAgo(180),
  },
  {
    source: "demo-seed",
    externalId: "DEMO-2023-0002",
    type: "vulnerability",
    title: "CVE-2023-4966 (Citrix Bleed): session token disclosure",
    description:
      "Sensitive information disclosure in Citrix NetScaler ADC and Gateway, exploited to hijack authenticated sessions.",
    severity: "critical",
    cvssScore: 9.4,
    vendor: "Citrix",
    product: "NetScaler ADC/Gateway",
    url: "https://nvd.nist.gov/vuln/detail/CVE-2023-4966",
    publishedAt: daysAgo(300),
  },
  {
    source: "demo-seed",
    externalId: "DEMO-2024-0003",
    type: "advisory",
    title: "CISA Advisory: Increased activity targeting internet-exposed ICS devices",
    description:
      "CISA guidance on hardening internet-facing industrial control systems following observed opportunistic scanning and intrusion attempts.",
    severity: "high",
    cvssScore: null,
    vendor: null,
    product: null,
    url: "https://www.cisa.gov/news-events/cybersecurity-advisories",
    publishedAt: daysAgo(45),
  },
  {
    source: "demo-seed",
    externalId: "DEMO-2024-0004",
    type: "malware-url",
    title: "Malicious URL: example distributing commodity loader malware",
    description: "Reported malware-distribution URL serving a commodity loader payload.",
    severity: "medium",
    cvssScore: null,
    vendor: null,
    product: null,
    url: "https://urlhaus.abuse.ch/",
    publishedAt: daysAgo(2),
  },
  {
    source: "demo-seed",
    externalId: "DEMO-2024-0005",
    type: "vulnerability",
    title: "CVE-2024-21762: FortiOS out-of-bounds write",
    description:
      "Out-of-bounds write in FortiOS SSL-VPN allowing remote code execution without authentication; added to CISA KEV.",
    severity: "critical",
    cvssScore: 9.8,
    vendor: "Fortinet",
    product: "FortiOS",
    url: "https://nvd.nist.gov/vuln/detail/CVE-2024-21762",
    publishedAt: daysAgo(10),
  },
];
