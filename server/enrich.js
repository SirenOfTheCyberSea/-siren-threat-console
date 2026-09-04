import { mapMitreAttack, mapNistControls } from "./mitreNist.js";

/**
 * CISA's 16 critical infrastructure sectors, plus a general IT bucket used
 * as the default for feeds (most CVEs/malware don't name a sector at all).
 */
export const SECTORS = [
  "Chemical",
  "Commercial Facilities",
  "Communications",
  "Critical Manufacturing",
  "Dams",
  "Defense Industrial Base",
  "Emergency Services",
  "Energy",
  "Financial Services",
  "Food and Agriculture",
  "Government Facilities",
  "Healthcare and Public Health",
  "Information Technology",
  "Nuclear Reactors, Materials, and Waste",
  "Transportation Systems",
  "Water and Wastewater Systems",
];

const VENDOR_SECTORS = [
  { keywords: ["siemens", "schneider", "rockwell", "honeywell", "abb", "mitsubishi electric", "emerson"], sector: "Critical Manufacturing" },
  { keywords: ["medtronic", "philips healthcare", "ge healthcare", "baxter"], sector: "Healthcare and Public Health" },
  { keywords: ["lockheed", "raytheon", "northrop", "general dynamics", "l3harris", "boeing defense"], sector: "Defense Industrial Base" },
  { keywords: ["nokia", "ericsson", "verizon", "at&t", "t-mobile"], sector: "Communications" },
  {
    keywords: [
      "palo alto", "fortinet", "cisco", "citrix", "juniper", "sonicwall", "check point", "microsoft",
      "vmware", "ivanti", "atlassian", "oracle", "sap", "adobe", "apache", "google", "apple", "fortios",
    ],
    sector: "Information Technology",
  },
];

const KEYWORD_SECTORS = [
  { keywords: ["hospital", "medical device", "healthcare", "patient data", "clinical"], sector: "Healthcare and Public Health" },
  { keywords: ["bank", "financial institution", "payment card", "swift network", "trading platform"], sector: "Financial Services" },
  { keywords: ["power grid", "electric utility", "substation", "energy sector", "pipeline"], sector: "Energy" },
  { keywords: ["water treatment", "wastewater", "water utility"], sector: "Water and Wastewater Systems" },
  { keywords: ["election", "voting system", "federal agency", "municipal government"], sector: "Government Facilities" },
  { keywords: ["airline", "aviation", "railway", "maritime", "transit system"], sector: "Transportation Systems" },
  { keywords: ["telecom", "cellular network", "5g network"], sector: "Communications" },
  { keywords: ["defense contractor", "military network", "weapons system"], sector: "Defense Industrial Base" },
  { keywords: ["food processing", "agriculture", "farm equipment"], sector: "Food and Agriculture" },
  { keywords: ["chemical plant", "chemical facility"], sector: "Chemical" },
  { keywords: ["nuclear", "radioactive material"], sector: "Nuclear Reactors, Materials, and Waste" },
  { keywords: ["dam ", "reservoir"], sector: "Dams" },
  { keywords: ["emergency response", "911 system", "first responder"], sector: "Emergency Services" },
  { keywords: ["casino", "hotel chain", "shopping mall", "stadium"], sector: "Commercial Facilities" },
  { keywords: ["ics advisory", "scada", " plc ", "industrial control system"], sector: "Critical Manufacturing" },
];

function classifySector(threat, text) {
  const vendor = (threat.vendor || "").toLowerCase();
  for (const rule of VENDOR_SECTORS) {
    if (rule.keywords.some((kw) => vendor.includes(kw))) return rule.sector;
  }
  for (const rule of KEYWORD_SECTORS) {
    if (rule.keywords.some((kw) => text.includes(kw))) return rule.sector;
  }
  return "Information Technology";
}

const HARDWARE_KEYWORDS = [
  "firmware", "router", "switch", "firewall", "gateway", "appliance", "iot device", "camera",
  "sensor", "controller", " plc ", "modem", "printer", "nas device", "access point", "embedded device",
];
const SOFTWARE_KEYWORDS = [
  "software", "application", "plugin", "cms", "wordpress", "framework", "library", "browser",
  "operating system", "database", " api ", "sdk", "server software", "website", "web app",
  "malware", "loader", "trojan", "ransomware", "backdoor",
];

function classifyAssetType(threat, text) {
  if (HARDWARE_KEYWORDS.some((kw) => text.includes(kw))) return "hardware";
  if (SOFTWARE_KEYWORDS.some((kw) => text.includes(kw))) return "software";
  if (threat.type === "vulnerability") return "software";
  if (threat.type === "malware-url") return "software";
  return "unknown";
}

/**
 * Computes sector / asset-type / MITRE ATT&CK / NIST 800-53 tags for a
 * normalized threat record. These are best-effort heuristics derived from
 * keyword matching, not authoritative classifications — the source feeds
 * don't provide this mapping themselves.
 */
export function enrichThreat(threat) {
  const text = `${threat.title || ""} ${threat.description || ""} ${threat.vendor || ""} ${threat.product || ""}`.toLowerCase();

  const sector = classifySector(threat, text);
  const assetType = classifyAssetType(threat, text);
  const mitreTechniques = mapMitreAttack(text, { type: threat.type, source: threat.source });
  const mitreTactics = [...new Set(mitreTechniques.map((t) => t.tactic))].join(", ");
  const nistControls = mapNistControls({
    mitreTechniques,
    type: threat.type,
    severity: (threat.severity || "unknown").toLowerCase(),
  });

  return { sector, assetType, mitreTactics, mitreTechniques, nistControls };
}
