/**
 * Best-effort MITRE ATT&CK / NIST 800-53 tagging.
 *
 * None of the ingested feeds (CISA KEV, NVD, CISA advisories, URLhaus) carry
 * authoritative ATT&CK or NIST mappings, so this derives a reasonable guess
 * from keywords in the title/description. It's a heuristic aid for
 * triage/grouping, not an authoritative classification.
 */

const MITRE_RULES = [
  {
    keywords: ["command injection", "remote code execution", " rce ", "code execution", "arbitrary code"],
    tactic: "Execution",
    techniqueId: "T1059",
    techniqueName: "Command and Scripting Interpreter",
  },
  {
    keywords: ["sql injection"],
    tactic: "Initial Access",
    techniqueId: "T1190",
    techniqueName: "Exploit Public-Facing Application",
  },
  {
    keywords: ["authentication bypass", "auth bypass", "unauthenticated access", "bypass authentication"],
    tactic: "Defense Evasion",
    techniqueId: "T1556",
    techniqueName: "Modify Authentication Process",
  },
  {
    keywords: ["privilege escalation", "elevation of privilege", "escalate privileges"],
    tactic: "Privilege Escalation",
    techniqueId: "T1068",
    techniqueName: "Exploitation for Privilege Escalation",
  },
  {
    keywords: ["session token", "session hijack", "token disclosure", "cookie theft", "session cookie"],
    tactic: "Credential Access",
    techniqueId: "T1539",
    techniqueName: "Steal Web Session Cookie",
  },
  {
    keywords: ["buffer overflow", "out-of-bounds", "memory corruption", "stack overflow", "heap overflow"],
    tactic: "Execution",
    techniqueId: "T1203",
    techniqueName: "Exploitation for Client Execution",
  },
  {
    keywords: ["denial of service", "dos attack", "resource exhaustion"],
    tactic: "Impact",
    techniqueId: "T1499",
    techniqueName: "Endpoint Denial of Service",
  },
  {
    keywords: ["phishing", "spearphishing"],
    tactic: "Initial Access",
    techniqueId: "T1566",
    techniqueName: "Phishing",
  },
  {
    keywords: ["credential", "password spray", "unsecured credentials"],
    tactic: "Credential Access",
    techniqueId: "T1552",
    techniqueName: "Unsecured Credentials",
  },
  {
    keywords: ["malware", "loader", "trojan", "ransomware", "backdoor", "payload"],
    tactic: "Command and Control",
    techniqueId: "T1105",
    techniqueName: "Ingress Tool Transfer",
  },
  {
    keywords: ["path traversal", "directory traversal"],
    tactic: "Initial Access",
    techniqueId: "T1190",
    techniqueName: "Exploit Public-Facing Application",
  },
  {
    keywords: ["deserialization"],
    tactic: "Execution",
    techniqueId: "T1055",
    techniqueName: "Process Injection",
  },
];

const KEV_DEFAULT = {
  tactic: "Initial Access",
  techniqueId: "T1190",
  techniqueName: "Exploit Public-Facing Application",
};

const URLHAUS_DEFAULT = {
  tactic: "Command and Control",
  techniqueId: "T1071",
  techniqueName: "Application Layer Protocol",
};

/**
 * Returns a deduped array of {tactic, techniqueId, techniqueName} guessed
 * from free text, plus source-appropriate defaults for feeds whose entire
 * category implies a tactic (KEV = actively exploited, URLhaus = malware
 * delivery infrastructure).
 */
export function mapMitreAttack(text, { type, source } = {}) {
  const matches = new Map();
  for (const rule of MITRE_RULES) {
    if (rule.keywords.some((kw) => text.includes(kw))) {
      matches.set(rule.techniqueId, { tactic: rule.tactic, techniqueId: rule.techniqueId, techniqueName: rule.techniqueName });
    }
  }

  if (matches.size === 0) {
    if (source === "cisa-kev" || type === "vulnerability") {
      matches.set(KEV_DEFAULT.techniqueId, KEV_DEFAULT);
    } else if (type === "malware-url") {
      matches.set(URLHAUS_DEFAULT.techniqueId, URLHAUS_DEFAULT);
    }
  }

  return [...matches.values()].slice(0, 4);
}

const NIST_CATALOG = {
  "RA-5": "Vulnerability Monitoring and Scanning",
  "SI-2": "Flaw Remediation",
  "SI-3": "Malicious Code Protection",
  "SI-5": "Security Alerts, Advisories, and Directives",
  "SC-5": "Denial-of-Service Protection",
  "SC-7": "Boundary Protection",
  "AC-6": "Least Privilege",
  "IA-5": "Authenticator Management",
  "IR-4": "Incident Handling",
  "CA-7": "Continuous Monitoring",
};

/**
 * Maps a threat's type/severity/ATT&CK tactics to a small, deduped set of
 * relevant NIST 800-53 Rev.5 control IDs (name looked up from NIST_CATALOG).
 */
export function mapNistControls({ mitreTechniques = [], type, severity } = {}) {
  const ids = new Set();

  if (type === "vulnerability") {
    ids.add("RA-5");
    ids.add("SI-2");
  }
  if (type === "advisory") {
    ids.add("SI-5");
    ids.add("CA-7");
  }
  if (type === "malware-url") {
    ids.add("SI-3");
    ids.add("SC-7");
  }

  const tactics = new Set(mitreTechniques.map((t) => t.tactic));
  if (tactics.has("Credential Access")) ids.add("IA-5");
  if (tactics.has("Privilege Escalation") || tactics.has("Defense Evasion")) ids.add("AC-6");
  if (tactics.has("Impact")) ids.add("SC-5");
  if (tactics.has("Command and Control") || tactics.has("Execution")) ids.add("SI-3");
  if (tactics.has("Initial Access")) ids.add("SC-7");

  if (severity === "critical" || severity === "high") ids.add("IR-4");

  return [...ids].slice(0, 5).map((id) => ({ id, name: NIST_CATALOG[id] }));
}
