import os

# ── Neo4j connection ──
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "graphcyber")

# ── External APIs ──
EPSS_API_URL = "https://api.first.org/data/v1/epss"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY", "")  # optional; increases rate limit
NVD_RATE_LIMIT_SLEEP = 6.5 if not NVD_API_KEY else 0.7  # seconds between requests

# ── BRIDG-ICS control-factor defaults (Appendix A) ──
# Uncontrolled baseline
CONTROL_FACTORS_BASELINE = {"a": 0.03, "c": 0.04, "e": 0.03, "h": 0.05}

# After NIST SP 800-53 / IEC 62443 mitigations
CONTROL_FACTORS_CONTROLLED = {"a": 0.005, "c": 0.01, "e": 0.005, "h": 0.01}

# Edges below this riskWeight are treated as non-exploitable (Section 4.3.2)
RISK_WEIGHT_THRESHOLD = 0.05

# ── Pathfinding defaults ──
YEN_K = 20
DEFAULT_SOURCE = "MQTT_Broker"
DEFAULT_TARGET = "Safety_PLC"

# ── BloodHound dataset ──
BLOODHOUND_JSON_URL = (
    "https://raw.githubusercontent.com/neo4j-graph-examples/"
    "cybersecurity/main/data/cybersecurity-json-data.json"
)
BLOODHOUND_JSON_LOCAL = "data_dumps/cybersecurity-json-data.json"
DEFAULT_SOURCE_BH = "PiedadFlatley255@TestCompany.Local"
DEFAULT_TARGET_BH = "DOMAIN ADMINS@TestCompany.Local"

# ── CVSS vector factor mappings for attackCost (Eq. 5) ──
# Maps CVSS v3.1 Access Complexity values to numeric factors
F_AC = {"L": 0.1, "H": 0.5}
# Maps CVSS v3.1 Attack Vector values to numeric factors
F_AV = {"N": 0.1, "A": 0.3, "L": 0.5, "P": 0.8}
