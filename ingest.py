"""
Threat intelligence ingestion: fetch live EPSS and CVSS data, push into Neo4j.
"""

import time
import requests
from neo4j import GraphDatabase

import config


def _get_cve_ids(driver):
    """Return all CVE IDs currently stored in the graph."""
    with driver.session() as session:
        result = session.run("MATCH (v:Vulnerability) RETURN v.cve_id AS cve_id")
        return [record["cve_id"] for record in result]


# ── EPSS ingestion ───────────────────────────────────────────

def fetch_epss_scores(cve_ids: list[str]) -> dict[str, float]:
    """Batch-fetch EPSS exploitation-probability scores from the FIRST API."""
    if not cve_ids:
        return {}

    params = {"cve": ",".join(cve_ids)}
    resp = requests.get(config.EPSS_API_URL, params=params, timeout=30)
    resp.raise_for_status()
    data = resp.json().get("data", [])
    return {entry["cve"]: float(entry["epss"]) for entry in data}


def push_epss_scores(driver, scores: dict[str, float]):
    """Write EPSS scores to Vulnerability nodes."""
    query = """
    UNWIND $rows AS row
    MATCH (v:Vulnerability {cve_id: row.cve})
    SET v.epss_score = row.epss
    """
    rows = [{"cve": cve, "epss": epss} for cve, epss in scores.items()]
    with driver.session() as session:
        session.run(query, rows=rows)
    print(f"  [EPSS] Updated {len(rows)} vulnerabilities")


# ── CVSS ingestion ───────────────────────────────────────────

def _parse_cvss_from_nvd(metrics: dict) -> tuple[float | None, str | None]:
    """Extract baseScore and vectorString with v4.0 -> v3.1 -> v2 fallback."""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            score = cvss_data.get("baseScore")
            vector = cvss_data.get("vectorString")
            if score is not None:
                return float(score), vector
    return None, None


def fetch_cvss_scores(cve_ids: list[str]) -> dict[str, dict]:
    """Fetch CVSS base scores + vectors from the NVD API 2.0 (one at a time)."""
    results = {}
    headers = {}
    if config.NVD_API_KEY:
        headers["apiKey"] = config.NVD_API_KEY

    for cve_id in cve_ids:
        try:
            resp = requests.get(
                config.NVD_API_URL,
                params={"cveId": cve_id},
                headers=headers,
                timeout=30,
            )
            resp.raise_for_status()
            vulns = resp.json().get("vulnerabilities", [])
            if vulns:
                metrics = vulns[0].get("cve", {}).get("metrics", {})
                score, vector = _parse_cvss_from_nvd(metrics)
                if score is not None:
                    results[cve_id] = {"score": score, "vector": vector}
        except requests.RequestException as exc:
            print(f"  [CVSS] Warning: failed to fetch {cve_id}: {exc}")

        time.sleep(config.NVD_RATE_LIMIT_SLEEP)

    return results


def push_cvss_scores(driver, scores: dict[str, dict]):
    """Write CVSS base scores and vectors to Vulnerability nodes."""
    query = """
    UNWIND $rows AS row
    MATCH (v:Vulnerability {cve_id: row.cve})
    SET v.cvss_base_score = row.score, v.cvss_vector = row.vector
    """
    rows = [
        {"cve": cve, "score": info["score"], "vector": info["vector"]}
        for cve, info in scores.items()
    ]
    with driver.session() as session:
        session.run(query, rows=rows)
    print(f"  [CVSS] Updated {len(rows)} vulnerabilities")


# ── Public entry point ───────────────────────────────────────

def run_ingestion(driver):
    """Fetch EPSS + CVSS for all CVEs in the graph and push results."""
    cve_ids = _get_cve_ids(driver)
    print(f"Ingesting threat intelligence for {len(cve_ids)} CVEs ...")

    epss_scores = fetch_epss_scores(cve_ids)
    push_epss_scores(driver, epss_scores)

    cvss_scores = fetch_cvss_scores(cve_ids)
    push_cvss_scores(driver, cvss_scores)

    print("Ingestion complete.\n")


if __name__ == "__main__":
    drv = GraphDatabase.driver(config.NEO4J_URI, auth=(config.NEO4J_USER, config.NEO4J_PASSWORD))
    try:
        run_ingestion(drv)
    finally:
        drv.close()
