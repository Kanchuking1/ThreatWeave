"""
BRIDG-ICS risk model (Eqs. 3-8).

Computes controlStrength, pExploit, attackCost, riskWeight on
COMMUNICATES_WITH edges, then derives node-level exposure.
Optionally creates CONTROLLED_COMMUNICATES_WITH edges with
improved control factors and prunes non-exploitable links.
"""

import re
from neo4j import GraphDatabase

import config


# ── CVSS vector parsing helpers ──────────────────────────────

def _parse_cvss_vector(vector_string: str | None) -> tuple[float, float]:
    """Return (f_AC, f_AV) numeric factors from a CVSS v3.x vector string."""
    if not vector_string:
        return 0.3, 0.3  # moderate defaults

    ac_match = re.search(r"AC:([LH])", vector_string)
    av_match = re.search(r"AV:([NALP])", vector_string)

    f_ac = config.F_AC.get(ac_match.group(1), 0.3) if ac_match else 0.3
    f_av = config.F_AV.get(av_match.group(1), 0.3) if av_match else 0.3
    return f_ac, f_av


# ── Step 4a: controlStrength (Eq. 3) ─────────────────────────

_QUERY_CONTROL_STRENGTH = """
MATCH ()-[c:COMMUNICATES_WITH]->()
SET c.controlStrength = c.a * c.c * c.e * c.h
"""


def compute_control_strength(session):
    session.run(_QUERY_CONTROL_STRENGTH)
    print("  [Eq.3] controlStrength computed on all COMMUNICATES_WITH edges")


# ── Step 4b: pExploit (Eq. 4) ────────────────────────────────

_QUERY_PEXPLOIT = """
MATCH (a:Asset)-[comm:COMMUNICATES_WITH]->(b:Asset)
OPTIONAL MATCH (b)-[:HAS_VULNERABILITY]->(v:Vulnerability)
WHERE v.epss_score IS NOT NULL
WITH a, b, comm, collect(v.epss_score) AS epss_list
WITH a, b, comm,
     CASE WHEN size(epss_list) = 0 THEN 0.0
          ELSE 1.0 - reduce(prod = 1.0, ep IN epss_list | prod * (1.0 - ep))
     END AS combinedEPSS
SET comm.pExploit = combinedEPSS * (1.0 - comm.controlStrength)
"""


def compute_pexploit(session):
    session.run(_QUERY_PEXPLOIT)
    print("  [Eq.4] pExploit computed (EPSS aggregation + control attenuation)")


# ── Step 4c: attackCost (Eq. 5) ──────────────────────────────
# This requires Python-side CVSS vector parsing, so we pull data,
# compute in Python, and push back.

_QUERY_FETCH_EDGE_VULNS = """
MATCH (a:Asset)-[comm:COMMUNICATES_WITH]->(b:Asset)
OPTIONAL MATCH (b)-[:HAS_VULNERABILITY]->(v:Vulnerability)
WHERE v.cvss_base_score IS NOT NULL
WITH a, b, comm, collect({
    base: v.cvss_base_score,
    vector: v.cvss_vector,
    epss: COALESCE(v.epss_score, 0.0)
}) AS vulns
RETURN elementId(comm) AS rel_id, vulns
"""

_QUERY_SET_ATTACK_COST = """
UNWIND $rows AS row
MATCH ()-[c:COMMUNICATES_WITH]->()
WHERE elementId(c) = row.rel_id
SET c.attackCost = row.cost
"""


def compute_attack_cost(session):
    records = list(session.run(_QUERY_FETCH_EDGE_VULNS))
    rows = []
    for rec in records:
        vulns = rec["vulns"]
        if not vulns or vulns == [None]:
            rows.append({"rel_id": rec["rel_id"], "cost": 0.0})
            continue

        max_cost = 0.0
        for v in vulns:
            if v is None or v.get("base") is None:
                continue
            f_ac, f_av = _parse_cvss_vector(v.get("vector"))
            cost = v["base"] + f_ac + f_av + v.get("epss", 0.0)
            max_cost = max(max_cost, cost)
        rows.append({"rel_id": rec["rel_id"], "cost": max_cost})

    session.run(_QUERY_SET_ATTACK_COST, rows=rows)
    print(f"  [Eq.5] attackCost computed for {len(rows)} edges")


# ── Step 4d: riskWeight (Eq. 6) ──────────────────────────────

_QUERY_RISK_WEIGHT = """
MATCH (a:Asset)-[comm:COMMUNICATES_WITH]->(b:Asset)
SET comm.riskWeight = comm.pExploit * b.criticality_score / 10.0
"""


def compute_risk_weight(session):
    session.run(_QUERY_RISK_WEIGHT)
    print("  [Eq.6] riskWeight computed on all COMMUNICATES_WITH edges")


# ── Step 4e: node exposure (Eq. 8) ───────────────────────────

_QUERY_EXPOSURE = """
MATCH (a:Asset)
OPTIONAL MATCH (a)<-[c:COMMUNICATES_WITH]-()
WITH a, COALESCE(SUM(c.riskWeight), 0.0) AS exposure
SET a.exposure = exposure
"""


def compute_node_exposure(session):
    session.run(_QUERY_EXPOSURE)
    print("  [Eq.8] Node exposure computed on all Asset nodes")


# ── Step 4f: CONTROLLED_COMMUNICATES_WITH ─────────────────────

_QUERY_CREATE_CONTROLLED = """
MATCH (a:Asset)-[c:COMMUNICATES_WITH]->(b:Asset)
MERGE (a)-[cc:CONTROLLED_COMMUNICATES_WITH]->(b)
SET cc.protocol = c.protocol,
    cc.a = $a, cc.c = $c, cc.e = $e, cc.h = $h,
    cc.controlStrength = $a * $c * $e * $h
"""

_QUERY_CONTROLLED_PEXPLOIT = """
MATCH (a:Asset)-[cc:CONTROLLED_COMMUNICATES_WITH]->(b:Asset)
OPTIONAL MATCH (b)-[:HAS_VULNERABILITY]->(v:Vulnerability)
WHERE v.epss_score IS NOT NULL
WITH a, b, cc, collect(v.epss_score) AS epss_list
WITH a, b, cc,
     CASE WHEN size(epss_list) = 0 THEN 0.0
          ELSE 1.0 - reduce(prod = 1.0, ep IN epss_list | prod * (1.0 - ep))
     END AS combinedEPSS
SET cc.pExploit = combinedEPSS * (1.0 - cc.controlStrength)
"""

_QUERY_CONTROLLED_RISK_WEIGHT = """
MATCH (a:Asset)-[cc:CONTROLLED_COMMUNICATES_WITH]->(b:Asset)
SET cc.riskWeight = cc.pExploit * b.criticality_score / 10.0
"""

_QUERY_PRUNE_NON_EXPLOITABLE = """
MATCH ()-[cc:CONTROLLED_COMMUNICATES_WITH]->()
WHERE cc.riskWeight < $threshold
DELETE cc
"""

_QUERY_CONTROLLED_EXPOSURE = """
MATCH (a:Asset)
OPTIONAL MATCH (a)<-[cc:CONTROLLED_COMMUNICATES_WITH]-()
WITH a, COALESCE(SUM(cc.riskWeight), 0.0) AS ctrl_exposure
SET a.controlled_exposure = ctrl_exposure
"""


def create_controlled_edges(session):
    cf = config.CONTROL_FACTORS_CONTROLLED
    session.run(_QUERY_CREATE_CONTROLLED, a=cf["a"], c=cf["c"], e=cf["e"], h=cf["h"])
    session.run(_QUERY_CONTROLLED_PEXPLOIT)
    session.run(_QUERY_CONTROLLED_RISK_WEIGHT)
    result = session.run(
        _QUERY_PRUNE_NON_EXPLOITABLE, threshold=config.RISK_WEIGHT_THRESHOLD
    )
    summary = result.consume()
    deleted = summary.counters.relationships_deleted
    print(f"  [Controlled] Created CONTROLLED_COMMUNICATES_WITH edges, pruned {deleted} non-exploitable")
    session.run(_QUERY_CONTROLLED_EXPOSURE)
    print("  [Controlled] Controlled exposure computed")


# ── Public entry point ───────────────────────────────────────

def run_risk_model(driver, with_controls: bool = False):
    """Compute all BRIDG-ICS risk metrics."""
    print("Computing BRIDG-ICS risk metrics ...")
    with driver.session() as session:
        compute_control_strength(session)
        compute_pexploit(session)
        compute_attack_cost(session)
        compute_risk_weight(session)
        compute_node_exposure(session)

        if with_controls:
            create_controlled_edges(session)

    print("Risk model complete.\n")


if __name__ == "__main__":
    drv = GraphDatabase.driver(config.NEO4J_URI, auth=(config.NEO4J_USER, config.NEO4J_PASSWORD))
    try:
        run_risk_model(drv, with_controls=True)
    finally:
        drv.close()
