"""
Graph analytics: PageRank, betweenness centrality, Louvain community detection.

Uses the same GDS graph projection lifecycle as pathfinding.
"""

from neo4j import GraphDatabase

import config


GRAPH_NAME = "analyticsGraph"

_QUERY_PROJECT = """
MATCH (s:Asset)-[r:COMMUNICATES_WITH]->(t:Asset)
WHERE r.riskWeight IS NOT NULL
RETURN gds.graph.project($name, s, t,
  { relationshipProperties: r { .riskWeight } })
"""

_QUERY_DROP = "CALL gds.graph.drop($name, false)"


# ── PageRank (Step 6a) ──────────────────────────────────────

_QUERY_PAGERANK = """
CALL gds.pageRank.stream($graph, {
    relationshipWeightProperty: 'riskWeight'
})
YIELD nodeId, score
RETURN gds.util.asNode(nodeId).name AS asset,
       gds.util.asNode(nodeId).zone AS zone,
       score
ORDER BY score DESC
"""


def run_pagerank(session) -> list[dict]:
    records = session.run(_QUERY_PAGERANK, graph=GRAPH_NAME)
    results = [
        {"asset": r["asset"], "zone": r["zone"], "pagerank": r["score"]}
        for r in records
    ]
    print("  PageRank (top-5 influential assets):")
    for r in results[:5]:
        print(f"    {r['asset']:30s}  zone={r['zone']:<6s}  PR={r['pagerank']:.4f}")
    return results


# ── Betweenness Centrality (Step 6b) ────────────────────────

_QUERY_BETWEENNESS = """
CALL gds.betweenness.stream($graph)
YIELD nodeId, score
RETURN gds.util.asNode(nodeId).name AS asset,
       gds.util.asNode(nodeId).zone AS zone,
       score AS betweenness
ORDER BY betweenness DESC
"""


def run_betweenness(session) -> list[dict]:
    records = session.run(_QUERY_BETWEENNESS, graph=GRAPH_NAME)
    results = [
        {"asset": r["asset"], "zone": r["zone"], "betweenness": r["betweenness"]}
        for r in records
    ]
    print("\n  Betweenness Centrality (top-5 chokepoint assets):")
    for r in results[:5]:
        print(f"    {r['asset']:30s}  zone={r['zone']:<6s}  BC={r['betweenness']:.4f}")
    return results


# ── Louvain Community Detection (Step 6c) ───────────────────

_QUERY_LOUVAIN = """
CALL gds.louvain.stream($graph, {
    relationshipWeightProperty: 'riskWeight'
})
YIELD nodeId, communityId
RETURN communityId,
  collect(gds.util.asNode(nodeId).name) AS members,
  count(*) AS size
ORDER BY size DESC
"""


def run_louvain(session) -> list[dict]:
    records = session.run(_QUERY_LOUVAIN, graph=GRAPH_NAME)
    results = [
        {
            "communityId": r["communityId"],
            "members": list(r["members"]),
            "size": r["size"],
        }
        for r in records
    ]
    print(f"\n  Louvain Communities ({len(results)} detected):")
    for r in results:
        print(f"    Community {r['communityId']}: {r['members']} (size={r['size']})")
    return results


# ── Public entry point ───────────────────────────────────────

def run_analytics(driver) -> dict:
    """Run all graph analytics and return results dict."""
    print("Running graph analytics ...")
    results = {}

    with driver.session() as session:
        proj_result = session.run(_QUERY_PROJECT, name=GRAPH_NAME)
        proj_record = proj_result.single()

        if proj_record is None:
            print("  No edges with riskWeight found — skipping analytics.\n")
            return results

        print(f"  GDS graph '{GRAPH_NAME}' projected\n")

        try:
            results["pagerank"] = run_pagerank(session)
            results["betweenness"] = run_betweenness(session)
            results["louvain"] = run_louvain(session)
        finally:
            session.run(_QUERY_DROP, name=GRAPH_NAME).consume()
            print(f"\n  GDS graph '{GRAPH_NAME}' dropped")

    print("Analytics complete.\n")
    return results


if __name__ == "__main__":
    drv = GraphDatabase.driver(config.NEO4J_URI, auth=(config.NEO4J_USER, config.NEO4J_PASSWORD))
    try:
        run_analytics(drv)
    finally:
        drv.close()
