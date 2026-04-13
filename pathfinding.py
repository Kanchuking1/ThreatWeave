"""
GDS pathfinding: Dijkstra source-target + Yen k-shortest paths.

Projects the COMMUNICATES_WITH graph into GDS, runs algorithms,
computes multi-hop attack probability (Eq. 7), and cleans up.
"""

from functools import reduce
from neo4j import GraphDatabase

import config


GRAPH_NAME = "cyberGraph"

# ── Graph projection ─────────────────────────────────────────

_QUERY_PROJECT = """
MATCH (s:Asset)-[r:COMMUNICATES_WITH]->(t:Asset)
WHERE r.riskWeight IS NOT NULL
RETURN gds.graph.project($name, s, t,
  { relationshipProperties: r { .riskWeight, .pExploit, .attackCost } })
"""

_QUERY_DROP = "CALL gds.graph.drop($name, false)"


def project_graph(session) -> bool:
    """Project the graph into GDS. Returns False if no edges matched."""
    result = session.run(_QUERY_PROJECT, name=GRAPH_NAME)
    record = result.single()
    if record is None:
        print("  No edges with riskWeight found — cannot project graph.")
        return False
    print(f"  GDS graph '{GRAPH_NAME}' projected")
    return True


def drop_graph(session):
    session.run(_QUERY_DROP, name=GRAPH_NAME).consume()
    print(f"  GDS graph '{GRAPH_NAME}' dropped")


# ── Dijkstra source-target (Step 5b) ─────────────────────────

_QUERY_DIJKSTRA = """
MATCH (source:Asset {name: $source}), (target:Asset {name: $target})
CALL gds.shortestPath.dijkstra.stream($graph, {
    sourceNode: source,
    targetNode: target,
    relationshipWeightProperty: 'riskWeight'
})
YIELD index, sourceNode, targetNode, totalCost, nodeIds, costs, path
RETURN
  [nid IN nodeIds | gds.util.asNode(nid).name] AS pathNames,
  totalCost,
  costs
"""


def run_dijkstra(session, source: str, target: str) -> list[dict]:
    result = session.run(
        _QUERY_DIJKSTRA, graph=GRAPH_NAME, source=source, target=target
    )
    paths = []
    for rec in result:
        paths.append({
            "nodes": list(rec["pathNames"]),
            "totalCost": rec["totalCost"],
            "costs": list(rec["costs"]),
        })
    return paths


# ── Yen k-shortest paths (Step 5c) ──────────────────────────

_QUERY_YEN = """
MATCH (source:Asset {name: $source}), (target:Asset {name: $target})
CALL gds.shortestPath.yens.stream($graph, {
    sourceNode: source,
    targetNode: target,
    k: $k,
    relationshipWeightProperty: 'riskWeight'
})
YIELD index, totalCost, nodeIds, costs
RETURN index,
  [nid IN nodeIds | gds.util.asNode(nid).name] AS pathNames,
  totalCost,
  costs
ORDER BY totalCost ASC
"""


def run_yen(session, source: str, target: str, k: int = config.YEN_K) -> list[dict]:
    result = session.run(
        _QUERY_YEN, graph=GRAPH_NAME, source=source, target=target, k=k
    )
    paths = []
    for rec in result:
        paths.append({
            "index": rec["index"],
            "nodes": list(rec["pathNames"]),
            "totalCost": rec["totalCost"],
            "costs": list(rec["costs"]),
        })
    return paths


# ── Multi-hop attack probability (Eq. 7) ────────────────────

_QUERY_EDGE_PEXPLOIT = """
MATCH (a:Asset {name: $src})-[c:COMMUNICATES_WITH]->(b:Asset {name: $tgt})
RETURN c.pExploit AS pExploit
LIMIT 1
"""


def compute_path_probability(session, path_nodes: list[str]) -> float:
    """Compute p(P) = product(pExploit(vi, vi+1)) along a path."""
    p_values = []
    for i in range(len(path_nodes) - 1):
        rec = session.run(
            _QUERY_EDGE_PEXPLOIT, src=path_nodes[i], tgt=path_nodes[i + 1]
        ).single()
        p = rec["pExploit"] if rec and rec["pExploit"] is not None else 0.0
        p_values.append(p)

    return reduce(lambda a, b: a * b, p_values, 1.0)


# ── Pretty-print helpers ────────────────────────────────────

def _fmt_path(path: dict, probability: float | None = None) -> str:
    chain = " -> ".join(path["nodes"])
    line = f"  {chain}  (totalCost={path['totalCost']:.4f})"
    if probability is not None:
        line += f"  p(attack)={probability:.6f}"
    return line


# ── Public entry point ───────────────────────────────────────

def run_pathfinding(driver, source: str, target: str) -> dict:
    """Run Dijkstra + Yen k-shortest and return results dict."""
    print(f"Pathfinding: {source} -> {target} ...")
    results = {"dijkstra": [], "yen": []}

    with driver.session() as session:
        if not project_graph(session):
            print("Pathfinding complete (no graph data).\n")
            return results

        try:
            # Dijkstra
            dijkstra_paths = run_dijkstra(session, source, target)
            for p in dijkstra_paths:
                prob = compute_path_probability(session, p["nodes"])
                p["probability"] = prob
            results["dijkstra"] = dijkstra_paths

            if dijkstra_paths:
                print("\n  Dijkstra shortest path:")
                for p in dijkstra_paths:
                    print(_fmt_path(p, p["probability"]))
            else:
                print("  No Dijkstra path found.")

            # Yen k-shortest
            yen_paths = run_yen(session, source, target)
            for p in yen_paths:
                prob = compute_path_probability(session, p["nodes"])
                p["probability"] = prob
            results["yen"] = yen_paths

            print(f"\n  Yen k-shortest paths ({len(yen_paths)} found):")
            for p in yen_paths[:5]:
                print(f"    #{p['index']} {_fmt_path(p, p['probability'])}")
            if len(yen_paths) > 5:
                print(f"    ... and {len(yen_paths) - 5} more")

        finally:
            drop_graph(session)

    print("Pathfinding complete.\n")
    return results


if __name__ == "__main__":
    drv = GraphDatabase.driver(config.NEO4J_URI, auth=(config.NEO4J_USER, config.NEO4J_PASSWORD))
    try:
        run_pathfinding(drv, config.DEFAULT_SOURCE, config.DEFAULT_TARGET)
    finally:
        drv.close()
