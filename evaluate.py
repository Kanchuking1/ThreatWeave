"""
Evaluation: Heuristic (CVSS-only) baseline vs. Empirical (BRIDG-ICS) model.

Metrics (aligned with Kaur, Mehta, Kapdi, Kumar):
  1. Blast Radius Reduction
  2. Path Priority Delta
  3. Predictive Accuracy (Hit Rate@K, MRR)
"""

import heapq
import random
from collections import Counter

from neo4j import GraphDatabase

import config

# ── Data extraction ──────────────────────────────────────────

_QUERY_ASSETS = """
MATCH (a:Asset)
OPTIONAL MATCH (a)-[:HAS_VULNERABILITY]->(v:Vulnerability)
WITH a,
     collect({cvss: v.cvss_base_score, epss: v.epss_score, cve: v.cve_id}) AS vulns
RETURN a.name AS name,
       a.zone AS zone,
       a.criticality_score AS criticality,
       COALESCE(a.exposure, 0.0) AS exposure,
       vulns
ORDER BY a.name
"""

_QUERY_EDGES = """
MATCH (a:Asset)-[c:COMMUNICATES_WITH]->(b:Asset)
WHERE c.riskWeight IS NOT NULL
RETURN a.name AS src, b.name AS tgt,
       c.riskWeight AS rw, c.pExploit AS pe,
       c.attackCost AS ac
"""

_QUERY_TARGET_VULNS = """
MATCH (a:Asset)-[c:COMMUNICATES_WITH]->(b:Asset)
WHERE c.riskWeight IS NOT NULL
OPTIONAL MATCH (b)-[:HAS_VULNERABILITY]->(v:Vulnerability)
RETURN a.name AS src, b.name AS tgt,
       collect({cve: v.cve_id, cvss: v.cvss_base_score, epss: v.epss_score}) AS target_vulns
"""


def _fetch_assets(session) -> list[dict]:
    records = session.run(_QUERY_ASSETS)
    assets = []
    for r in records:
        vulns = r["vulns"]
        cvss_scores = [v["cvss"] for v in vulns if v and v.get("cvss") is not None]
        epss_scores = [v["epss"] for v in vulns if v and v.get("epss") is not None]
        assets.append({
            "name": r["name"],
            "zone": r["zone"],
            "criticality": r["criticality"],
            "exposure": r["exposure"],
            "max_cvss": max(cvss_scores) if cvss_scores else 0.0,
            "max_epss": max(epss_scores) if epss_scores else 0.0,
            "vulns": [v for v in vulns if v and v.get("cvss") is not None],
        })
    return assets


def _fetch_edges(session) -> list[dict]:
    records = session.run(_QUERY_EDGES)
    return [
        {"src": r["src"], "tgt": r["tgt"], "rw": r["rw"],
         "pe": r["pe"], "ac": r["ac"]}
        for r in records
    ]


def _fetch_target_vulns(session) -> dict[tuple[str, str], list[dict]]:
    """Map (src, tgt) -> list of vuln dicts on the target node."""
    records = session.run(_QUERY_TARGET_VULNS)
    mapping: dict[tuple[str, str], list[dict]] = {}
    for r in records:
        vulns = [v for v in r["target_vulns"] if v and v.get("cve") is not None]
        mapping[(r["src"], r["tgt"])] = vulns
    return mapping


# ── Graph helpers ────────────────────────────────────────────

def _build_adj(edges: list[dict], weight_key: str) -> dict[str, list[tuple[str, float]]]:
    """Build adjacency list: node -> [(neighbor, weight), ...]."""
    adj: dict[str, list[tuple[str, float]]] = {}
    for e in edges:
        w = e.get(weight_key)
        if w is None or w <= 0:
            w = 0.001
        adj.setdefault(e["src"], []).append((e["tgt"], w))
    return adj


def _bfs_reachable(adj: dict[str, list[tuple[str, float]]], source: str,
                   max_hops: int | None = None,
                   excluded: set[str] | None = None) -> set[str]:
    """BFS from source, optionally limited to max_hops, skipping excluded nodes."""
    if excluded is None:
        excluded = set()
    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(source, 0)]
    while queue:
        node, depth = queue.pop(0)
        if node in visited or node in excluded:
            continue
        visited.add(node)
        if max_hops is not None and depth >= max_hops:
            continue
        for nb, _ in adj.get(node, []):
            if nb not in visited and nb not in excluded:
                queue.append((nb, depth + 1))
    return visited


def _dijkstra(adj: dict[str, list[tuple[str, float]]],
              source: str, target: str) -> tuple[list[str], float]:
    """Return (path_nodes, total_cost) or ([], inf) if unreachable."""
    dist: dict[str, float] = {source: 0.0}
    prev: dict[str, str | None] = {source: None}
    heap = [(0.0, source)]

    while heap:
        d, u = heapq.heappop(heap)
        if u == target:
            break
        if d > dist.get(u, float("inf")):
            continue
        for v, w in adj.get(u, []):
            nd = d + w
            if nd < dist.get(v, float("inf")):
                dist[v] = nd
                prev[v] = u
                heapq.heappush(heap, (nd, v))

    if target not in dist:
        return [], float("inf")

    path = []
    cur: str | None = target
    while cur is not None:
        path.append(cur)
        cur = prev.get(cur)
    path.reverse()
    return path, dist[target]


def _yen_k_shortest(adj: dict[str, list[tuple[str, float]]],
                    source: str, target: str, k: int) -> list[tuple[list[str], float]]:
    """Yen's k-shortest loopless paths (Python-side, for both weight models)."""
    best_path, best_cost = _dijkstra(adj, source, target)
    if not best_path:
        return []

    A: list[tuple[list[str], float]] = [(best_path, best_cost)]
    B: list[tuple[float, list[str]]] = []

    for i in range(1, k):
        if i - 1 >= len(A):
            break
        prev_path = A[i - 1][0]

        for j in range(len(prev_path) - 1):
            spur_node = prev_path[j]
            root_path = prev_path[: j + 1]

            removed_edges: set[tuple[str, str]] = set()
            for path_a, _ in A:
                if path_a[: j + 1] == root_path and j + 1 < len(path_a):
                    removed_edges.add((path_a[j], path_a[j + 1]))

            excluded_nodes = set(root_path[:-1])

            filtered_adj: dict[str, list[tuple[str, float]]] = {}
            for node, neighbors in adj.items():
                if node in excluded_nodes:
                    continue
                filtered_adj[node] = [
                    (nb, w) for nb, w in neighbors
                    if nb not in excluded_nodes and (node, nb) not in removed_edges
                ]

            spur_path, spur_cost = _dijkstra(filtered_adj, spur_node, target)
            if spur_path:
                total_path = root_path[:-1] + spur_path
                root_cost = 0.0
                for idx in range(len(root_path) - 1):
                    for nb, w in adj.get(root_path[idx], []):
                        if nb == root_path[idx + 1]:
                            root_cost += w
                            break
                total_cost = root_cost + spur_cost
                candidate = (total_cost, total_path)
                if total_path not in [b[1] for b in B] and total_path not in [a[0] for a in A]:
                    heapq.heappush(B, candidate)

        if not B:
            break
        cost, path = heapq.heappop(B)
        A.append((path, cost))

    return A


# ── Metric 1: Blast Radius Reduction ────────────────────────

def _evaluate_blast_radius(assets: list[dict], edges: list[dict],
                           source: str, max_hops: int = 6, n_remediate: int = 3) -> dict:
    adj = _build_adj(edges, "rw")

    baseline_reachable = _bfs_reachable(adj, source, max_hops=max_hops)
    baseline_count = len(baseline_reachable)
    baseline_exposure = sum(a["exposure"] for a in assets)

    rank_heuristic = sorted(assets, key=lambda a: a["max_cvss"], reverse=True)
    heuristic_patch = {a["name"] for a in rank_heuristic[:n_remediate]}
    heur_reachable = _bfs_reachable(adj, source, max_hops=max_hops, excluded=heuristic_patch)
    heur_count = len(heur_reachable)
    heur_exposure = sum(
        a["exposure"] for a in assets if a["name"] not in heuristic_patch
    )

    rank_empirical = sorted(assets, key=lambda a: a["exposure"], reverse=True)
    empirical_patch = {a["name"] for a in rank_empirical[:n_remediate]}
    emp_reachable = _bfs_reachable(adj, source, max_hops=max_hops, excluded=empirical_patch)
    emp_count = len(emp_reachable)
    emp_exposure = sum(
        a["exposure"] for a in assets if a["name"] not in empirical_patch
    )

    heur_br_reduction = (
        (baseline_count - heur_count) / baseline_count * 100
        if baseline_count > 0 else 0.0
    )
    emp_br_reduction = (
        (baseline_count - emp_count) / baseline_count * 100
        if baseline_count > 0 else 0.0
    )
    heur_exp_reduction = (
        (baseline_exposure - heur_exposure) / baseline_exposure * 100
        if baseline_exposure > 0 else 0.0
    )
    emp_exp_reduction = (
        (baseline_exposure - emp_exposure) / baseline_exposure * 100
        if baseline_exposure > 0 else 0.0
    )

    print(f"\n{'─' * 72}")
    print("  METRIC 1: Blast Radius Reduction")
    print(f"{'─' * 72}")
    print(f"  Entry point: {source}  |  Max hops: {max_hops}  |  Remediate top-{n_remediate}")
    print(f"\n  {'Model':<22s} {'Patched Assets':<30s} {'Reachable':>10s} {'BR Reduction':>14s}")
    print(f"  {'-' * 76}")
    print(f"  {'Baseline (none)':<22s} {'—':<30s} {baseline_count:>10d} {'—':>14s}")
    print(f"  {'Heuristic (CVSS)':<22s} {str(sorted(heuristic_patch)):<30s} {heur_count:>10d} {heur_br_reduction:>13.1f}%")
    print(f"  {'Empirical (BRIDG-ICS)':<22s} {str(sorted(empirical_patch)):<30s} {emp_count:>10d} {emp_br_reduction:>13.1f}%")
    print(f"\n  Critical Node Exposure:")
    print(f"    Baseline total:          {baseline_exposure:.4f}")
    print(f"    After heuristic patch:   {heur_exposure:.4f}  ({heur_exp_reduction:.1f}% reduction)")
    print(f"    After empirical patch:   {emp_exposure:.4f}  ({emp_exp_reduction:.1f}% reduction)")

    return {
        "baseline_reachable": baseline_count,
        "heuristic": {"reachable": heur_count, "br_reduction_pct": heur_br_reduction,
                      "exposure_reduction_pct": heur_exp_reduction, "patched": sorted(heuristic_patch)},
        "empirical": {"reachable": emp_count, "br_reduction_pct": emp_br_reduction,
                      "exposure_reduction_pct": emp_exp_reduction, "patched": sorted(empirical_patch)},
    }


# ── Metric 2: Path Priority Delta ───────────────────────────

def _compute_heuristic_weights(edges: list[dict], assets: list[dict]) -> list[dict]:
    """Add heuristic_weight to each edge: max CVSS on the target / 10."""
    asset_cvss = {a["name"]: a["max_cvss"] for a in assets}
    enriched = []
    for e in edges:
        hw = asset_cvss.get(e["tgt"], 0.0) / 10.0
        if hw <= 0:
            hw = 0.001
        enriched.append({**e, "hw": hw})
    return enriched


def _evaluate_path_priority_delta(
    edges: list[dict], assets: list[dict],
    target_vulns: dict[tuple[str, str], list[dict]],
    source: str, target: str,
) -> dict:
    enriched_edges = _compute_heuristic_weights(edges, assets)

    adj_heuristic = _build_adj(enriched_edges, "hw")
    adj_empirical = _build_adj(enriched_edges, "rw")

    heur_path, heur_cost = _dijkstra(adj_heuristic, source, target)
    emp_path, emp_cost = _dijkstra(adj_empirical, source, target)

    print(f"\n{'─' * 72}")
    print("  METRIC 2: Path Priority Delta")
    print(f"{'─' * 72}")
    print(f"  Source: {source}  ->  Target: {target}")

    print(f"\n  Heuristic path (CVSS-only weights):  cost={heur_cost:.4f}")
    print(f"    {' -> '.join(heur_path) if heur_path else 'No path found'}")
    print(f"\n  Empirical path (BRIDG-ICS weights):  cost={emp_cost:.4f}")
    print(f"    {' -> '.join(emp_path) if emp_path else 'No path found'}")

    divergences = []
    if heur_path and emp_path:
        heur_edge_set = set(zip(heur_path[:-1], heur_path[1:]))
        emp_edge_set = set(zip(emp_path[:-1], emp_path[1:]))

        heur_only = heur_edge_set - emp_edge_set
        emp_only = emp_edge_set - heur_edge_set

        all_divergent_edges = heur_only | emp_only

        if all_divergent_edges:
            print(f"\n  Divergence Analysis ({len(all_divergent_edges)} differing edges):")
            print(f"  {'-' * 68}")

        for edge in sorted(all_divergent_edges):
            vulns = target_vulns.get(edge, [])
            if not vulns:
                continue

            valid_vulns = [v for v in vulns if v.get("cvss") is not None]
            if not valid_vulns:
                continue

            highest_cvss = max(valid_vulns, key=lambda v: v.get("cvss", 0))
            vulns_with_epss = [v for v in valid_vulns if v.get("epss") is not None]
            highest_epss = max(vulns_with_epss, key=lambda v: v.get("epss", 0)) if vulns_with_epss else None

            in_heur = "HEURISTIC" if edge in heur_only else "both"
            in_emp = "EMPIRICAL" if edge in emp_only else "both"
            model_label = in_heur if edge in heur_only else in_emp

            cvss_str = f"{highest_cvss['cve']} (CVSS {highest_cvss['cvss']:.1f})"
            epss_str = ""
            if highest_epss and highest_epss["cve"] != highest_cvss["cve"]:
                epss_str = f" vs EPSS-leader {highest_epss['cve']} (CVSS {highest_epss.get('cvss', 0):.1f}, EPSS {highest_epss['epss']:.4f})"

            divergences.append({
                "edge": edge,
                "model": model_label,
                "highest_cvss_cve": highest_cvss,
                "highest_epss_cve": highest_epss,
            })
            print(f"    {edge[0]} -> {edge[1]}  [{model_label}]")
            print(f"      Highest-CVSS: {cvss_str}{epss_str}")

        if heur_path != emp_path and not all_divergent_edges:
            print("\n  Paths differ in traversal order but use the same edges.")

    if heur_path == emp_path:
        print("\n  Both models produce the same path (no divergence at this topology scale).")

    return {
        "heuristic_path": heur_path, "heuristic_cost": heur_cost,
        "empirical_path": emp_path, "empirical_cost": emp_cost,
        "divergences": divergences,
    }


# ── Metric 3: Predictive Accuracy (Hit Rate@K, MRR) ─────────

def _simulate_ground_truth(adj_pe: dict[str, list[tuple[str, float]]],
                           source: str, target: str,
                           n_simulations: int = 500,
                           max_steps: int = 15) -> tuple[list[str], int]:
    """EPSS-weighted stochastic walk to generate a ground-truth attack path.

    Returns (most_frequent_path, frequency).
    """
    path_counts: Counter[tuple[str, ...]] = Counter()

    for _ in range(n_simulations):
        path = [source]
        visited = {source}
        current = source
        for _ in range(max_steps):
            if current == target:
                break
            neighbors = adj_pe.get(current, [])
            reachable = [(nb, w) for nb, w in neighbors if nb not in visited]
            if not reachable:
                break

            weights = [max(w, 1e-9) for _, w in reachable]
            total = sum(weights)
            probs = [w / total for w in weights]

            r = random.random()
            cumulative = 0.0
            chosen = reachable[0][0]
            for (nb, _), p in zip(reachable, probs):
                cumulative += p
                if r <= cumulative:
                    chosen = nb
                    break

            path.append(chosen)
            visited.add(chosen)
            current = chosen

        if path[-1] == target:
            path_counts[tuple(path)] += 1

    if not path_counts:
        return [], 0

    most_common_path, freq = path_counts.most_common(1)[0]
    return list(most_common_path), freq


def _path_matches(predicted: list[str], ground_truth: list[str]) -> bool:
    """Check if two paths visit the same nodes in the same order."""
    return predicted == ground_truth


def _evaluate_predictive_accuracy(
    edges: list[dict], assets: list[dict],
    source: str, target: str, k_max: int = 20,
) -> dict:
    adj_pe: dict[str, list[tuple[str, float]]] = {}
    for e in edges:
        pe = e.get("pe")
        if pe is None or pe <= 0:
            pe = 1e-6
        adj_pe.setdefault(e["src"], []).append((e["tgt"], pe))

    random.seed(42)
    gt_path, gt_freq = _simulate_ground_truth(adj_pe, source, target)

    enriched = _compute_heuristic_weights(edges, assets)
    adj_heur = _build_adj(enriched, "hw")
    adj_emp = _build_adj(enriched, "rw")

    heur_paths = _yen_k_shortest(adj_heur, source, target, k_max)
    emp_paths = _yen_k_shortest(adj_emp, source, target, k_max)

    k_values = [1, 3, 5, 10, 20]

    def _hit_rate(predicted_paths: list[tuple[list[str], float]], gt: list[str], k: int) -> int:
        for path, _ in predicted_paths[:k]:
            if _path_matches(path, gt):
                return 1
        return 0

    def _mrr(predicted_paths: list[tuple[list[str], float]], gt: list[str], k: int) -> float:
        for rank, (path, _) in enumerate(predicted_paths[:k], start=1):
            if _path_matches(path, gt):
                return 1.0 / rank
        return 0.0

    print(f"\n{'─' * 72}")
    print("  METRIC 3: Predictive Accuracy (Hit Rate@K, MRR)")
    print(f"{'─' * 72}")
    print(f"  Ground truth: EPSS-weighted stochastic simulation (500 walks, seed=42)")
    if gt_path:
        print(f"  Most frequent path: {' -> '.join(gt_path)}")
        print(f"  Frequency: {gt_freq}/500 simulations")
    else:
        print(f"  No ground-truth path reached {target} from {source}")

    print(f"\n  Heuristic model produced {len(heur_paths)} candidate paths")
    print(f"  Empirical model produced {len(emp_paths)} candidate paths")

    if gt_path:
        print(f"\n  {'K':>4s}   {'Heuristic Hit':>15s}   {'Empirical Hit':>15s}   {'Heuristic MRR':>15s}   {'Empirical MRR':>15s}")
        print(f"  {'-' * 70}")
        results_table = []
        for k in k_values:
            hh = _hit_rate(heur_paths, gt_path, k)
            eh = _hit_rate(emp_paths, gt_path, k)
            hm = _mrr(heur_paths, gt_path, k)
            em = _mrr(emp_paths, gt_path, k)
            results_table.append({"k": k, "heur_hit": hh, "emp_hit": eh, "heur_mrr": hm, "emp_mrr": em})
            print(f"  {k:>4d}   {hh:>15d}   {eh:>15d}   {hm:>15.4f}   {em:>15.4f}")

        overall_heur_mrr = _mrr(heur_paths, gt_path, k_max)
        overall_emp_mrr = _mrr(emp_paths, gt_path, k_max)
        print(f"\n  Overall MRR (K={k_max}):  Heuristic={overall_heur_mrr:.4f}  Empirical={overall_emp_mrr:.4f}")
    else:
        results_table = []
        overall_heur_mrr = 0.0
        overall_emp_mrr = 0.0
        print("  (Skipping Hit Rate / MRR — no ground-truth path found)")

    return {
        "ground_truth_path": gt_path,
        "ground_truth_freq": gt_freq,
        "heuristic_paths_count": len(heur_paths),
        "empirical_paths_count": len(emp_paths),
        "hit_rate_mrr_table": results_table,
        "overall_heur_mrr": overall_heur_mrr,
        "overall_emp_mrr": overall_emp_mrr,
    }


# ── Main evaluation logic ────────────────────────────────────

def run_evaluation(driver, source: str = config.DEFAULT_SOURCE,
                   target: str = config.DEFAULT_TARGET):
    """Run all three evaluation metrics and print comparison report."""
    print("=" * 72)
    print("  EVALUATION: Heuristic Baseline vs. Empirical Model")
    print("=" * 72)

    with driver.session() as session:
        assets = _fetch_assets(session)
        edges = _fetch_edges(session)
        target_vulns = _fetch_target_vulns(session)

    if not assets:
        print("  No asset data found. Run the pipeline first.")
        return {}

    if not edges:
        print("  No edge data found. Run the risk model first.")
        return {}

    # Metric 1
    blast = _evaluate_blast_radius(assets, edges, source)

    # Metric 2
    delta = _evaluate_path_priority_delta(edges, assets, target_vulns, source, target)

    # Metric 3
    accuracy = _evaluate_predictive_accuracy(edges, assets, source, target)

    # Summary
    print(f"\n{'=' * 72}")
    print("  SUMMARY")
    print(f"{'=' * 72}")

    emp_br = blast["empirical"]["br_reduction_pct"]
    heur_br = blast["heuristic"]["br_reduction_pct"]
    emp_exp = blast["empirical"]["exposure_reduction_pct"]
    print(f"  Blast Radius: Empirical remediation reduces reachable assets by {emp_br:.1f}%")
    print(f"                vs. {heur_br:.1f}% for heuristic (CVSS-only) remediation")
    print(f"                Empirical cuts critical node exposure by {emp_exp:.1f}%")

    if delta["heuristic_path"] != delta["empirical_path"]:
        print(f"  Path Delta:   Models produce different attack paths ({len(delta['divergences'])} edge divergences)")
    else:
        print(f"  Path Delta:   Both models converge on the same path at this scale")

    if accuracy["ground_truth_path"]:
        print(f"  Prediction:   Empirical MRR={accuracy['overall_emp_mrr']:.4f}  "
              f"Heuristic MRR={accuracy['overall_heur_mrr']:.4f}")
    else:
        print(f"  Prediction:   No ground-truth path could be simulated")

    print(f"{'=' * 72}\n")

    return {"blast_radius": blast, "path_delta": delta, "predictive_accuracy": accuracy}


if __name__ == "__main__":
    drv = GraphDatabase.driver(config.NEO4J_URI, auth=(config.NEO4J_USER, config.NEO4J_PASSWORD))
    try:
        run_evaluation(drv)
    finally:
        drv.close()
