# ThreatWeave: Topology aware CVE patching prioritization

A proof-of-concept for graph-based cybersecurity risk assessment, grounded in
the **BRIDG-ICS** framework (Nandiya et al., 2025), the **Neo4j "Graphs for
Cybersecurity"** whitepaper.

This is done as a part of course project for CSCE 704: CyberSecurity Risk by
Ramneek Kaur, Saksham Mehta and Wahib Kapdi.

## What it does

1. Models network infrastructure as an attack graph in Neo4j -- supports two
   data modes:
   - **Purdue ICS** (12 assets across DMZ/IT/OT zones, 8 CVEs)
   - **BloodHound AD** (~910 assets from a fictitious Active Directory with
     300 computers, 300 users, 308 groups, 18 CVEs, ~4000 attack edges)
2. Ingests live **EPSS** exploitation probabilities and **CVSS** severity scores
   from the FIRST and NVD APIs
3. Computes four BRIDG-ICS risk metrics on every communication edge:
   `controlStrength`, `pExploit`, `attackCost`, `riskWeight`
4. Runs **Dijkstra** and **Yen k-shortest** pathfinding to simulate attacker
   traversal with multi-hop attack probability
5. Performs **PageRank**, **betweenness centrality**, and **Louvain community
   detection** for structural risk analysis
6. Evaluates a heuristic baseline (CVSS-only weights) against the empirical
   BRIDG-ICS model across three metrics: **Blast Radius Reduction**, **Path
   Priority Delta**, and **Predictive Accuracy** (Hit Rate@K, MRR)

## Prerequisites

- **Docker** and **Docker Compose**
- **Python 3.10+**

## Quick Start

```bash
# 1. Start Neo4j with the GDS plugin
docker compose up -d

# 2. Wait ~30s for Neo4j to initialize, then install Python dependencies
pip install -r requirements.txt

# 3a. Run the full pipeline with Purdue ICS topology (12 nodes)
python main.py --seed --with-controls --evaluate

# 3b. Or run at BloodHound AD scale (~910 nodes, ~4000 edges)
python main.py --bloodhound --with-controls --evaluate

# 4. Subsequent runs (data already loaded)
python main.py --skip-ingest --with-controls --evaluate

# 5. Specify custom source/target for pathfinding
python main.py --skip-ingest --with-controls --evaluate \
  --source "PiedadFlatley255@TestCompany.Local" \
  --target "DOMAIN ADMINS@TestCompany.Local"
```

## CLI Options

| Flag              | Description                                                     |
|-------------------|-----------------------------------------------------------------|
| `--seed`          | Load Purdue ICS schema and seed data (mutually exclusive with `--bloodhound`) |
| `--bloodhound`    | Load BloodHound AD dataset at scale (mutually exclusive with `--seed`) |
| `--with-controls` | Create controlled edges with improved security factors           |
| `--evaluate`      | Run heuristic vs. empirical evaluation (3 metrics)               |
| `--skip-ingest`   | Skip EPSS/CVSS API calls (use previously fetched data)           |
| `--source NAME`   | Source asset for pathfinding (auto-set per data mode)             |
| `--target NAME`   | Target asset for pathfinding (auto-set per data mode)             |

## Project Structure

```
docker-compose.yml      Neo4j 5 + GDS plugin
config.py               Connection settings, API keys, control-factor defaults
cypher/
  schema.cypher         Constraints and indexes (Purdue + BloodHound labels)
  seed_data.cypher      ICS-inspired sample topology + CVE mappings
load_bloodhound.py      BloodHound AD loader: JSON parsing, Asset overlay, CVE pools
data_dumps/             BloodHound dump and cached JSON data
ingest.py               Fetch EPSS (FIRST API) + CVSS (NVD API 2.0)
risk_model.py           BRIDG-ICS Eqs 3-8: controlStrength -> riskWeight -> exposure
pathfinding.py          GDS Dijkstra + Yen k-shortest paths + attack probability
analytics.py            PageRank, betweenness centrality, Louvain communities
evaluate.py             Heuristic vs. empirical model evaluation
main.py                 CLI orchestrator
```

## BloodHound Data Mode

When `--bloodhound` is passed, the pipeline loads a fictitious Active Directory
environment (from the [neo4j-graph-examples/cybersecurity](https://github.com/neo4j-graph-examples/cybersecurity) repo) and applies a
BRIDG-ICS overlay:

- **Node labels**: Computer, User, Group, Domain all receive the `:Asset` label
  with `criticality_score` (1-10), `zone` (DMZ/IT/OT_L1-L3), and `type`
- **CVE assignment**: 18 real CVEs mapped by AD relationship type (ADMIN_TO,
  CAN_RDP, HAS_SESSION, etc.) and by OS version (Windows 7 -> BlueKeep, etc.)
- **Attack edges**: `COMMUNICATES_WITH` edges derived from AD attack
  relationships (ADMIN_TO, CAN_RDP, HAS_SESSION, EXECUTE_DCOM, GENERIC_ALL,
  GENERIC_WRITE, WRITE_OWNER, MEMBER_OF), each with BRIDG-ICS control factors
- **Default pathfinding**: `PiedadFlatley255@TestCompany.Local` ->
  `DOMAIN ADMINS@TestCompany.Local`

## Risk Model (BRIDG-ICS Equations)

| Equation | Formula | Purpose |
|----------|---------|---------|
| Eq. 3 | `controlStrength = a * c * e * h` | Defensive strength of a link |
| Eq. 4 | `pExploit = EPSS * (1 - controlStrength)` | Exploitation probability |
| Eq. 5 | `attackCost = Base + fAC + fAV + EPSS` | Adversarial effort required |
| Eq. 6 | `riskWeight = pExploit * criticality / 10` | Residual edge risk |
| Eq. 7 | `p(P) = Product(pExploit(vi, vi+1))` | Multi-hop attack probability |
| Eq. 8 | `Exposure(v) = Sum(riskWeight(u,v))` | Node-level exploitation pressure |

## Evaluation Metrics

The evaluation compares two models using the same graph topology but different
edge weights:

- **Heuristic Baseline**: edge weight = `max(cvss_base_score) / 10` on target
- **Empirical Enriched**: edge weight = `riskWeight` from BRIDG-ICS (Eq. 6)

| # | Metric | What it measures |
|---|--------|------------------|
| 1 | Blast Radius Reduction | BFS-reachable assets before/after patching top-N by CVSS vs. exposure |
| 2 | Path Priority Delta | Dijkstra shortest path divergence: which CVEs each model routes through |
| 3 | Predictive Accuracy | Hit Rate@K and MRR against EPSS-weighted stochastic ground truth |

## Configuration

Set environment variables to override defaults in `config.py`:

```bash
export NEO4J_URI=bolt://localhost:7687
export NEO4J_USER=neo4j
export NEO4J_PASSWORD=graphcyber
export NVD_API_KEY=your-key-here    # optional, increases NVD rate limit
```

## References

- Nandiya, P. et al. "BRIDG-ICS: AI-Grounded Knowledge Graphs for Intelligent
  Threat Analytics in Industry 5.0 Cyber-Physical Systems." arXiv:2512.12112, 2025.
- Voutila, D. et al. "Graphs for Cybersecurity." Neo4j Whitepaper, 2022.
- Kaur, R., Mehta, S., Kapdi, W. S. & Kumar, S. "Graph-Based Attack Simulation
  & Blast Radius Analysis." 2025.
- neo4j-graph-examples/cybersecurity. BloodHound Active Directory dataset.
  https://github.com/neo4j-graph-examples/cybersecurity
