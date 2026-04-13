# GraphCyberAnalytics POC

A proof-of-concept for graph-based cybersecurity risk assessment in ICS/IT-OT
environments, grounded in the **BRIDG-ICS** framework (Nandiya et al., 2025) and
the **Neo4j "Graphs for Cybersecurity"** whitepaper.

## What it does

1. Models a Purdue-like ICS network (12 assets across DMZ/IT/OT zones) in Neo4j
2. Ingests live **EPSS** exploitation probabilities and **CVSS** severity scores
3. Computes four BRIDG-ICS risk metrics on every communication edge:
   `controlStrength`, `pExploit`, `attackCost`, `riskWeight`
4. Runs **Dijkstra** and **Yen k-shortest** pathfinding to simulate attacker
   traversal with multi-hop attack probability
5. Performs **PageRank**, **betweenness centrality**, and **Louvain community
   detection** for structural risk analysis
6. Evaluates graph-based vs. three traditional approaches (CVSS-only,
   CVSS×EPSS, risk matrix) across six quantitative metrics

## Prerequisites

- **Docker** and **Docker Compose**
- **Python 3.10+**

## Quick Start

```bash
# 1. Start Neo4j with the GDS plugin
docker compose up -d

# 2. Wait ~30s for Neo4j to initialize, then install Python dependencies
pip install -r requirements.txt

# 3. Run the full pipeline (first run — seeds the database)
python main.py --seed --with-controls --evaluate

# 4. Subsequent runs (data already seeded)
python main.py --with-controls --evaluate

# 5. Skip API calls if you already have cached EPSS/CVSS data
python main.py --skip-ingest --with-controls --evaluate
```

## CLI Options

| Flag              | Description                                           |
|-------------------|-------------------------------------------------------|
| `--seed`          | Load schema constraints and seed data (first run)     |
| `--with-controls` | Create controlled edges with improved security factors|
| `--evaluate`      | Run graph-vs-traditional comparison (6 metrics)       |
| `--skip-ingest`   | Skip EPSS/CVSS API calls (use previously fetched data)|
| `--source NAME`   | Source asset for pathfinding (default: `MQTT_Broker`)  |
| `--target NAME`   | Target asset for pathfinding (default: `Safety_PLC`)   |

## Project Structure

```
docker-compose.yml      Neo4j 5 + GDS plugin
config.py               Connection settings, API keys, control-factor defaults
cypher/
  schema.cypher         Constraints and indexes
  seed_data.cypher      ICS-inspired sample topology + CVE mappings
ingest.py               Fetch EPSS (FIRST API) + CVSS (NVD API 2.0)
risk_model.py           BRIDG-ICS Eqs 3-8: controlStrength → riskWeight → exposure
pathfinding.py          GDS Dijkstra + Yen k-shortest paths + attack probability
analytics.py            PageRank, betweenness centrality, Louvain communities
evaluate.py             Graph-based vs. traditional baseline comparison
main.py                 CLI orchestrator
```

## Risk Model (BRIDG-ICS Equations)

| Equation | Formula | Purpose |
|----------|---------|---------|
| Eq. 3 | `controlStrength = a × c × e × h` | Defensive strength of a link |
| Eq. 4 | `pExploit = EPSS × (1 − controlStrength)` | Exploitation probability |
| Eq. 5 | `attackCost = Base + fAC + fAV + EPSS` | Adversarial effort required |
| Eq. 6 | `riskWeight = pExploit × criticality / 10` | Residual edge risk |
| Eq. 7 | `p(P) = Π pExploit(vi, vi+1)` | Multi-hop attack probability |
| Eq. 8 | `Exposure(v) = Σ riskWeight(u,v)` | Node-level exploitation pressure |

## Evaluation Metrics

| # | Metric | Traditional | Graph-Based |
|---|--------|-------------|-------------|
| 1 | Priority Ranking Agreement | Spearman ρ vs. graph ranking | Reference |
| 2 | Hidden Path Discovery | 0 (no topology) | Count from Yen k=20 |
| 3 | Reachability Blind Spots | Assets misranked | 0 by definition |
| 4 | Control Impact Visibility | Binary only | % risk reduction |
| 5 | Cascade Risk Detection | Not possible | Centrality + communities |
| 6 | Prioritization Precision | Residual after top-N fix | Lowest residual |

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
