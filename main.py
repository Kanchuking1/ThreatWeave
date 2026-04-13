"""
GraphCyberAnalytics POC — main orchestrator.

Usage:
    python main.py --seed                         # First run: load schema + seed data
    python main.py --seed --with-controls         # Full pipeline with controlled edges
    python main.py --evaluate                     # Run evaluation only (data must exist)
    python main.py --source MQTT_Broker --target Actuator_Valve
"""

import argparse
import pathlib
import sys

from neo4j import GraphDatabase

import config
from ingest import run_ingestion
from risk_model import run_risk_model
from pathfinding import run_pathfinding
from analytics import run_analytics
from evaluate import run_evaluation


CYPHER_DIR = pathlib.Path(__file__).parent / "cypher"


def _verify_connection(driver):
    """Check Neo4j connectivity and GDS availability."""
    with driver.session() as session:
        result = session.run("RETURN 1 AS ok")
        assert result.single()["ok"] == 1
        print("[OK] Neo4j connection verified")

        gds_result = session.run("RETURN gds.version() AS version")
        version = gds_result.single()["version"]
        print(f"[OK] GDS library v{version} available\n")


def _run_cypher_file(driver, filepath: pathlib.Path):
    """Execute a .cypher file statement by statement.

    Files with semicolons are split into individual statements.
    Files without semicolons are executed as a single statement.
    Cypher-style // comments are left in — Neo4j handles them natively.
    """
    text = filepath.read_text(encoding="utf-8")
    if ";" in text:
        statements = [s.strip() for s in text.split(";") if s.strip()]
    else:
        statements = [text.strip()] if text.strip() else []
    with driver.session() as session:
        for stmt in statements:
            session.run(stmt).consume()
    print(f"  Executed {filepath.name} ({len(statements)} statements)")


def _seed_database(driver):
    """Run schema + seed data cypher files."""
    print("Seeding database ...")
    _run_cypher_file(driver, CYPHER_DIR / "schema.cypher")
    _run_cypher_file(driver, CYPHER_DIR / "seed_data.cypher")
    print("Seeding complete.\n")


def main():
    parser = argparse.ArgumentParser(description="GraphCyberAnalytics POC")
    parser.add_argument("--seed", action="store_true", help="Load schema and seed data (first run)")
    parser.add_argument("--with-controls", action="store_true", help="Create CONTROLLED_COMMUNICATES_WITH edges")
    parser.add_argument("--source", default=config.DEFAULT_SOURCE, help="Source asset for pathfinding")
    parser.add_argument("--target", default=config.DEFAULT_TARGET, help="Target asset for pathfinding")
    parser.add_argument("--evaluate", action="store_true", help="Run graph-vs-traditional evaluation")
    parser.add_argument("--skip-ingest", action="store_true", help="Skip API calls (use cached data)")
    args = parser.parse_args()

    driver = GraphDatabase.driver(
        config.NEO4J_URI, auth=(config.NEO4J_USER, config.NEO4J_PASSWORD)
    )

    try:
        # Step 0: verify
        _verify_connection(driver)

        # Step 1: seed
        if args.seed:
            _seed_database(driver)

        # Step 2: ingest
        if not args.skip_ingest:
            run_ingestion(driver)

        # Step 3: risk model
        run_risk_model(driver, with_controls=args.with_controls)

        # Step 4: pathfinding
        pf_results = run_pathfinding(driver, args.source, args.target)

        # Step 5: analytics
        analytics_results = run_analytics(driver)

        # Step 6: evaluation
        if args.evaluate:
            eval_results = run_evaluation(driver, args.source, args.target)

        print("=" * 60)
        print("  Pipeline complete.")
        print("=" * 60)

    except Exception as exc:
        print(f"\n[ERROR] {exc}", file=sys.stderr)
        raise
    finally:
        driver.close()


if __name__ == "__main__":
    main()
