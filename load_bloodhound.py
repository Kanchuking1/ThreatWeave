"""
BloodHound AD dataset loader.

Downloads the neo4j-graph-examples/cybersecurity JSON, loads all nodes and
relationships into Neo4j, then adds a BRIDG-ICS overlay:
  - :Asset label on Computer and User nodes
  - Vulnerability nodes from a curated CVE pool
  - COMMUNICATES_WITH edges derived from AD attack relationships
"""

import json
import pathlib
import random

import requests
from neo4j import GraphDatabase

import config

# ── CVE pools per AD relationship type ───────────────────────

ATTACK_REL_CVES: dict[str, list[str]] = {
    "ADMIN_TO": [
        "CVE-2021-34527",   # PrintNightmare
        "CVE-2020-1472",    # Zerologon
        "CVE-2021-36934",   # HiveNightmare
        "CVE-2021-1675",    # Print Spooler RCE
    ],
    "CAN_RDP": [
        "CVE-2019-0708",    # BlueKeep
        "CVE-2019-1182",    # DejaBlue
        "CVE-2023-24905",   # RDP Client RCE
    ],
    "HAS_SESSION": [
        "CVE-2017-0144",    # EternalBlue
        "CVE-2021-1732",    # Win32k EoP
        "CVE-2022-37958",   # NEGOEX RCE
    ],
    "EXECUTE_DCOM": [
        "CVE-2017-0213",    # COM EoP
        "CVE-2019-0726",    # DHCP Client RCE
        "CVE-2021-26414",   # DCOM hardening bypass
    ],
    "GENERIC_ALL": [
        "CVE-2022-26923",   # AD Certificate Services
        "CVE-2021-42278",   # sAMAccountName Spoofing
        "CVE-2021-42287",   # noPac
        "CVE-2022-33679",   # Kerberos RC4-HMAC
    ],
}
ATTACK_REL_CVES["GENERIC_WRITE"] = ATTACK_REL_CVES["GENERIC_ALL"]
ATTACK_REL_CVES["WRITE_OWNER"] = ATTACK_REL_CVES["GENERIC_ALL"]
ATTACK_REL_CVES["MEMBER_OF"] = ATTACK_REL_CVES["GENERIC_ALL"]

OS_CVES: dict[str, str] = {
    "Windows XP":          "CVE-2017-0143",
    "Windows Server 2003": "CVE-2017-0143",
    "Windows 7":           "CVE-2019-0708",
    "Windows Server 2008": "CVE-2017-0144",
    "Windows 10":          "CVE-2021-34527",
    "Windows Server 2012": "CVE-2020-1472",
}

# ── BRIDG-ICS control factors per relationship type ──────────

CONTROL_FACTORS: dict[str, dict[str, float]] = {
    "ADMIN_TO":     {"a": 0.02, "c": 0.03, "e": 0.02, "h": 0.04},
    "GENERIC_ALL":  {"a": 0.02, "c": 0.03, "e": 0.02, "h": 0.04},
    "CAN_RDP":      {"a": 0.03, "c": 0.04, "e": 0.03, "h": 0.05},
    "EXECUTE_DCOM": {"a": 0.03, "c": 0.04, "e": 0.03, "h": 0.05},
    "GENERIC_WRITE":{"a": 0.03, "c": 0.04, "e": 0.03, "h": 0.05},
    "WRITE_OWNER":  {"a": 0.03, "c": 0.04, "e": 0.03, "h": 0.05},
    "HAS_SESSION":  {"a": 0.04, "c": 0.05, "e": 0.04, "h": 0.06},
    "MEMBER_OF":    {"a": 0.03, "c": 0.04, "e": 0.03, "h": 0.05},
}

ATTACK_REL_TYPES = set(CONTROL_FACTORS.keys())

# ── Criticality / zone / type mappings ───────────────────────

def _computer_criticality(name: str, os_name: str | None) -> int:
    if "FLLABDC" in name.upper():
        return 10
    if os_name is None:
        return 5
    os_lower = os_name.lower()
    if "server 2012" in os_lower:
        return 8
    if "server 2008" in os_lower or "server 2003" in os_lower:
        return 7
    if "xp" in os_lower:
        return 7
    if "windows 7" in os_lower:
        return 6
    return 5  # Windows 10 and others


def _computer_zone(name: str, os_name: str | None) -> str:
    if "FLLABDC" in name.upper():
        return "OT_L1"
    if os_name and "server" in os_name.lower():
        return "OT_L3"
    return "IT"


def _computer_type(os_name: str | None) -> str:
    if os_name and "server" in os_name.lower():
        return "Server"
    return "Workstation"


# ── JSON download / cache ────────────────────────────────────

def _get_json_lines(local_path: str, remote_url: str) -> list[str]:
    lp = pathlib.Path(local_path)
    if lp.exists():
        print(f"  Using cached JSON: {lp}")
        return lp.read_text(encoding="utf-8").strip().splitlines()

    print(f"  Downloading BloodHound JSON from GitHub ...")
    resp = requests.get(remote_url, timeout=60)
    resp.raise_for_status()
    lp.parent.mkdir(parents=True, exist_ok=True)
    lp.write_text(resp.text, encoding="utf-8")
    print(f"  Saved to {lp}")
    return resp.text.strip().splitlines()


# ── Node creation ────────────────────────────────────────────

def _create_nodes(session, nodes: list[dict]):
    """Batch-create nodes grouped by label combination."""
    label_groups: dict[str, list[dict]] = {}
    for n in nodes:
        label_key = ":".join(sorted(n["labels"]))
        label_groups.setdefault(label_key, []).append(n)

    total = 0
    for label_key, group in label_groups.items():
        labels = ":".join(group[0]["labels"])
        rows = [{"id": n["id"], **n["properties"]} for n in group]
        query = f"UNWIND $rows AS row CREATE (n:{labels}) SET n = row"
        session.run(query, rows=rows)
        total += len(rows)

    print(f"  Created {total} BloodHound nodes")


# ── Relationship creation ────────────────────────────────────

def _create_relationships(session, rels: list[dict], node_id_map: dict[str, dict]):
    """Batch-create relationships grouped by type."""
    type_groups: dict[str, list[dict]] = {}
    for r in rels:
        type_groups.setdefault(r["label"], []).append(r)

    total = 0
    for rel_type, group in type_groups.items():
        rows = []
        for r in group:
            start_node = node_id_map.get(r["start"]["id"])
            end_node = node_id_map.get(r["end"]["id"])
            if not start_node or not end_node:
                continue
            start_name = start_node["properties"].get("name")
            end_name = end_node["properties"].get("name")
            if not start_name or not end_name:
                continue
            start_labels = start_node["labels"]
            end_labels = end_node["labels"]
            rows.append({
                "start_name": start_name,
                "end_name": end_name,
                "start_label": start_labels[0],
                "end_label": end_labels[0],
                "props": r.get("properties", {}),
            })

        if not rows:
            continue

        for label_combo, sub_rows in _group_by_label_combo(rows):
            sl, el = label_combo
            query = (
                f"UNWIND $rows AS row "
                f"MATCH (a:{sl} {{name: row.start_name}}) "
                f"MATCH (b:{el} {{name: row.end_name}}) "
                f"CREATE (a)-[r:{rel_type}]->(b) SET r = row.props"
            )
            session.run(query, rows=sub_rows)
            total += len(sub_rows)

    print(f"  Created {total} BloodHound relationships")


def _group_by_label_combo(rows: list[dict]) -> list[tuple[tuple[str, str], list[dict]]]:
    groups: dict[tuple[str, str], list[dict]] = {}
    for r in rows:
        key = (r["start_label"], r["end_label"])
        groups.setdefault(key, []).append(r)
    return list(groups.items())


# ── Asset overlay ────────────────────────────────────────────

def _add_asset_overlay(session, nodes: list[dict]):
    """Add :Asset label and BRIDG-ICS properties to Computer, User, Group, and Domain nodes."""
    comp_rows = []
    user_rows = []
    group_rows = []
    domain_rows = []

    domain_admin_members: set[str] = set()
    _find_domain_admin_users(session, domain_admin_members)

    kerberoastable: set[str] = set()
    for n in nodes:
        if "User" in n["labels"] and n["properties"].get("hasspn"):
            name = n["properties"].get("name")
            if name:
                kerberoastable.add(name)

    for n in nodes:
        props = n["properties"]
        name = props.get("name")
        if not name:
            continue

        if "Computer" in n["labels"]:
            os_name = props.get("operatingsystem")
            comp_rows.append({
                "name": name,
                "id": props.get("objectid", name),
                "criticality": _computer_criticality(name, os_name),
                "zone": _computer_zone(name, os_name),
                "type": _computer_type(os_name),
            })
        elif "User" in n["labels"]:
            crit = 3
            if name in domain_admin_members:
                crit = 8
            elif name in kerberoastable:
                crit = 5
            user_rows.append({
                "name": name,
                "id": props.get("objectid", name),
                "criticality": crit,
                "zone": "DMZ",
                "type": "User",
            })
        elif "Group" in n["labels"]:
            is_high_value = "HighValue" in n["labels"] or props.get("highvalue")
            group_rows.append({
                "name": name,
                "id": props.get("objectid", name),
                "criticality": 9 if is_high_value else 4,
                "zone": "OT_L2" if is_high_value else "IT",
                "type": "Group",
            })
        elif "Domain" in n["labels"]:
            domain_rows.append({
                "name": name,
                "id": props.get("objectid", name) if props.get("objectid") else name,
                "criticality": 10,
                "zone": "OT_L1",
                "type": "Domain",
            })

    if comp_rows:
        session.run(
            "UNWIND $rows AS row "
            "MATCH (c:Computer {name: row.name}) "
            "SET c:Asset, c.id = row.id, c.criticality_score = row.criticality, "
            "    c.zone = row.zone, c.type = row.type",
            rows=comp_rows,
        )

    if user_rows:
        session.run(
            "UNWIND $rows AS row "
            "MATCH (u:User {name: row.name}) "
            "SET u:Asset, u.id = row.id, u.criticality_score = row.criticality, "
            "    u.zone = row.zone, u.type = row.type",
            rows=user_rows,
        )

    if group_rows:
        session.run(
            "UNWIND $rows AS row "
            "MATCH (g:Group {name: row.name}) "
            "SET g:Asset, g.id = row.id, g.criticality_score = row.criticality, "
            "    g.zone = row.zone, g.type = row.type",
            rows=group_rows,
        )

    if domain_rows:
        session.run(
            "UNWIND $rows AS row "
            "MATCH (d:Domain {name: row.name}) "
            "SET d:Asset, d.id = row.id, d.criticality_score = row.criticality, "
            "    d.zone = row.zone, d.type = row.type",
            rows=domain_rows,
        )

    total = len(comp_rows) + len(user_rows) + len(group_rows) + len(domain_rows)
    print(f"  Asset overlay: {len(comp_rows)} Computers + {len(user_rows)} Users "
          f"+ {len(group_rows)} Groups + {len(domain_rows)} Domains = {total} :Asset nodes")


def _find_domain_admin_users(session, result_set: set[str]):
    """Find users who are members of DOMAIN ADMINS (directly or 1 hop)."""
    records = session.run(
        "MATCH (u:User)-[:MEMBER_OF*1..2]->"
        "(:Group {name: 'DOMAIN ADMINS@TestCompany.Local'}) "
        "RETURN u.name AS name"
    )
    for r in records:
        if r["name"]:
            result_set.add(r["name"])


# ── Vulnerability nodes and HAS_VULNERABILITY ────────────────

def _create_vulnerabilities_and_links(session, nodes: list[dict], rels: list[dict],
                                       node_id_map: dict[str, dict]):
    """Create Vulnerability nodes and HAS_VULNERABILITY edges."""
    all_cves: set[str] = set()
    for pool in ATTACK_REL_CVES.values():
        all_cves.update(pool)
    for cve in OS_CVES.values():
        all_cves.add(cve)

    cve_rows = [{"cve_id": cve} for cve in sorted(all_cves)]
    session.run(
        "UNWIND $rows AS row MERGE (v:Vulnerability {cve_id: row.cve_id})",
        rows=cve_rows,
    )
    print(f"  Created {len(cve_rows)} Vulnerability nodes")

    # OS-based CVEs -> HAS_VULNERABILITY for every Computer
    os_links: list[dict] = []
    for n in nodes:
        if "Computer" not in n["labels"]:
            continue
        name = n["properties"].get("name")
        os_name = n["properties"].get("operatingsystem")
        if not name or not os_name:
            continue
        cve = OS_CVES.get(os_name)
        if cve:
            os_links.append({"name": name, "cve_id": cve})

    if os_links:
        session.run(
            "UNWIND $rows AS row "
            "MATCH (c:Computer {name: row.name}) "
            "MATCH (v:Vulnerability {cve_id: row.cve_id}) "
            "MERGE (c)-[:HAS_VULNERABILITY]->(v)",
            rows=os_links,
        )
    print(f"  OS-based HAS_VULNERABILITY: {len(os_links)} links")

    # Relationship-based CVEs -> HAS_VULNERABILITY on target nodes
    random.seed(42)
    rel_links: list[dict] = []
    for r in rels:
        rel_type = r["label"]
        if rel_type not in ATTACK_REL_CVES:
            continue
        end_node = node_id_map.get(r["end"]["id"])
        if not end_node:
            continue
        end_name = end_node["properties"].get("name")
        if not end_name:
            continue
        cve = random.choice(ATTACK_REL_CVES[rel_type])
        rel_links.append({"name": end_name, "cve_id": cve})

    if rel_links:
        session.run(
            "UNWIND $rows AS row "
            "MATCH (a:Asset {name: row.name}) "
            "MATCH (v:Vulnerability {cve_id: row.cve_id}) "
            "MERGE (a)-[:HAS_VULNERABILITY]->(v)",
            rows=rel_links,
        )
    print(f"  Relationship-based HAS_VULNERABILITY: {len(rel_links)} links")


# ── COMMUNICATES_WITH edges from attack relationships ────────

def _create_communicates_with(session, rels: list[dict], node_id_map: dict[str, dict]):
    """Derive COMMUNICATES_WITH edges from AD attack relationships."""
    rows: list[dict] = []
    for r in rels:
        rel_type = r["label"]
        if rel_type not in ATTACK_REL_TYPES:
            continue
        start_node = node_id_map.get(r["start"]["id"])
        end_node = node_id_map.get(r["end"]["id"])
        if not start_node or not end_node:
            continue
        start_name = start_node["properties"].get("name")
        end_name = end_node["properties"].get("name")
        if not start_name or not end_name:
            continue
        cf = CONTROL_FACTORS[rel_type]
        rows.append({
            "src": start_name,
            "tgt": end_name,
            "protocol": rel_type,
            "a": cf["a"], "c": cf["c"], "e": cf["e"], "h": cf["h"],
        })

    if rows:
        session.run(
            "UNWIND $rows AS row "
            "MATCH (a:Asset {name: row.src}) "
            "MATCH (b:Asset {name: row.tgt}) "
            "MERGE (a)-[c:COMMUNICATES_WITH {protocol: row.protocol}]->(b) "
            "SET c.a = row.a, c.c = row.c, c.e = row.e, c.h = row.h",
            rows=rows,
        )
    print(f"  COMMUNICATES_WITH edges: {len(rows)} created from attack relationships")


# ── Public entry point ───────────────────────────────────────

def load_bloodhound_data(driver):
    """Load BloodHound AD dataset and apply BRIDG-ICS overlay."""
    print("Loading BloodHound Active Directory dataset ...")

    with driver.session() as session:
        session.run("MATCH (n) DETACH DELETE n").consume()
        print("  Cleared existing graph data")

    lines = _get_json_lines(config.BLOODHOUND_JSON_LOCAL, config.BLOODHOUND_JSON_URL)
    nodes: list[dict] = []
    rels: list[dict] = []
    node_id_map: dict[str, dict] = {}

    for line in lines:
        obj = json.loads(line.strip())
        if obj["type"] == "node":
            nodes.append(obj)
            node_id_map[obj["id"]] = obj
        elif obj["type"] == "relationship":
            rels.append(obj)

    print(f"  Parsed {len(nodes)} nodes, {len(rels)} relationships from JSON")

    with driver.session() as session:
        _create_nodes(session, nodes)
        _create_relationships(session, rels, node_id_map)
        _add_asset_overlay(session, nodes)
        _create_vulnerabilities_and_links(session, nodes, rels, node_id_map)
        _create_communicates_with(session, rels, node_id_map)

    print("BloodHound loading complete.\n")


if __name__ == "__main__":
    drv = GraphDatabase.driver(config.NEO4J_URI, auth=(config.NEO4J_USER, config.NEO4J_PASSWORD))
    try:
        load_bloodhound_data(drv)
    finally:
        drv.close()
