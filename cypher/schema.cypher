// ── Node constraints ──
CREATE CONSTRAINT asset_id_unique IF NOT EXISTS
FOR (a:Asset) REQUIRE a.id IS UNIQUE;

CREATE CONSTRAINT vuln_cve_unique IF NOT EXISTS
FOR (v:Vulnerability) REQUIRE v.cve_id IS UNIQUE;

// ── Indexes for fast lookups ──
CREATE INDEX asset_name_idx IF NOT EXISTS
FOR (a:Asset) ON (a.name);

CREATE INDEX asset_zone_idx IF NOT EXISTS
FOR (a:Asset) ON (a.zone);

CREATE INDEX vuln_epss_idx IF NOT EXISTS
FOR (v:Vulnerability) ON (v.epss_score);
