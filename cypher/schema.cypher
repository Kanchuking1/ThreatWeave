// ── Node constraints ──
CREATE CONSTRAINT asset_id_unique IF NOT EXISTS
FOR (a:Asset) REQUIRE a.id IS UNIQUE;

CREATE CONSTRAINT vuln_cve_unique IF NOT EXISTS
FOR (v:Vulnerability) REQUIRE v.cve_id IS UNIQUE;

// ── BloodHound label constraints ──
CREATE CONSTRAINT computer_name_unique IF NOT EXISTS
FOR (c:Computer) REQUIRE c.name IS UNIQUE;

CREATE CONSTRAINT user_name_unique IF NOT EXISTS
FOR (u:User) REQUIRE u.name IS UNIQUE;

CREATE CONSTRAINT group_name_unique IF NOT EXISTS
FOR (g:Group) REQUIRE g.name IS UNIQUE;

// ── Indexes for fast lookups ──
CREATE INDEX asset_name_idx IF NOT EXISTS
FOR (a:Asset) ON (a.name);

CREATE INDEX asset_zone_idx IF NOT EXISTS
FOR (a:Asset) ON (a.zone);

CREATE INDEX vuln_epss_idx IF NOT EXISTS
FOR (v:Vulnerability) ON (v.epss_score);
