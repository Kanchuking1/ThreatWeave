// ============================================================
// Purdue-like ICS topology inspired by BRIDG-ICS Figure 2
// ============================================================

// ── Zone: DMZ ──
MERGE (mqtt:Asset {id: 'DMZ-001', name: 'MQTT_Broker',              type: 'Broker',      zone: 'DMZ',   criticality_score: 5})
MERGE (rp:Asset   {id: 'DMZ-002', name: 'Reverse_Proxy',            type: 'Server',      zone: 'DMZ',   criticality_score: 4})

// ── Zone: IT ──
MERGE (eg:Asset   {id: 'IT-001',  name: 'Email_Gateway',            type: 'Gateway',     zone: 'IT',    criticality_score: 3})
MERGE (ew:Asset   {id: 'IT-002',  name: 'Engineering_Workstation',   type: 'Workstation', zone: 'IT',    criticality_score: 6})
MERGE (js:Asset   {id: 'IT-003',  name: 'Jump_Server',              type: 'Server',      zone: 'IT',    criticality_score: 7})

// ── Zone: OT Level 3 ──
MERGE (scada:Asset {id: 'OT3-001', name: 'SCADA_Server',            type: 'Server',      zone: 'OT_L3', criticality_score: 9})
MERGE (mes:Asset   {id: 'OT3-002', name: 'MES_Server',              type: 'Server',      zone: 'OT_L3', criticality_score: 7})
MERGE (hist:Asset  {id: 'OT3-003', name: 'Data_Historian',          type: 'Server',      zone: 'OT_L3', criticality_score: 6})

// ── Zone: OT Level 2 ──
MERGE (hmi:Asset   {id: 'OT2-001', name: 'HMI_Terminal',            type: 'HMI',         zone: 'OT_L2', criticality_score: 8})
MERGE (plc:Asset   {id: 'OT2-002', name: 'PLC_RobotCell',           type: 'PLC',         zone: 'OT_L2', criticality_score: 9})

// ── Zone: OT Level 1 ──
MERGE (splc:Asset  {id: 'OT1-001', name: 'Safety_PLC',              type: 'PLC',         zone: 'OT_L1', criticality_score: 10})
MERGE (act:Asset   {id: 'OT1-002', name: 'Actuator_Valve',          type: 'Actuator',    zone: 'OT_L1', criticality_score: 8})

// ============================================================
// Vulnerabilities (real CVE IDs for live API look-up)
// ============================================================
MERGE (v1:Vulnerability {cve_id: 'CVE-2023-44487'})  // HTTP/2 Rapid Reset
MERGE (v2:Vulnerability {cve_id: 'CVE-2024-3094'})   // XZ Utils backdoor
MERGE (v3:Vulnerability {cve_id: 'CVE-2023-4966'})   // Citrix Bleed
MERGE (v4:Vulnerability {cve_id: 'CVE-2024-21887'})  // Ivanti Connect Secure
MERGE (v5:Vulnerability {cve_id: 'CVE-2022-22965'})  // Spring4Shell
MERGE (v6:Vulnerability {cve_id: 'CVE-2020-14882'})  // Oracle WebLogic
MERGE (v7:Vulnerability {cve_id: 'CVE-2019-0708'})   // BlueKeep
MERGE (v8:Vulnerability {cve_id: 'CVE-2017-0144'})   // EternalBlue

// ============================================================
// HAS_VULNERABILITY mappings
// ============================================================
MERGE (mqtt)-[:HAS_VULNERABILITY]->(v1)
MERGE (rp)-[:HAS_VULNERABILITY]->(v3)
MERGE (rp)-[:HAS_VULNERABILITY]->(v4)
MERGE (eg)-[:HAS_VULNERABILITY]->(v1)
MERGE (ew)-[:HAS_VULNERABILITY]->(v7)
MERGE (js)-[:HAS_VULNERABILITY]->(v2)
MERGE (mes)-[:HAS_VULNERABILITY]->(v5)
MERGE (mes)-[:HAS_VULNERABILITY]->(v6)
MERGE (scada)-[:HAS_VULNERABILITY]->(v8)
MERGE (hmi)-[:HAS_VULNERABILITY]->(v7)
MERGE (plc)-[:HAS_VULNERABILITY]->(v8)
MERGE (splc)-[:HAS_VULNERABILITY]->(v8)
MERGE (act)-[:HAS_VULNERABILITY]->(v5)

// ============================================================
// COMMUNICATES_WITH edges with BRIDG-ICS control factors
// Uncontrolled defaults from Appendix A: a=0.03, c=0.04, e=0.03, h=0.05
// ============================================================

// DMZ -> IT
MERGE (mqtt)-[:COMMUNICATES_WITH {protocol: 'MQTT/TCP',   a: 0.03, c: 0.04, e: 0.03, h: 0.05}]->(mes)
MERGE (rp)-[:COMMUNICATES_WITH   {protocol: 'HTTPS',      a: 0.03, c: 0.04, e: 0.03, h: 0.05}]->(ew)
MERGE (eg)-[:COMMUNICATES_WITH   {protocol: 'SMTP',       a: 0.03, c: 0.04, e: 0.03, h: 0.05}]->(ew)

// IT -> OT L3
MERGE (ew)-[:COMMUNICATES_WITH  {protocol: 'RDP',         a: 0.03, c: 0.04, e: 0.03, h: 0.05}]->(scada)
MERGE (js)-[:COMMUNICATES_WITH  {protocol: 'SSH',         a: 0.03, c: 0.04, e: 0.03, h: 0.05}]->(scada)
MERGE (js)-[:COMMUNICATES_WITH  {protocol: 'SSH',         a: 0.03, c: 0.04, e: 0.03, h: 0.05}]->(mes)
MERGE (ew)-[:COMMUNICATES_WITH  {protocol: 'OPC UA',      a: 0.03, c: 0.04, e: 0.03, h: 0.05}]->(hist)

// OT L3 internal
MERGE (scada)-[:COMMUNICATES_WITH {protocol: 'OPC UA',    a: 0.03, c: 0.04, e: 0.03, h: 0.05}]->(mes)
MERGE (mes)-[:COMMUNICATES_WITH   {protocol: 'SQL',       a: 0.03, c: 0.04, e: 0.03, h: 0.05}]->(hist)

// OT L3 -> OT L2
MERGE (scada)-[:COMMUNICATES_WITH {protocol: 'Modbus/TCP', a: 0.03, c: 0.04, e: 0.03, h: 0.05}]->(hmi)
MERGE (scada)-[:COMMUNICATES_WITH {protocol: 'Modbus/TCP', a: 0.03, c: 0.04, e: 0.03, h: 0.05}]->(plc)
MERGE (mes)-[:COMMUNICATES_WITH   {protocol: 'PROFINET',   a: 0.03, c: 0.04, e: 0.03, h: 0.05}]->(plc)

// OT L2 -> OT L1
MERGE (plc)-[:COMMUNICATES_WITH  {protocol: 'EtherNet/IP', a: 0.03, c: 0.04, e: 0.03, h: 0.05}]->(splc)
MERGE (plc)-[:COMMUNICATES_WITH  {protocol: 'PROFINET',    a: 0.03, c: 0.04, e: 0.03, h: 0.05}]->(act)
MERGE (hmi)-[:COMMUNICATES_WITH  {protocol: 'Modbus/TCP',  a: 0.03, c: 0.04, e: 0.03, h: 0.05}]->(plc)
MERGE (splc)-[:COMMUNICATES_WITH {protocol: 'Fieldbus',    a: 0.03, c: 0.04, e: 0.03, h: 0.05}]->(act)
