# Query to find CVEs affecting Go programming language 
"""Match (p:Product)<-[:AFFECTS]-(c:CVE)
             Where p.name="go"
             return distinct c;
"""
#"What weaknesses (CWEs) are linked to a given CVE?",
"""MATCH (c:CVE {id: $cveId})-[:HAS_WEAKNESS]->(w:CWE) 
RETURN w.id AS cwe_id, w.name AS cwe_name, w.description AS description;"""
#"Which CAPEC attack patterns are related to a specific CWE?",
"""MATCH (w:CWE {id: $cweId})-[:HAS_RELATED_ATTACK_PATTERN]->(a:CAPEC) 
RETURN a.id AS capec_id, a.name AS attack_name, a.description;"""
#"What are the typical severities for a given CAPEC attack?",
"""MATCH (a:CAPEC {id: $capecId})-[:HAS_TYPICAL_SEVERITY]->(s:ScaleLevel) 
RETURN s.level AS severity_level;"""
#"Which mitigations exist for a given CWE and in which phase they apply?",
"""MATCH (w:CWE {id: $cweId})-[:CAN_BE_MITIGATED_BY]->(m:Mitigation)-[:DURING_PHASE]->(p:Phase) 
RETURN m.description AS mitigation, p.name AS phase;"""
#"Find all CAPEC attacks that require a given skill level.",
"""MATCH (s:Skill {description: $skill})<-[:REQUIRES_SKILL]-(a:CAPEC) 
RETURN a.id AS capec_id, a.name AS attack_name;"""
#"List all CAPEC attacks that target a specific asset type.",
"""MATCH (as:Asset {description: $asset})<-[:REQUIRES_ASSET]-(a:CAPEC) 
RETURN a.id AS capec_id, a.name AS attack_name, a.description;"""
#"For a given CWE, find its related CAPEC attacks and corresponding mitigations.",
"""MATCH (w:CWE {id: $cweId})-[:HAS_RELATED_ATTACK_PATTERN]->(a:CAPEC)-[:CAN_BE_MITIGATED_BY]->(m:Mitigation) 
RETURN w.id AS cwe_id, a.id AS capec_id, m.description AS mitigation;"""
#"Which CWEs can precede or lead to another specific CWE?",
"""MATCH (c1:CWE)-[:CAN_PRECEDE]->(c2:CWE {id: $cweId}) 
RETURN c1.id AS preceding_cwe_id, c1.name AS preceding_weakness;"""
#"What are the common consequences of a specific CAPEC attack?",
"""MATCH (a:CAPEC {id: $capecId})-[:HAS_COMMON_CONSEQUENCE]->(c:Consequence) 
RETURN c.description AS consequence;"""
#"Find CAPEC attack patterns linked to a given CVE through shared CWE relationships.",
"""MATCH (v:CVE {id: $cveId})-[:HAS_WEAKNESS]->(w:CWE)-[:HAS_RELATED_ATTACK_PATTERN]->(a:CAPEC) 
RETURN DISTINCT a.id AS capec_id, a.name AS attack_name;"""
#"Which products are affected by a given CVE?,
"""MATCH (c:CVE {id: $cveId})-[:AFFECTS]->(p:Product) 
RETURN p.name AS product_name, p.type AS product_type;"""
#"Which vendors have products impacted by a specific vulnerability?", (CVE)?,
"""MATCH (v:CVE {id: $cveId})-[:AFFECTS]->(p:Product)<-[:OWN]-(ven:Vendor) 
RETURN DISTINCT ven.name AS vendor_name;"""
#"List all CVEs affecting products from a specific vendor.",
"""MATCH (ven:Vendor {name: $vendorName})-[:OWN]->(p:Product)<-[:AFFECTS]-(v:CVE) 
RETURN v.id AS cve_id, v.description AS description, p.name AS product_name;"""
#"For each CVE, return its impact and exploitability scores.",
"""MATCH (v:CVE {id: $cveId})-[:HAS_METRIC]->(m) 
RETURN labels(m)[0] AS metric_type, m.baseScore, m.vector;"""
#"Which CVEs are linked to a given CWE and affect products from a specific vendor?",
"""MATCH (w:CWE {id: $cweId})<-[:HAS_WEAKNESS]-(v:CVE)-[:AFFECTS]->(p:Product)<-[:OWN]-(ven:Vendor {name: $vendorName}) 
RETURN v.id AS cve_id, p.name AS product_name;"""
#"Which CNA assigned a given CVE?",
"""MATCH (c:CVE {id: $cveId})<-[:ASSIGNED]-(org:CNA) 
RETURN org.name AS cna_name, org.link AS cna_link;"""
#"Which CNAs are based in a given country?",
"""MATCH (country:Country {name: $country})<-[:BASED_IN]-(cna:CNA) 
RETURN cna.name AS cna_name;"""
#"For each CNA, list their contact email(s).",
"""MATCH (cna:CNA)-[:REACHABLE_BY_EMAIL]->(e:Email) 
RETURN cna.name AS cna_name, e.contact AS email;"""
#"Find all CNAs that own other CNAs (hierarchical structure).",
"""MATCH (cna1:CNA)-[:OWNS_ORGANIZATION]->(cna2:CNA) 
RETURN cna1.name AS parent_cna, cna2.name AS child_cna;"""
#"What disclosure policies are associated with each CNA?",
"""MATCH (cna:CNA)-[:HAS_DISCLOSURE_POLICY]->(d:DisclosurePolicy) 
RETURN cna.name AS cna_name, d.link AS policy_link, d.description;"""
#"Which threat actors use a given adversary technique?",
"""MATCH (t:AdversaryTechnique {id: $techId})<-[:IS_USED_BY]-(a:THREAT_ACTOR) 
RETURN a.name AS actor_name, a.link AS actor_link;"""
#"Which MITRE ATT&CK tactics include a specific technique?",
"""MATCH (t:TACTIC)-[:HAS_MITRE_TECHNIQUE]->(tech:AdversaryTechnique {id: $techId}) 
RETURN t.name AS tactic_name, t.id AS tactic_id;"""
#"Find all CAPEC attack patterns that use a given technique in any flow (exploit/explore/experiment).",
"""MATCH (a:CAPEC)-[:HAS_EXPLOIT_FLOW|:HAS_EXPERIMENT_FLOW|:HAS_EXPLORE_FLOW]->(:ExecutionFlow)-[:HAS_TECHNIQUE]->(t:Technique {description: $tech}) 
RETURN DISTINCT a.id AS capec_id, a.name AS attack_name;"""
#"Retrieve IPs and their geolocation data linked to a specific domain.",
"""MATCH (d:DOMAIN {domain: $domain})-[:HAS_IP]->(ip:IP)-[:HAS_LOCATION]->(loc:IP_location) 
RETURN ip.ip AS ip_address, loc.country_name AS country, loc.country_city AS city, loc.latitude, loc.longitude;"""
#"Find IPs with high AbuseIPDB reputation scores (e.g., >80) and their associated organizations.",
"""MATCH (ip:IP)-[:HAS_ABUSEIPDB_REPUTATION]->(r:IP_AbuseIPDB_Reputation) 
WHERE r.score > 80 OPTIONAL MATCH (ip)-[:HAS_ORGANIZATION]->(org:IP_Organization) 
RETURN ip.ip AS ip_address, r.score, org.organization AS organization_name, org.usage_type;"""
