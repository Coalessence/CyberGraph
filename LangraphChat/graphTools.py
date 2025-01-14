import os
from typing import Any, Dict, List, Optional, Tuple, Type, Annotated
from dotenv import load_dotenv
from langchain_neo4j import Neo4jGraph
from langchain_neo4j.vectorstores.neo4j_vector import remove_lucene_chars
from langchain_core.tools import tool, StructuredTool
from pydantic import Field, BaseModel

load_dotenv(".env")

graph = Neo4jGraph(url=os.getenv('NEO4J_URI') , username=os.getenv('NEO4J_USERNAME'), password=os.getenv('NEO4J_PASSWORD'))


def generate_indexes():
    """
    Generate indexes for the Neo4j database.

    This function creates full-text indexes for the 'CVE', 'Product', CWE, CAPEC nodes in the
    Neo4j database. It ensures that the indexes are created only if they do not already
    exist.
    """
    graph.query(
        "CREATE FULLTEXT INDEX cve IF NOT EXISTS FOR (cve:CVE) ON EACH [cve.id];"
    )
    graph.query(
        "CREATE FULLTEXT INDEX product IF NOT EXISTS FOR (p:Product) ON EACH [p.name];"
    )
    
    graph.query(
        "CREATE FULLTEXT INDEX cwe IF NOT EXISTS FOR (cwe:CWE) ON EACH [cwe.id];"
    )
    
    graph.query(
        "CREATE FULLTEXT INDEX capec IF NOT EXISTS FOR (capec:CAPEC) ON EACH [capec.id];"
    )

def generate_full_text_query(input: str) -> str:
    """
    Generate a full-text search query for a given input string.

    This function constructs a query string suitable for a full-text search.
    It processes the input string by splitting it into words and appending a
    similarity threshold (~2) to each word, then combines them using the AND
    operator.
    """
    full_text_query = ""
    words = [el for el in remove_lucene_chars(input).split() if el]
    for word in words[:-1]:
        full_text_query += f" {word}~2 AND"
    full_text_query += f" {words[-1]}~2"
    return full_text_query.strip()

candidate_query = """
CALL db.index.fulltext.queryNodes ($index,  $fulltextQuery, {limit: $limit})
YIELD node
RETURN coalesce(node.name) AS candidate,
       labels(node)[0] AS label
"""

def get_candidates(input: str, type: str, limit: int = 3) -> List[Dict[str, str]]:
    """
    Retrieve a list of candidate entities from database based on the input string.

    This function queries the Neo4j database using a full-text search. It takes the
    input string, generates a full-text query, and executes this query against the
    specified index in the database. The function returns a list of candidates
    matching the query, with each candidate being a dictionary containing their name
    (or title) and label (either 'Person' or 'Movie').
    """
    ft_query = generate_full_text_query(input)
    candidates = graph.query(
        candidate_query, {"fulltextQuery": ft_query, "index": type, "limit": limit}
    )
    return candidates

def get_exact_candidate(input: str, type: str, key: str) -> Optional[str]:
    """
    Retrieve an exact candidate entity from the database based on the input string.

    This function queries the Neo4j database for an exact match of the input string
    against the specified index. If a candidate is found, it returns the name of the
    candidate; otherwise, it returns None.
    """
    exact_candidate_query = """
    MATCH (n:{type})
    WHERE n.{key} = $name
    RETURN n.{key} AS candidate
    """.format(type=type, key=key)
    candidate = graph.query(exact_candidate_query, {"name": input})
    return candidate[0]["candidate"] if candidate else None

@tool
def get_cve_product(
    product: Annotated[str, "Product mentioned in the question. Return None if no mentioned."]
):
    """Useful for when you need to find all the vulnerabilities of a software product."""
    params = {}
    filters = []
    vulnerabilty_product_base_query = """
    MATCH (p:Product)<-[a:AFFECTS]-(c:CVE)
    """
    if product and isinstance(product, str):
        candidate_products = [el["candidate"] for el in get_candidates(product, "product")]
        if not candidate_products:
            return "The mentioned product was not found"
        filters.append("p.name IN $products")
        params["products"] = candidate_products

    if filters:
        vulnerabilty_product_base_query += " WHERE "
        vulnerabilty_product_base_query += " AND ".join(filters)
    vulnerabilty_product_base_query += """
    RETURN p.name AS product, c.id AS answer, a.versionStartIncluding as version, count(*) AS count
    ORDER BY count DESC
    """
    print(f"Using parameters: {params}")
    data = graph.query(vulnerabilty_product_base_query, params=params)
    print(data)
    return data

@tool
def get_multiple_cve_information(
    cve: Annotated[List[str], "List of CVE IDs mentioned in the question. Return None if no mentioned."]
):
    """Useful to find information about multiple CVEs or vulnerabilities, including the description, published date, and last modified date."""
    params = {}
    filters = []
    cve_information_base_query = """
    MATCH (c:CVE)
    """
    if cve and isinstance(cve, list):
        candidate_cves = [get_exact_candidate(el, "CVE", "id") for el in cve]
        if not candidate_cves:
            return "The mentioned CVEs were not found"
        filters.append('c.id IN $candidate_cves')
        params["candidate_cves"] = candidate_cves

    if filters:
        cve_information_base_query += " WHERE "
        cve_information_base_query += " OR ".join(filters)
    cve_information_base_query += """
    RETURN c.id AS cve, c.description AS description, c.publishedDate AS published_date, c.lastModifiedDate AS last_modified_date
    """
    print(f"Using parameters: {params}")
    data = graph.query(cve_information_base_query, params=params)
    return data

@tool
def get_cve_information(
    cve: Annotated[str, "CVE ID mentioned in the question. Return None if no mentioned."]
):
    """Useful to find information about a single CVE or vulnerability, including the description, published date, and last modified date."""
    params = {}
    filters = []
    cve_information_base_query = """
    MATCH (c:CVE)
    """
    if cve and isinstance(cve, str):
        candidate_cve = get_exact_candidate(cve, "CVE", "id")
        if not candidate_cve:
            return "The mentioned CVE was not found"
        filters.append(('c.id = "{candidate_cve}"').format(candidate_cve=candidate_cve))

    if filters:
        cve_information_base_query += " WHERE "
        cve_information_base_query += " OR ".join(filters)
    cve_information_base_query += """
    RETURN c.id AS cve, c.description AS description, c.publishedDate AS published_date, c.lastModifiedDate AS last_modified_date
    """
    print(f"Using parameters: {params}")
    data = graph.query(cve_information_base_query, params=params)
    return data

@tool
def get_cve_cna(
    cve: Annotated[str, "CVE ID mentioned in the question. Return None if no mentioned."]
):
    """Useful for when you need to find the CNA of a CVE."""
    params = {}
    filters = []
    cve_cna_base_query = """
    MATCH (c:CVE)<-[:ASSIGNED]-(n:CNA)
    """
    if cve and isinstance(cve, str):
        candidate_cve = get_exact_candidate(cve, "CVE", "id")
        if not candidate_cve:
            return "The mentioned CVE was not found"
        filters.append(('c.id = "{candidate_cve}"').format(candidate_cve=candidate_cve))

    if filters:
        cve_cna_base_query += " WHERE "
        cve_cna_base_query += " AND ".join(filters)
    cve_cna_base_query += """
    RETURN c.id AS cve, n.link AS answer
    """
    data = graph.query(cve_cna_base_query, params=params)
    return data

@tool
def get_cve_cwe(
    cve: Annotated[str, "CVE ID mentioned in the question. Return None if no mentioned."]
):
    """Useful for when you need to find the CWE id and CAPEC id of a CVE. Useful when you need to find the weakness id and attack patter id froma vulnerability id"""
    params = {}
    filters = []
    cve_cwe_base_query = """
    MATCH (c:CVE)-[:HAS_WEAKNESS]->(w:CWE)
    """
    if cve and isinstance(cve, str):
        candidate_cve = get_exact_candidate(cve, "CVE", "id")
        if not candidate_cve:
            return "The mentioned CVE was not found"
        filters.append(('c.id = "{candidate_cve}"').format(candidate_cve=candidate_cve))

    if filters:
        cve_cwe_base_query += " WHERE "
        cve_cwe_base_query += " AND ".join(filters)
    cve_cwe_base_query += """
    RETURN c.id AS cve, w.id AS answer
    """
    data = graph.query(cve_cwe_base_query, params=params)
    return data

@tool
def get_cve_description(
    cve: Annotated[str, "CVE ID mentioned in the question. Return None if no mentioned."]
):
    """Useful for when you need to find the description of a CVE."""
    params = {}
    filters = []
    cve_description_base_query = """
    MATCH (c:CVE)
    """
    if cve and isinstance(cve, str):
        candidate_cve = get_exact_candidate(cve, "CVE", "id")
        if not candidate_cve:
            return "The mentioned CVE was not found"
        filters.append(('c.id = "{candidate_cve}"').format(candidate_cve=candidate_cve))

    if filters:
        cve_description_base_query += " WHERE "
        cve_description_base_query += " AND ".join(filters)
    cve_description_base_query += """
    RETURN c.id AS cve, c.description AS description
    """
    print(f"Using parameters: {params}")
    data = graph.query(cve_description_base_query, params=params)
    return data

@tool
def get_cwe_cve(
    cwe: Annotated[int, "CWE ID mentioned in the question. Return None if no mentioned."]
):
    """Useful for when you need to find the CVE id from a CWE. Useful when you need to find the vulnerability id from a weakness id"""
    params = {}
    filters = []
    cwe_cve_base_query = """
    MATCH (c:CVE)-[:HAS_WEAKNESS]->(w:CWE)
    """
    cwe=str(cwe)
    if cwe and isinstance(cwe, str):
        candidate_cwe = get_exact_candidate(cwe, "CWE", "id")
        if not candidate_cwe:
            return "The mentioned CWE was not found"
        filters.append(('w.id = "{candidate_cwe}"').format(candidate_cwe=candidate_cwe))

    if filters:
        cwe_cve_base_query += " WHERE "
        cwe_cve_base_query += " AND ".join(filters)
    cwe_cve_base_query += """
    RETURN w.id AS cwe, c.id AS answer
    """
    data = graph.query(cwe_cve_base_query, params=params)
    return data


@tool
def get_cwe_capec(
    cwe: Annotated[int, "CWE ID mentioned in the question. Return None if no mentioned."]
):
    """Useful for when you need to find the CAPEC id from a CWE. Useful when you need to find the attack patter id from a weakness id"""
    params = {}
    filters = []
    cwe_capec_base_query = """
    MATCH (c:CWE)-[:HAS_RELATED_ATTACK_PATTERN]->(a:CAPEC)
    """
    cwe=str(cwe)
    if cwe and isinstance(cwe, str):
        candidate_cwe = get_exact_candidate(cwe, "CWE", "id")
        if not candidate_cwe:
            return "The mentioned CWE was not found"
        filters.append(('c.id = "{candidate_cwe}"').format(candidate_cwe=candidate_cwe))

    if filters:
        cwe_capec_base_query += " WHERE "
        cwe_capec_base_query += " AND ".join(filters)
    cwe_capec_base_query += """
    RETURN c.id AS cwe, a.id AS answer
    """
    data = graph.query(cwe_capec_base_query, params=params)
    return data

@tool
def get_cwe_description(
    cwe: Annotated[int, "CWE ID mentioned in the question. Return None if no mentioned."]
):
    """Useful for when you need to find the description of a CWE."""
    params = {}
    filters = []
    cwe_description_base_query = """
    MATCH (c:CWE)
    """
    cwe=str(cwe)
    if cwe and isinstance(cwe, str):
        candidate_cwe = get_exact_candidate(cwe, "CWE", "id")
        if not candidate_cwe:
            return "The mentioned CWE was not found"
        filters.append(('c.id = "{candidate_cwe}"').format(candidate_cwe=candidate_cwe))

    if filters:
        cwe_description_base_query += " WHERE "
        cwe_description_base_query += " AND ".join(filters)
    cwe_description_base_query += """
    RETURN c.id AS cwe, c.extendedDescription AS description
    """
    print(f"Using parameters: {params}")
    data = graph.query(cwe_description_base_query, params=params)
    return data

@tool
def get_capec_description(
    capec: Annotated[int, "CAPEC ID mentioned in the question. Return None if no mentioned."]
):
    """Useful for when you need to find the description of a CAPEC, useful to find the attack pattern for a software vulnerability."""
    params = {}
    filters = []
    capec_description_base_query = """
    MATCH (c:CAPEC)
    """
    capec=str(capec)
    if capec and isinstance(capec, str):
        candidate_capec = get_exact_candidate(capec, "CAPEC", "id")
        if not candidate_capec:
            return "The mentioned CAPEC was not found"
        filters.append(('c.id = "{candidate_capec}"').format(candidate_capec=candidate_capec))

    if filters:
        capec_description_base_query += " WHERE "
        capec_description_base_query += " AND ".join(filters)
    capec_description_base_query += """
    RETURN c.id AS capec, c.description AS description
    """
    print(f"Using parameters: {params}")
    data = graph.query(capec_description_base_query, params=params)
    return data

@tool
def get_capec_mitigation(
    capec: Annotated[int, "CAPEC ID mentioned in the question. Return None if no mentioned."]
):
    """Useful for when you need to find the mitigation of a CAPEC, useful to find the mitigation for a software vulnerability."""
    params = {}
    filters = []
    capec_mitigation_base_query = """
    MATCH (c:CAPEC)-[:CAN_BE_MITIGATED_BY]->(m:Mitigation)
    """
    capec=str(capec)
    if capec and isinstance(capec, str):
        candidate_capec = get_exact_candidate(capec, "CAPEC", "id")
        if not candidate_capec:
            return "The mentioned CAPEC was not found"
        filters.append(('c.id = "{candidate_capec}"').format(candidate_capec=candidate_capec))

    if filters:
        capec_mitigation_base_query += " WHERE "
        capec_mitigation_base_query += " AND ".join(filters)
    capec_mitigation_base_query += """
    RETURN c.id AS capec, m.description AS mitigation
    """
    print(f"Using parameters: {params}")
    data = graph.query(capec_mitigation_base_query, params=params)
    return data

@tool
def get_capec_attack_pattern(
    capec: Annotated[int, "CAPEC ID mentioned in the question. Return None if no mentioned."]
):
    """Useful for when you need to find the attack pattern information given a CAPEC."""
    params = {}
    filters = []
    capec_attack_pattern_base_query = """
    MATCH (c:CAPEC)
    """
    capec=str(capec)
    if capec and isinstance(capec, str):
        candidate_capec = get_exact_candidate(capec, "CAPEC", "id")
        if not candidate_capec:
            return "The mentioned CAPEC was not found"
        filters.append(('c.id = "{candidate_capec}"').format(candidate_capec=candidate_capec))

    if filters:
        capec_attack_pattern_base_query += " WHERE "
        capec_attack_pattern_base_query += " AND ".join(filters)
    capec_attack_pattern_base_query += """
    RETURN c.id AS capec, c.name AS attack_pattern, c.description AS description
    """
    data = graph.query(capec_attack_pattern_base_query, params=params)
    return data

@tool
def get_threatActors(
    threat_actor: Annotated[str, "Threat Actor mentioned in the question. Return None if no mentioned."]
):
    """Useful for when you need to find the threat actor of a software vulnerability."""
    params = {}
    filters = []
    threat_actor_base_query = """
    MATCH (t:ThreatActor)
    """
    if threat_actor and isinstance(threat_actor, str):
        candidate_threat_actor = get_exact_candidate(threat_actor, "ThreatActor", "name")
        if not candidate_threat_actor:
            return "The mentioned threat actor was not found"
        filters.append(('t.name = "{candidate_threat_actor}"').format(candidate_threat_actor=candidate_threat_actor))

    if filters:
        threat_actor_base_query += " WHERE "
        threat_actor_base_query += " AND ".join(filters)
    threat_actor_base_query += """
    RETURN t.name AS threat_actor, t.description AS description
    """
    print(f"Using parameters: {params}")
    data = graph.query(threat_actor_base_query, params=params)
    return data

@tool
def get_cna_link(
    link: Annotated[str, "CNA link mentioned in the question. Return None if no mentioned."]
):
    """Useful for when you need to find a specific CNA having the link."""
    params = {}
    filters = []
    cna_link_base_query = """
    MATCH (n:CNA)
    """
    if link and isinstance(link, str):
        candidate_cna = get_exact_candidate(link, "CNA", "link")
        if not candidate_cna:
            return "The mentioned CNA was not found"
        filters.append(('n.link = "{candidate_cna}"').format(candidate_cna=candidate_cna))

    if filters:
        cna_link_base_query += " WHERE "
        cna_link_base_query += " AND ".join(filters)
    cna_link_base_query += """
    RETURN n.link AS cna
    """
    print(f"Using parameters: {params}")
    data = graph.query(cna_link_base_query, params=params)
    return data


@tool
def get_most_recent_vulnerability(
    product: Annotated[str, "Product mentioned in the question. Return None if no mentioned."]
):
    """Useful for when you need to find the most recent CVEs of a software product."""
    most_recent_cve_query = """
    MATCH (c:CVE)
    RETURN c.id AS cve, c.publishedDate AS published_date, c.lastModifiedDate AS last_modified_date
    ORDER BY c.lastModifiedDate DESC
    LIMIT 5
    """
    params = {}
    filters = []
    most_recent_cve_query = """
    MATCH (p:Product)<-[a:AFFECTS]-(c:CVE)
    """
    if product and isinstance(product, str):
        candidate_products = [el["candidate"] for el in get_candidates(product, "product")]
        if not candidate_products:
            return "The mentioned product was not found"
        filters.append("p.name IN $products")
        params["products"] = candidate_products

    if filters:
        most_recent_cve_query += " WHERE "
        most_recent_cve_query += " AND ".join(filters)
    most_recent_cve_query += """
    RETURN p.name AS product, c.id AS vulnerability, c.publishedDate AS published_date, c.lastModifiedDate AS last_modified_date
    ORDER BY publishedDate DESC
    """
    print(f"Using parameters: {params}")
    data = graph.query( most_recent_cve_query, params=params)
    return data

graph_schema_txt=graph.get_schema

def parse_graph_schema(schema_text: str):
    """
    Parse graph schema text to extract node labels and relationships
    
    Args:
        schema_text (str): Text containing graph schema
    
    Returns:
        dict: A dictionary with node types and their relationships
    """
    graph_schema = {}
    
    # Find relationship lines
    for line in schema_text.split('\n'):
        if '(' in line and '->' in line:
            # Extract source and target node types
            source_node = line.split('(')[1].split(')')[0].strip('(:)')
            target_node = line.split('(')[2].split(')')[0].strip('(:)')
            relationship = line.split('[:')[1].split(']')[0]
            
            source_node = source_node.lower()
            target_node = target_node.lower()
            #relationship = relationship.lower()
            
            # Initialize node entries if not exists
            if source_node not in graph_schema:
                graph_schema[source_node] = set()
            
            if target_node not in graph_schema:
                graph_schema[target_node] = set()
            
            # Add relationship
            #graph_schema[source_node].add((relationship, target_node))
            #graph_schema[target_node].add((relationship, source_node))
            graph_schema[source_node].add(target_node)
            graph_schema[target_node].add(source_node)
    
    return graph_schema

def get_entities_from_schema(graph_schema):
    """
    Extract entity types from graph schema
    
    Args:
        graph_schema (dict): A dictionary with node types and their relationships
    
    Returns:
        list: A list of entity types
    """
    entities = set()
    
    for node in graph_schema.keys():        
        entities.add(node)
    
    return list(entities)

graph_schema = parse_graph_schema(graph_schema_txt)

categories = get_entities_from_schema(graph_schema)

tools = {
    "cve": [get_cve_product, get_cve_cwe, get_cve_description, get_cve_cna, get_cve_information, get_multiple_cve_information],
    "cwe": [get_cwe_description, get_cwe_capec, get_cwe_cve],
    "capec": [get_capec_description, get_capec_mitigation, get_capec_attack_pattern],
    "cna": [get_cna_link],
}

generate_indexes()

if __name__ == "__main__":
    query= ['CVE-2001-0771', 'CVE-2001-1009', 'CVE-2000-0844', 'CVE-2000-0219', 'CVE-1999-0839', 'CVE-1999-0899', 'CVE-1999-0777', 'CVE-1999-0909', 'CVE-1999-1011', 'CVE-1999-0728', 'CVE-1999-0344', 'CVE-1999-0227', 'CVE-1999-0496', 'CVE-1999-1383']
    print(get_multiple_cve_information({'cve':query}))