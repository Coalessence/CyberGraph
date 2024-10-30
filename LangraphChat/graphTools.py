import os
from typing import Any, Dict, List, Optional, Tuple, Type
from dotenv import load_dotenv
from langchain_community.graphs import Neo4jGraph
from langchain_community.vectorstores.neo4j_vector import remove_lucene_chars
from langchain_core.tools import tool
from langchain_core.pydantic_v1 import Field

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
    product: Optional[str] = Field(
        description="software product mentioned in the question. Return None if no mentioned."
    )
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
    RETURN p.name AS product, c.id AS vulnerability, a.versionStartIncluding as version, count(*) AS count
    ORDER BY count DESC
    """
    print(f"Using parameters: {params}")
    data = graph.query(vulnerabilty_product_base_query, params=params)
    return data
     
@tool
def get_cwe_capec(
    cve: Optional[str] = Field(
        description="CVE ID mentioned in the question. Return None if no mentioned."
    )
):
    """Useful for when you need to find the CWE id and CAPEC id of a CVE. Useful when you need to find the weakness id and attack patter id froma vulnerability id"""
    params = {}
    filters = []
    cwe_capec_base_query = """
    MATCH (c:CVE)-[:HAS_WEAKNESS]->(w:CWE)
    MATCH (w)-[:HAS_RELATED_ATTACK_PATTERN]->(a:CAPEC)
    """
    if cve and isinstance(cve, str):
        candidate_cve = get_exact_candidate(cve, "CVE", "id")
        if not candidate_cve:
            return "The mentioned CVE was not found"
        filters.append(('c.id = "{candidate_cve}"').format(candidate_cve=candidate_cve))

    if filters:
        cwe_capec_base_query += " WHERE "
        cwe_capec_base_query += " AND ".join(filters)
    cwe_capec_base_query += """
    RETURN c.id AS cve, w.id AS cwe, a.id AS capec
    """
    data = graph.query(cwe_capec_base_query, params=params)
    return data

@tool
def get_cve_description(
    cve: Optional[str] = Field(
        description="CVE ID mentioned in the question. Return None if no mentioned."
    )
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
def get_cwe_description(
    cwe: Optional[str] = Field(
        description="CWE ID mentioned in the question. Return None if no mentioned."
    )
):
    """Useful for when you need to find the description of a CWE."""
    params = {}
    filters = []
    cwe_description_base_query = """
    MATCH (c:CWE)
    """
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
    capec: Optional[str] = Field(
        description="CAPEC ID mentioned in the question. Return None if no mentioned."
    )
):
    """Useful for when you need to find the description of a CAPEC, useful to find the attack pattern for a software vulnerability."""
    params = {}
    filters = []
    capec_description_base_query = """
    MATCH (c:CAPEC)
    """
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
    capec: Optional[str] = Field(
        description="CAPEC ID mentioned in the question. Return None if no mentioned."
    )
):
    """Useful for when you need to find the mitigation of a CAPEC, useful to find the mitigation for a software vulnerability."""
    params = {}
    filters = []
    capec_mitigation_base_query = """
    MATCH (c:CAPEC)-[:CAN_BE_MITIGATED_BY]->(m:Mitigation)
    """
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

tools = [get_cve_product, get_cwe_capec, get_cve_description, get_cwe_description, get_capec_description, get_capec_mitigation]
generate_indexes()
