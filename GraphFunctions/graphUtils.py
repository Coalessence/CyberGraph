from neo4j import GraphDatabase
import json

def getGraphConnection(uri: str, user: str, password: str) -> GraphDatabase:
    """
    Establish a connection to the Neo4j graph database.
    
    :param uri: URI of the Neo4j database
    :param user: Username for authentication
    :param password: Password for authentication
    :return: GraphDatabase connection object
    """
    return GraphDatabase.driver(uri, auth=(user, password))


def create_graph_schema(conn: GraphDatabase, database: str) -> str:

    res=conn.execute_query("""With {sample: -1} as config
    CALL apoc.meta.schema(config)
    YIELD value
    UNWIND keys(value) AS key
    RETURN key, value[key] AS value;""", database=database)

    
    nodes= {}
    relationships = []
    
    for el in res[0]:
        match(el.get("value").get("type")):
            case "node":
                node={"properties": [], "relationships": {}}
                for name, _ in el.get("value").get("properties").items():
                    node["properties"].append(name)
                    
                for key, value in el.get("value").get("relationships").items():
                    relProp=[]
                    labels = set(value.get("labels"))
                    for propName, _ in value.get("properties").items():
                        relProp.append(propName)
                    rel={"connecting" : labels, "direction": value.get("direction"), "properties": relProp}
                    for destination in labels:
                        if value.get("direction") == "out":
                            relationships.append((el.get("key"), key , destination))
                    node["relationships"][key] = rel
                        
                nodes[el.get("key")] = node
            case _:
                print("Unknown type")
    
    schema=""
    schema+="Nodes: \n{"
    for key, value in nodes.items():
        schema+=f"{key}: {value},\n"
    schema+="} \nRelationships: \n{"
    for source, relationship, target in relationships:
        schema+=f"{source} -[{relationship}]-> {target}\n"
    schema+="}"
    
    return schema, nodes, relationships
    
print("Graph functions loaded")

if __name__ == "__main__":
    s,n, r = create_graph_schema(getGraphConnection("bolt://localhost:7687", "neo4j", "password"), "neo4j")
    print(s)
    #print only s to a json file, s is a string
    with open("graph_schema.txt", "w") as f:
        f.write(s)    