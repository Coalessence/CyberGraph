def entity_mapping(entity: str):
    """maps the entity to a specific entity class
    Args:
        entity (str): _description_
    """
    entity=entity.lower()
    if entity in "cve":
        return "cve"
    if entity in "cpe":
        return "product"
    if character_distance(entity, "vulnerability", 3):
        return "cve"
    if character_distance(entity, "software", 2):
        return "product"
    if character_distance(entity, "product", 2):
        return "product"
    if character_distance(entity, "vendor", 2):
        return "vendor"
    if character_distance(entity, "capec", 2):
        return "capec"
    if character_distance(entity, "threat actor", 3):
        return "threat actor"
    if character_distance(entity, "threat actor group", 4):
        return "threat actor group"
    if character_distance(entity, "attack pattern", 3):
        return "attack pattern"
    
    
    
    
def character_distance(str1: str, str2: str, max_distance: int):
    """_description_
    Args:
        s1 (str): the string we have
        s2 (str): the possible matching string
        max_dist (int): the maximum distance between the two strings
    """
    # If the length difference is more than max_distance, return False
    if abs(len(str1) - len(str2)) > max_distance:
        return False
    
    # If strings are exactly the same, return True
    if str1 == str2:
        return True
    
    # If strings have same length, count character differences
    if len(str1) == len(str2):
        differences = sum(c1 != c2 for c1, c2 in zip(str1, str2))
        return differences <= max_distance
    
    # If lengths differ, check for insertions, deletions, or substitutions
    # Try all possible modifications
    shorter = str1 if len(str1) < len(str2) else str2
    longer = str2 if len(str1) < len(str2) else str1
    
    for i in range(len(longer)):
        # Try removing a character
        modified = longer[:i] + longer[i+1:]
        if modified == shorter:
            return True
        
        # Try substituting a character
        for j in range(26):  # considering lowercase letters
            char = chr(97 + j)  # a-z
            modified = longer[:i] + char + longer[i+1:]
            if modified == shorter:
                return True
    
    return False

def bfs_shortest_path(graph, start, goal):
    explored = []
    queue = [[start]]
 
    if start == goal:
        return [start]
 
    while queue:

        path = queue.pop(0)

        node = path[-1]
        if node not in explored:
            neighbours = graph[node]

            for neighbour in neighbours:
                new_path = list(path)
                new_path.append(neighbour)
                queue.append(new_path)

                if neighbour == goal:
                    return new_path

            explored.append(node)

    return None

def streamline_path(path):
    """eliminates nodes from the paths that are not data entities

    Args:
        path (List[str]): a path of node
    """
    new_path = []
    for node in path:
        if node in data_entities:
            new_path.append(node)
    return new_path
    
data_entities=[
    "cve",
    "capec",
    "cna",
    "cwe",
]

categories = [
    "Product",
    "Vendor",
    "CVE",
    "CAPEC",
    "CPE",
    "CWE",
    "CNA",
    "Threat Actor",
    "Threat Actor Group",
    "Attack Pattern"
]