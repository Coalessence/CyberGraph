import neo4j
from neo4j import GraphDatabase
from classes.domain import DOMAIN
from classes.ip import IP
import time

class IoCGraph:

    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()
        
    # ==============================================
    # =============== HANDLE IP ===================
    # ==============================================

    @staticmethod
    def _create_IP(tx, elements):
        tx.run("MERGE (x:IP { ip:$ip_address, is_public:$availability, version:$version})", 
            ip_address=elements["ip"],
            availability=elements["is_public"],
            version=elements["ip_version"])
        
    @staticmethod
    def _create_abuseipdb_reputation(tx, elements):
        tx.run("""
            MATCH (x:IP { ip:$ip_address })
            MERGE (y:IP_AbuseIPDB_Reputation { score:$score, last_reported:$last_reported, number_of_reports:$number_of_reports })
            MERGE (x)-[:HAS_ABUSEIPDB_REPUTATION]->(y)
            """,
            score=elements["score"], 
            last_reported=elements["last_reported"],
            number_of_reports=elements["number_of_reports"],
            ip_address=elements["ip"])
    
    @staticmethod
    def _create_location(tx, elements):
        tx.run("""
            MATCH (x:IP { ip:$ip_address })
            MERGE (y:IP_location { country_code:$country_code, country_name:$country_name, country_city:$country_city, longitude:$longitude, latitude:$latitude })
            MERGE (x)-[:HAS_LOCATION]->(y)
            """,
            country_code=elements["country_code"], 
            country_name=elements["country_name"],
            country_city=elements["country_city"],
            longitude=elements["longitude"],
            latitude=elements["latitude"],
            ip_address=elements["ip"])
    
    @staticmethod
    def _create_organization(tx, elements):
        tx.run("""
            MATCH (x:IP { ip:$ip_address })
            MERGE (y:IP_Organization { organization:$organization, usage_type:$usage_type })
            MERGE (x)-[:HAS_ORGANIZATION]->(y)
            """,
            organization=elements["organization"], 
            usage_type=elements["usage_type"],
            ip_address=elements["ip"])
        
    @staticmethod
    def _create_ISP(tx, elements):
        tx.run("""
            MATCH (x:IP { ip:$ip_address })
            MERGE (y:IP_ISP { isp:$isp})
            MERGE (x)-[:HAS_ISP]->(y)
            """,
            isp=elements["isp"],
            ip_address=elements["ip"])
    
    @staticmethod
    def _create_ASN(tx, elements):
        tx.run("""
            MATCH (x:IP { ip:$ip_address })
            MERGE (y:IP_ASN { asn:$asn})
            MERGE (x)-[:HAS_ASN]->(y)
            """,
            asn=elements["asn"],
            ip_address=elements["ip"])

    @staticmethod
    def _create_DOMAINS(tx, elements):
        tx.run("""
            MATCH (x:IP { ip:$ip_address })
            MATCH (y:DOMAIN { domain:$domain})
            MERGE (x)-[:HAS_DOMAIN]->(y)
            """,
            domain=elements["domains"],
            ip_address=elements["ip"])
           
    def get_ip(self, value):
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (ip_address:IP)
                WHERE ip_address.ip=$address
                OPTIONAL MATCH (ip_address)-[:HAS_ABUSEIPDB_REPUTATION]->(reputation:IP_AbuseIPDB_Reputation)
                OPTIONAL MATCH (ip_address)-[:HAS_LOCATION]->(location:IP_location)
                OPTIONAL MATCH (ip_address)-[:HAS_ORGANIZATION]->(org:IP_Organization)
                OPTIONAL MATCH (ip_address)-[:HAS_ISP]->(ispp:IP_ISP)
                OPTIONAL MATCH (ip_address)-[:HAS_ASN]->(asnn:IP_ASN)
                OPTIONAL MATCH (ip_address)-[:HAS_DOMAIN]->(domainn:DOMAIN)
                RETURN ip_address.ip AS ip, ip_address.is_public AS is_public, ip_address.version AS ip_version, reputation.last_reported AS last_reported, reputation.number_of_reports AS number_of_reports, reputation.score AS score, location.country_city AS country_city, location.country_code AS country_code, location.country_name AS country_name, location.latitude AS latitude, location.longitude AS longitude, org.organization AS organization, org.usage_type AS usage_type, ispp.isp AS ISP, asnn.asn AS ASN, collect(distinct(domainn.domain)) AS domains
                """,
                address=value
            )
            record = result.single()
            if record != None and record.get('ip') != None:
                return {
                    'ip':record.get('ip'),
                    'is_public':record.get('is_public'),
                    'ip_version':record.get('ip_version'),
                    'last_reported':record.get('last_reported'),
                    'number_of_reports':record.get('number_of_reports'),
                    'score':record.get('score'),
                    'country_city':record.get('country_city'),
                    'country_code':record.get('country_code'),
                    'country_name':record.get('country_name'),
                    'latitude':record.get('latitude'),
                    'longitude':record.get('longitude'),
                    'organization':record.get('organization'),
                    'usage_type':record.get('usage_type'),
                    'ISP':record.get('ISP'),
                    'ASN':record.get('ASN'),
                    'domains':record.get('domains')
                }
            return None

    def write_ip(self, elements):
        with self.driver.session() as session:
            res = session.execute_write(self._create_IP, elements)

    def write_abuseipdb_reputation(self, elements):
        with self.driver.session() as session:
            res = session.execute_write(self._create_abuseipdb_reputation, elements)

    def write_location(self, elements):
        with self.driver.session() as session:
            res = session.execute_write(self._create_location, elements)

    def write_organization(self, elements):
        with self.driver.session() as session:
            res = session.execute_write(self._create_organization, elements)

    def write_isp(self, elements):
        with self.driver.session() as session:
            res = session.execute_write(self._create_ISP, elements)

    def write_asn(self, elements):
        with self.driver.session() as session:
            res = session.execute_write(self._create_ASN, elements)

    def write_domains(self, elements):
        with self.driver.session() as session:
            res = session.execute_write(self._create_DOMAINS, elements)

    def handle_ip(self, json, flag):
       self.write_ip({
            "ip":json.get('ip'),
            "is_public":json.get("is_public"),
            "ip_version":json.get("ip_version")
        })
       if json.get('is_public') == "True":
            self.write_location({
                "country_code":json.get("country_code"), 
                "country_name":json.get("country_name"),
                "country_city":json.get("country_city"),
                "longitude":json.get("longitude"),
                "latitude":json.get("latitude"),
                "ip":json.get('ip')
            })
            self.write_abuseipdb_reputation({
                "score":json.get("score"), 
                "last_reported":json.get("last_reported"),
                "number_of_reports":json.get("number_of_reports"),
                "ip":json.get('ip')
            })
            self.write_organization({
                "organization":json.get('organization'), 
                "usage_type":json.get('usage_type'),
                "ip":json.get('ip')
            })
            self.write_isp({
                "isp":json.get('ISP'),
                "ip":json.get('ip')
            })
            self.write_asn({
                "asn":json.get('ASN'),
                "ip":json.get('ip')
            })
            for item in json.get('domains'):
                domain_analyzed = DOMAIN(item, json.get('ip'))
                if flag == False:
                    self.handle_domain(domain_analyzed.__dict__, True)
                self.write_domains({
                    "domains":item,
                    "ip":json.get('ip')
            })


    # ==============================================
    # =============== HANDLE DOMAIN ===================
    # ==============================================

    
    @staticmethod
    def _create_DOMAIN_(tx, elements):
        tx.run("MERGE (x:DOMAIN { domain:$domain, organization:$organization})", 
            domain=elements["domain"],
            organization=elements["organization"])
    
    def get_domain(self, value):
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (domain_info:DOMAIN)
                WHERE domain_info.domain=$address
                MATCH (domain_info)-[:HAS_IP]->(ip_address:IP)
                OPTIONAL MATCH (domain_info)-[:HAS_DNS_RECORD]->(dns_rec:DNS_RECORD)
                MATCH (domain_info)-[:HAS_REPUTATION]->(score_rep:DOMAIN_REPUTATION)
                OPTIONAL MATCH (domain_info)-[:HAS_HOSTNAME]->(hostnames:HOSTNAME)
                OPTIONAL MATCH (domain_info)-[:HAS_VULN]->(cves:CVE)
                OPTIONAL MATCH (domain_info)-[:HAS_OPEN_PORT]->(ports:PORTS)
                OPTIONAL MATCH (domain_info)-[:HAS_PRODUCT]->(prod:PRODUCTS)
                OPTIONAL MATCH (domain_info)-[:HAS_SUBDOMAIN]->(dom:SUBDOMAIN) 
                RETURN distinct(domain_info.domain) AS domain, domain_info.organization AS organization, ip_address.ip AS ipv4, collect(distinct({ key: dns_rec.key, value: dns_rec.value })) AS dns_rec, score_rep.score AS reputation, collect(distinct(hostnames.hostname)) AS hostnames, collect(distinct({id : cves.id, description: cves.description, url : 'https://nvd.nist.gov/vuln/detail/'+cves.id })) AS vulnerabilities, collect(distinct(ports.port)) AS ports, collect(distinct(prod.name)) AS products, collect(distinct(dom.domain)) AS subdomains
                """,
                address=value
            )
            record = result.single()
            if record != None and record.get('domain') != None:
                if record.get('vulnerabilities')[0].get('id') != None:
                    return {
                        'domain':record.get('domain'),
                        'ipv4':record.get('ipv4'),
                        'reputation':record.get('reputation'),
                        'dns_records_other_format':record.get('dns_rec'),
                        'vulnerabilities_other_format':record.get('vulnerabilities'),
                        'organization':record.get('organization'),
                        'hostnames':record.get('hostnames'),
                        'ports':record.get('ports'),
                        'products':record.get('products'),
                        'subdomains':record.get('subdomains')
                    }
                else:
                    return {
                        'domain':record.get('domain'),
                        'ipv4':record.get('ipv4'),
                        'reputation':record.get('reputation'),
                        'dns_records_other_format':record.get('dns_rec'),
                        'vulnerabilities_other_format':[],
                        'organization':record.get('organization'),
                        'hostnames':record.get('hostnames'),
                        'ports':record.get('ports'),
                        'products':record.get('products'),
                        'subdomains':record.get('subdomains')
                    }
            return None 
        
    @staticmethod
    def _create_IP_DOMAIN(tx, elements):
        tx.run("""
            MATCH (x:DOMAIN { domain:$domain })
            MATCH (y:IP { ip:$ipp})
            MERGE (x)-[:HAS_IP]->(y)
            """,
            ipp = elements.get("ip"),
            domain=elements.get("domain"))
            
    @staticmethod
    def _create_DNS_RECORD(tx, elements):
        for item in elements.get('dns_records'):
            keys = item.keys()
            for item2 in keys:
                for item3 in item.get(item2):
                    tx.run("""
                        MATCH (x:DOMAIN { domain:$domain })
                        MERGE (y:DNS_RECORD { key:$key, value:$value})
                        MERGE (x)-[:HAS_DNS_RECORD]->(y)
                        """,
                        key = item2,
                        value = item3,
                        domain=elements["domain"])
              
    @staticmethod
    def _create_domain_reputation(tx, elements):
        tx.run("""
            MATCH (x:DOMAIN { domain:$domain })
            MERGE (y:DOMAIN_REPUTATION { score:$score})
            MERGE (x)-[:HAS_REPUTATION]->(y)
            """,
            score=elements["reputation"], 
            domain=elements["domain"])
    
    @staticmethod
    def _create_hostnames(tx, elements):
        for item in elements.get('hostnames'):
            tx.run("""
                MATCH (x:DOMAIN { domain:$domain })
                MERGE (y:HOSTNAME { hostname:$hostname})
                MERGE (x)-[:HAS_HOSTNAME]->(y)
                """,
                domain=elements["domain"],
                hostname=item)
    
    @staticmethod
    def _create_vulnerabilities(tx, elements):
        for item in elements.get('vulnerabilities'):
            res = tx.run("""
                OPTIONAL MATCH (n:CVE)
                WHERE n.id=$id
                RETURN count(n) as occurences
                """,
                id=item)
            record = res.single()
            if record.get('occurences') == 1:
                tx.run("""
                    MATCH (x:DOMAIN { domain:$domain })
                    MERGE (y:CVE { id:$id})
                    MERGE (x)-[:HAS_VULN]->(y)
                    """
                    ,
                    domain=elements["domain"],
                    id=item)
            elif record.get('occurences') == 0:
                tx.run("""
                    MATCH (x:DOMAIN { domain:$domain })
                    CREATE (y:CVE { id:$id, description:"N/A", lastModifiedDate:"N/A", publishedDate:"N/A"})
                    MERGE (x)-[:HAS_VULN]->(y)
                    """
                    ,
                    domain=elements["domain"],
                    id=item)
            else:
                pass

        
    @staticmethod
    def _create_ports(tx, elements):
        for item in elements.get('ports'):
            tx.run("""
                MATCH (x:DOMAIN { domain:$domain })
                MERGE (y:PORTS { port:$port})
                MERGE (x)-[:HAS_OPEN_PORT]->(y)
                """,
                domain=elements["domain"],
                port=item)
    
    @staticmethod
    def _create_products(tx, elements):
        for item in elements.get('products'):
            tx.run("""
                MATCH (x:DOMAIN { domain:$domain })
                MERGE (y:PRODUCTS { name:$product})
                MERGE (x)-[:HAS_PRODUCT]->(y)
                """,
                domain=elements["domain"],
                product=item)

    @staticmethod
    def _create_subdomains(tx, elements):
        for item in elements.get('subdomains'):
            if len(item) > 0:
                for item2 in item.get('subdomains'):
                    tx.run("""
                        MATCH (x:DOMAIN { domain:$domain })
                        MERGE (y:SUBDOMAIN { domain:$subdomain})
                        MERGE (x)-[:HAS_SUBDOMAIN]->(y)
                        """,
                        domain=elements["domain"],
                        subdomain=item2)
           
    def write_domain_(self, elements):
        with self.driver.session() as session:
            res = session.execute_write(self._create_DOMAIN_, elements)

    def write_ip_domain(self, elements):
        with self.driver.session() as session:
            res = session.execute_write(self._create_IP_DOMAIN, elements)

    def write_domain_reputation(self, elements):
        with self.driver.session() as session:
            res = session.execute_write(self._create_domain_reputation, elements)

    def write_hostnames(self, elements):
        with self.driver.session() as session:
            res = session.execute_write(self._create_hostnames, elements)

    def write_vulnerabilities(self, elements):
        with self.driver.session() as session:
            res = session.execute_write(self._create_vulnerabilities, elements)

    def write_ports(self, elements):
        with self.driver.session() as session:
            res = session.execute_write(self._create_ports, elements)

    def write_products(self, elements):
        with self.driver.session() as session:
            res = session.execute_write(self._create_products, elements)

    def write_subdomains(self, elements):
        with self.driver.session() as session:
            res = session.execute_write(self._create_subdomains, elements)

    def write_dns_records(self, elements):
        with self.driver.session() as session:
            res = session.execute_write(self._create_DNS_RECORD, elements)

    def handle_domain(self, json, flag):
        self.write_domain_({
            "domain":json.get('domain'),
            "organization":json.get("organization"),
            "last_update":json.get("last_update")
        })
        if json.get('ipv4') != None:
            ip_analyzed = IP(json.get('ipv4'))
            if flag == False:
                self.handle_ip(ip_analyzed.__dict__, True) 
            self.write_ip_domain({
                "domain":json.get('domain'),
                "ip":json.get('ipv4')
            })
        if json.get('ipv6') != None:
            ip_analyzed = IP(json.get('ipv6'))
            if flag == False:
                self.handle_ip(ip_analyzed.__dict__, True) 
            self.write_ip_domain({
                "domain":json.get('domain'),
                "ip":json.get('ipv6')
            })
        self.write_domain_reputation({
            "reputation":json.get("reputation"), 
            "domain":json.get('domain'),
        })
        self.write_hostnames({
            "hostnames":json.get('hostnames'), 
            "domain":json.get('domain'),
        })
        self.write_vulnerabilities({
            "vulnerabilities":json.get('vulnerabilities'),
            "domain":json.get('domain'),
        })
        self.write_ports({
            "ports":json.get('ports'),
            "domain":json.get('domain'),
        })
        self.write_products({
            "products":json.get('products'),
            "domain":json.get('domain'),
        })
        self.write_subdomains({
            "subdomains":json.get('subdomains'),
            "domain":json.get('domain'),
        })
        self.write_dns_records({
            "dns_records":json.get('dns_records'),
            "domain":json.get('domain'),
        })
        


    # ==============================================
    # =============== HANDLE HASH ===================
    # ==============================================

    
    @staticmethod
    def _create_HASH(tx, elements):
        tx.run("MERGE (x:HASH { hash:$hash, link:$link, first_submission:$first_submission })", 
            hash=elements["hash"],
            link=elements["link"],
            first_submission=elements["first_submission"])
    
    def get_hash(self, value):
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (hash_info:HASH)
                WHERE hash_info.hash=$address
                MATCH (hash_info)-[:HAS_TYPE]->(hash_type:HASH_TYPE)
                OPTIONAL MATCH (hash_info)-[:HAS_FILE_NAME]->(hash_file:HASH_FILE_NAME)
                OPTIONAL MATCH (hash_info)-[:HAS_THREAT]->(hash_threat:HASH_THREAT)
                OPTIONAL MATCH (hash_info)-[:HAS_VULN]->(hash_tags:CVE)
                MATCH (hash_info)-[:HAS_EXTENSION]->(hash_ext:HASH_EXTENSION)
                MATCH (hash_info)-[:HAS_MAGIC]->(hash_mag:HASH_MAGIC)
                MATCH (hash_info)-[:HAS_HASH_SCORE]->(hash_sco:HASH_SCORE)
                OPTIONAL MATCH (ta:THREAT_ACTOR)<-[:IS_USED_BY]-(tec:AdversaryTechnique)<-[:HAS_MITRE_TECHNIQUE]-(tact:TACTIC)<-[:USES_TACTIC]-(hash_info)-[:USES_TECHNIQUE]->(tec)
                WITH hash_info,hash_type,hash_ext,hash_file,hash_tags, hash_threat,hash_mag,hash_sco, tact, tec,ta,{id:ta.name, link:ta.link} AS tas
                WITH hash_info,hash_type,hash_ext,hash_file,hash_tags, hash_threat,hash_mag,hash_sco,tact,tec,{id:tec.id, name: tec.name, link:tec.link, actors:COLLECT(tas)} AS tect
                WITH hash_info,hash_type,hash_ext,hash_file,hash_tags, hash_threat,hash_mag,hash_sco,tact,{id:tact.id,name:tact.name,link:tact.link,techniques:COLLECT(tect)} AS tacts
                RETURN hash_info.hash as hash, collect(distinct({id : hash_tags.id, description: hash_tags.description, url : 'https://nvd.nist.gov/vuln/detail/'+hash_tags.id })) AS tags, hash_info.link AS link, hash_info.first_submission AS first_submission, hash_type.type AS type, hash_type.type_description AS type_description, hash_ext.extension AS extension, COLLECT(DISTINCT(hash_file.name)) AS files, hash_threat.name AS threats, hash_mag.magic AS magic, hash_sco.score AS score, COLLECT(DISTINCT(tacts)) AS tactics
                """,
                address=value
            )
            record = result.single()
            if record != None and record.get('hash') != None:
                if record.get('tags')[0].get('id') != None:
                    record_new = {
                        'hash':record.get('hash'),
                        'link':record.get('link'),
                        'type':record.get('type'),
                        'first_submission':record.get('first_submission'),
                        'type_description':record.get('type_description'),
                        'extension':record.get('extension'),
                        'magic':record.get('magic'),
                        'score':record.get('score'),
                        'file':record.get('files'),
                        'threat':record.get('threats'),
                        'tactics':record.get('tactics'),
                        'tags':record.get('tags')
                    }
                else:
                    record_new = {
                        'hash':record.get('hash'),
                        'link':record.get('link'),
                        'type':record.get('type'),
                        'first_submission':record.get('first_submission'),
                        'type_description':record.get('type_description'),
                        'extension':record.get('extension'),
                        'magic':record.get('magic'),
                        'score':record.get('score'),
                        'file':record.get('files'),
                        'threat':record.get('threats'),
                        'tactics':record.get('tactics'),
                        'tags':[]
                    }
                return record_new
            return None 
        
    @staticmethod
    def _create_type(tx, elements):
        tx.run("""
                MATCH (x:HASH { hash:$hash })
                MERGE (y:HASH_TYPE { type:$type, type_description:$type_description})
                MERGE (x)-[:HAS_TYPE]->(y)
                """,
                type = elements["type"],
                type_description = elements["type_description"],
                hash=elements["hash"])

    @staticmethod
    def _create_file_name(tx, elements):
        tx.run("""
                MATCH (x:HASH { hash:$hash })
                MERGE (y:HASH_FILE_NAME { name:$name})
                MERGE (x)-[:HAS_FILE_NAME]->(y)
                """,
                name = elements["name"],
                hash=elements["hash"])

    @staticmethod
    def _create_tags(tx, elements):
        res = tx.run("""
            OPTIONAL MATCH (n:CVE)
            WHERE n.id=$id
            RETURN count(n) as occurences
            """,
            id= elements["value"])
        record = res.single()
        if record.get('occurences') == 1:
            tx.run("""
                MATCH (x:HASH { hash:$hash })
                MERGE (y:CVE { id:$id})
                MERGE (x)-[:HAS_VULN]->(y)
                """,
                id = elements["value"],
                hash=elements["hash"])
        elif record.get('occurences') == 0:
            tx.run("""
                MATCH (x:HASH { hash:$hash })
                CREATE (y:CVE { id:$id, description:"N/A", lastModifiedDate:"N/A", publishedDate:"N/A"})
                MERGE (x)-[:HAS_VULN]->(y)
                """
                ,
                id = elements["value"],
                hash=elements["hash"])
        else:
            pass
        
    @staticmethod
    def _create_threat(tx, elements):
        tx.run("""
                MATCH (x:HASH { hash:$hash })
                MERGE (y:HASH_THREAT { name:$name})
                MERGE (x)-[:HAS_THREAT]->(y)
                """,
                name = elements["name"],
                hash=elements["hash"])
         
    @staticmethod
    def _create_extension(tx, elements):
        tx.run("""
                MATCH (x:HASH { hash:$hash })
                MERGE (y:HASH_EXTENSION { extension:$extension})
                MERGE (x)-[:HAS_EXTENSION]->(y)
                """,
                extension = elements["extension"],
                hash=elements["hash"])

    @staticmethod
    def _create_magic(tx, elements):
        tx.run("""
                MATCH (x:HASH { hash:$hash })
                MERGE (y:HASH_MAGIC { magic:$magic})
                MERGE (x)-[:HAS_MAGIC]->(y)
                """,
                magic = elements["magic"],
                hash=elements["hash"])
        
    @staticmethod
    def _create_score(tx, elements):
        tx.run("""
                MATCH (x:HASH { hash:$hash })
                MERGE (y:HASH_SCORE { score:$score})
                MERGE (x)-[:HAS_HASH_SCORE]->(y)
                """,
                score = elements["score"],
                hash=elements["hash"])

    @staticmethod
    def _create_tactic(tx, elements):
        tx.run("""
            MATCH (sha:HASH { hash:$hash })
            MERGE (tactic:TACTIC { id:$id, name:$name, description:$description, link:$link })
            MERGE (sha)-[:USES_TACTIC]->(tactic)
            """,
            hash=elements['hash'],
            id=elements["external_id"],
            name=elements["name"],
            description=elements["description"],
            link=elements["link"])

    @staticmethod
    def _create_technique(tx, elements):
        tx.run("""
            MATCH (tactic:TACTIC { id:$tacId })
            MATCH (sha:HASH { hash:$hash })
            MERGE (tec:AdversaryTechnique { id:$id, name:$name, description:$description, link:$link})
            MERGE (tactic)-[:HAS_MITRE_TECHNIQUE]->(tec)
            MERGE (sha)-[:USES_TECHNIQUE]->(tec)
            """,
            hash=elements['hash'], 
            tacId=elements["tac_external_id"],
            id=elements["external_id"],
            name=elements["name"],
            description=elements["description"],
            link=elements["link"])
              
    def write_hash(self, elements):
        with self.driver.session() as session:
            res = session.execute_write(self._create_HASH, elements)

    def write_type(self, elements):
        with self.driver.session() as session:
            res = session.execute_write(self._create_type, elements)

    def write_file_name(self, elements):
        with self.driver.session() as session:
            res = session.execute_write(self._create_file_name, elements)

    def write_hash_tags(self, elements):
        with self.driver.session() as session:
            res = session.execute_write(self._create_tags, elements)

    def write_threat(self, elements):
        with self.driver.session() as session:
            res = session.execute_write(self._create_threat, elements)

    def write_extension(self, elements):
        with self.driver.session() as session:
            res = session.execute_write(self._create_extension, elements)

    def write_magic(self, elements):
        with self.driver.session() as session:
            res = session.execute_write(self._create_magic, elements)

    def write_score(self, elements):
        with self.driver.session() as session:
            res = session.execute_write(self._create_score, elements)
    
    def write_tactic(self, elements):
        with self.driver.session() as session:
            res = session.execute_write(self._create_tactic, elements)

    def write_technique_(self, elements):
        with self.driver.session() as session:
            res = session.execute_write(self._create_technique, elements)
    
    def handle_hash(self, json):
        self.write_hash({
            "hash":json.get('hash'),
            "link":json.get("link"),
            "first_submission":json.get("first_submission")
        })
        self.write_type({
            "hash":json.get('hash'),
            "type":json.get("type"),
            "type_description":json.get("type_description")
        })
        self.write_extension({
            "hash":json.get('hash'),
            "extension":json.get("extension")        
        })
        self.write_magic({
            "hash":json.get('hash'),
            "magic":json.get("magic")
        })
        self.write_score({
            "hash":json.get('hash'),
            "score":json.get("score")
        })
        self.write_threat({
            "hash":json.get('hash'),
            "name":json.get("threat_classification")
        })
        for item in json.get('tags'):
            if item.startswith("cve"):
                self.write_hash_tags({
                    "hash":json.get('hash'),
                    'value':item.upper()
                })
        for item in json.get('names'):
            self.write_file_name({
                "hash":json.get('hash'),
                'name':item
            })
        for item in json.get('techniques'):
            self.write_tactic({
                'hash':json.get('hash'),
                'external_id':item.get('tactic_id'),
                'name':item.get('tactic_name'),
                'description':item.get('tactic_description'),
                'link':item.get('tactic_link')
            })
            self.write_technique_({
                'hash':json.get('hash'),
                'tac_external_id':item.get('tactic_id'),
                'external_id':item.get('technique_id'),
                'name':item.get('technique_name'),
                'description':item.get('technique_description'),
                'link':item.get('technique_link')
            })

    
    # ==============================================
    # =============== HANDLE THREAT ACTOR ===================
    # ==============================================         

    def get_threat_actor(self, value):
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (ta:THREAT_ACTOR)
                WHERE toLower(ta.name) CONTAINS toLower($name)
                WITH ta AS ThreatActor
                OPTIONAL MATCH (ThreatActor)-[:HAS_ALIAS]->(alias:THREAT_ACTOR_ALIAS)
                OPTIONAL MATCH (tec:AdversaryTechnique)-[:IS_USED_BY]->(ThreatActor)
                RETURN ThreatActor.name AS name, ThreatActor.link AS link, ThreatActor.description AS description, collect(distinct(alias.name)) AS aliases, collect(distinct({id:tec.id, link:tec.link, name:tec.name})) AS techniques
                """,
                name=value
            )
            record = result.single()
            if record != None and record.get('name') != None:
                return {
                    'name':record.get('name'),
                    'link': record.get('link'),
                    'description': record.get('description'),
                    'aliases':record.get('aliases'),
                    'technique':record.get('techniques')
                }
            else:
                result = session.run(
                    """
                    MATCH (alias:THREAT_ACTOR_ALIAS)
                    WHERE toLower(alias.name) CONTAINS toLower($name)
                    MATCH (ta:THREAT_ACTOR)-[:HAS_ALIAS]->(alias)
                    OPTIONAL MATCH (tec:AdversaryTechnique)-[:IS_USED_BY]->(ta)
                    MATCH (ta)-[:HAS_ALIAS]->(alias_2:THREAT_ACTOR_ALIAS)
                    RETURN ta.name AS name, ta.link AS link, ta.description AS description, collect(distinct(alias_2.name)) AS aliases, collect(distinct({id:tec.id, link:tec.link, name:tec.name})) AS techniques
                    """,
                    name=value
                )
                record = result.single()
                if record != None and record.get('name') != None:
                    return {
                        'name':record.get('name'),
                        'link': record.get('link'),
                        'description': record.get('description'),
                        'aliases':record.get('aliases'),
                        'technique':record.get('techniques')
                    }
            return None 