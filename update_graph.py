from retrieve_data import CNA, CWE, CAPEC, EPSS
from create_graph import CyberGraph
import requests
import os
import time
import json
import glob
import re
import gzip
from io import BytesIO
from urllib.request import urlopen
from zipfile import ZipFile
from dotenv import load_dotenv
import argparse


class CyberGraphUpdater(CyberGraph):
    def __init__(self, uri, user, password):
        super().__init__(uri, user, password)

    @staticmethod
    def _update_recent_cve(tx, elements):
    # Dynamically construct the Cypher query
    # Note: This assumes required nodes (CNA, CWE, Product etc.) already exist or can be created/merged

        query = """
        OPTIONAL MATCH (cve1:CVE { id: toString($id) })
        CALL (cve1){
            OPTIONAL MATCH (cve1)<-[r:ASSIGNED]-(:CNA)
            OPTIONAL MATCH (cve1)-[rw:HAS_WEAKNESS]->(:CWE)
            OPTIONAL MATCH (cve1)-[rm:HAS_METRIC]->(old_metric:Metric)
            OPTIONAL MATCH (cve1)-[rl:HAS_LINK_TO]->(old_ref:Reference)
            OPTIONAL MATCH (cve1)-[ra:AFFECTS]->(:Product)
            DETACH DELETE r, rw, rm, rl, ra, old_metric, old_ref
        }

        MERGE (cve:CVE { id:toString($id) })
        SET cve +={description:$description, publishedDate:$publishedDate, lastModifiedDate:$lastModifiedDate}

        WITH cve
        OPTIONAL MATCH (cna:CNA)-[:REACHABLE_BY_EMAIL]->(:ContactInfo { contact: $cnaEmail })
        FOREACH (c IN CASE WHEN cna IS NOT NULL THEN [cna] ELSE [] END |
            CREATE (cve)<-[:ASSIGNED]-(c)
        )
        
        WITH DISTINCT cve
        UNWIND CASE WHEN size($cweIds) > 0 THEN $cweIds ELSE [null] END AS cweId
        OPTIONAL MATCH (cwe:CWE { id: cweId })
        FOREACH (c IN CASE WHEN cwe IS NOT NULL THEN [cwe] ELSE [] END |
            CREATE (cve)-[:HAS_WEAKNESS]->(c)
        )
        
        WITH DISTINCT cve
        FOREACH (metric in $metrics |
            CREATE (m:Metric {
                vector: metric.vector,
                baseScore: metric.baseScore
            })
            SET m:$(metric.severity)
            CREATE (cve)-[:HAS_METRIC {
                exploitabilityScore: metric.exploitabilityScore,
                impactScore: metric.impactScore
            }]->(m)
        )
        
        WITH DISTINCT cve
        FOREACH (r in $references |
            MERGE (reference:Reference { url: toString(r.url) })
            CREATE (cve)-[:HAS_LINK_TO]->(reference)
        )
        
        WITH DISTINCT cve
        FOREACH (v in $vendors_products |
            MERGE (vendor:Vendor { name: toString(v.vendorName) })
            MERGE (product:Product { name: toString(v.productName) })
            ON CREATE SET product.type = v.productType
            MERGE (vendor)-[:OWN]->(product)
            CREATE (cve)-[:AFFECTS {
            vulnerable: v.vulnerable,
            cpe23Uri: v.cpe23Uri,
            versionEndExcluding: v.versionEndExcluding,
            versionStartIncluding: v.versionStartIncluding
            }]->(product)
        )
        
        """

        tx.run(query,
               id=elements["id"],
               description=elements["description"],
               publishedDate=elements["publishedDate"],
               lastModifiedDate=elements["lastModifiedDate"],
               cnaEmail=elements["cnaEmail"],
               cweIds=elements.get("cweIds", []),
               metrics=elements.get("metrics", []),
               references=elements.get("references", []),
               vendors_products=elements.get("vendors_products", []),
               versions=elements.get("versions", []))

    
    def write_cve_updates(self, elements):
        with self.driver.session(database=self.db) as session:
            session.execute_write(self._update_recent_cve, elements)
        
        
    def create_cve_dump(self, filename="cve_updated"):

        print("Starting retrieving CVEs data...")
        with urlopen("https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.zip") as zip_response:
            with ZipFile(BytesIO(zip_response.read())) as zfile:
                zfile.extractall("./")
                original_filename = zfile.namelist()
                os.rename("{}".format(original_filename[0]),"{}.json".format(filename))

        print("All CVEs has been downloaded and successfully saved into the \'{}.json\' file.".format(filename))
        return "{}.json".format(filename)
    
    def update_cves(self, filename="cve_updated"):
        #source_filename=self.create_cve_dump(filename)
        
        source_filename="dump2023.json"
        
        with open(source_filename, mode="r", encoding='utf-8') as file:
            # Create indexes first
            self.create_cve_index()
            self.create_product_index()
            self.create_reference_index()
            
            data = json.load(file)
            cve_count = len(data["vulnerabilities"])
            
            for idx, cve in enumerate(data["vulnerabilities"], 1):
                self.printProgressBar(idx, cve_count, "CVE")
                
                cve_data = self.process_single_cve(cve)
                
                self.write_cve_updates(cve_data)
                
            
    
    def download_upated_data(self):
        print("Downloading updated data...")
        cna_data = CNA().create_cna_dump("cna_updated")
        cwe_data = CWE().create_cwes_dump("cwe_updated")
        capec_data = CAPEC().create_capec_dump("capec_updated")
        epss_data = EPSS().create_epss_dump("epss_updated")
        self.create_cve_dump("cve_updated")

        print("Graph update complete.")

if __name__ == "__main__":
    load_dotenv()

    parser = argparse.ArgumentParser(description="Update Cyber Graph Database with latest data.")
    parser.add_argument('--weekly', action='store_true', help='Update the graph also with weekly data updates.')
    
    neo4j_uri = os.getenv('NEO4J_URI')
    neo4j_username = os.getenv('NEO4J_USERNAME')
    neo4j_password = os.getenv('NEO4J_PASSWORD')
    
    updater = CyberGraphUpdater(neo4j_uri, neo4j_username, neo4j_password)
    
    updater.update_cves("cve_updated")
    
    