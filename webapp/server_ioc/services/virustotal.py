import requests
import re 
from dotenv import load_dotenv
import json
import math
import os
from datetime import datetime
from mitreattack.stix20 import *

load_dotenv()
api_key_virustotal = os.getenv('VIRUSTOTAL_API_KEY')

def get_domain_info(domain):
    domain_virus = f'https://www.virustotal.com/api/v3/domains/{domain}' 
    header = {'x-apikey' : api_key_virustotal}
    response = requests.get(domain_virus, headers=header)
    if response.status_code > 399:
        return None
    formatted_data = format_whois(response.json())
    return formatted_data

def get_dns_update(domain):
    domain_virus = f'https://www.virustotal.com/api/v3/domains/{domain}' 
    header = {'x-apikey' : api_key_virustotal}
    response = requests.get(domain_virus, headers=header)
    response.raise_for_status()
    formatted_data = format_dns(response.json())
    return formatted_data

def format_whois(data):
    formatted = []
    malicious = data.get('data').get('attributes').get('last_analysis_stats').get('malicious')
    suspicious = data.get('data').get('attributes').get('last_analysis_stats').get('suspicious')
    undetected = data.get('data').get('attributes').get('last_analysis_stats').get('undetected')
    harmless = data.get('data').get('attributes').get('last_analysis_stats').get('harmless')
    domain = data.get('data').get('id')
    #creation_old = data.get('data').get('attributes').get('whois')
    registrant = data.get('data').get('attributes').get('registrar')
    #creation = re.search('(\d{4}-\d{2}-\d{2})',creation_old)[0]
    reputation = math.trunc(((int(malicious)+int(suspicious))/(int(malicious)+int(suspicious)+int(undetected)+int(harmless)))*100)
    #formatted.append({'domain' : domain, 'creation' : creation, 'registrant': registrant, 'reputation' : reputation, 'malicious':malicious, 'suspicious':suspicious, 'undetected':undetected, 'harmless':harmless  })
    formatted.append({'domain' : domain, 'registrant': registrant, 'reputation' : reputation, 'malicious':malicious, 'suspicious':suspicious, 'undetected':undetected, 'harmless':harmless  }) 
    return formatted 

def format_dns(data):
    formatted = []
    a = []
    aaaa = []
    txt = []
    ns = []
    soa = []
    mx = []
    caa = []
    for item in data['data']['attributes']['last_dns_records']:
        if item['type'] == 'A':
            a.append(item['value'])
        elif item['type'] == 'AAAA':
            aaaa.append(item['value'])
        elif item['type'] == 'TXT':
            txt.append(item['value'])
        elif item['type'] == 'NS':
            ns.append(item['value'])
        elif item['type'] == 'SOA':
            soa.append(item['value'])
        elif item['type'] == 'MX':
            mx.append(item['value'])
        elif item['type'] == 'CAA':
            caa.append(item['value'])       
    formatted.append({'A' : a, 'AAAA': aaaa, 'TXT' : txt, 'NS':ns, 'SOA':soa, 'MX':mx, 'CAA':caa}) 
    return formatted 

def format_hash_details(info : dict):
    id : str = if_not_none(info.get('data').get('id'))
    type_file : str = if_not_none(info.get('data').get('type'))
    link = if_not_none(info.get('data').get('links').get('self'))
    extension = if_not_none(info.get('data').get('attributes').get('type_extension'))
    first_submission = if_not_none(info.get('data').get('attributes').get('first_submission_date'))
    magic = if_not_none(info.get('data').get('attributes').get('magic'))
    type_description = if_not_none(info.get('data').get('attributes').get('type_description'))
    threat_classification = 'N/A'
    if info.get('data').get('attributes').get('popular_threat_classification') != None:
        threat_classification = if_not_none(info.get('data').get('attributes').get('popular_threat_classification').get('suggested_threat_label'))
    names : list = if_not_none(info.get('data').get('attributes').get('names'))
    tags : list = if_not_none(info.get('data').get('attributes').get('tags'))
    malicious_votes = if_not_none(info.get('data').get('attributes').get('last_analysis_stats').get('malicious'))
    suspicious_votes = if_not_none(info.get('data').get('attributes').get('last_analysis_stats').get('suspicious'))
    harmless_votes = if_not_none(info.get('data').get('attributes').get('last_analysis_stats').get('harmless'))
    undetected_votes = if_not_none(info.get('data').get('attributes').get('last_analysis_stats').get('undetected'))
    x = str("{\"id\":\""+id+"\",\"type\":\""+type_file+"\", \"link\":\""+link+"\", \"first_submission\":"+first_submission+", \"extension\":\""+extension+"\", \"magic\":\""+magic+"\", \"type_description\":\""+type_description+"\", \"threat_classification\":\""+threat_classification+"\", \"names\":"+names+", \"tags\":"+tags+", \"malicious_votes\":"+malicious_votes+",\"suspicious_votes\":"+suspicious_votes+",\"harmless_votes\":"+harmless_votes+", \"undetected_votes\":"+undetected_votes+"}")
    return json.loads(x) 

# 
#Integrare Techniques all'interno di ogni Tactic
def format_hash_mitre(data):
    tactics = []
    sandbox = data.get('data').keys()
    for item1 in sandbox:
        element : list = data.get('data').get(item1).get('tactics')
        for item2 in element:
            id = item2.get('id')
            name = item2.get('name')
            description = item2.get('description')
            url = item2.get('link')
            t : Tactic = Tactic(id, name, description, url)
            if not any(x.id == id for x in tactics):
                for item3 in item2.get('techniques'):
                    if item3 != None:
                        t.add_technique(json.loads(json.dumps(Technique(item3.get('id'), item3.get('name'),item3.get('description'),item3.get('link')).__dict__)))
                tactics.append(t)
    result = []
    for item in tactics:
        result.append(json.loads(json.dumps(item.__dict__)))
    return result 

def virustotal_hash(hash):
    hash_virus_details = f'https://www.virustotal.com/api/v3/files/{hash}'
    hash_virus_mitre = f'https://www.virustotal.com/api/v3/files/{hash}/behaviour_mitre_trees'  
    header = {'x-apikey' : api_key_virustotal}
    response = requests.get(hash_virus_details, headers=header)
    response.raise_for_status()
    formatted_data1 = format_hash_details(response.json())
    response = requests.get(hash_virus_mitre, headers=header)
    response.raise_for_status()
    formatted_data2 = format_hash_mitre(response.json())
    formatted_data1['tactics'] = formatted_data2
    return formatted_data1

def if_not_none(x):
    if x is not None and type(x) == str:
        return x
    elif type(x) == int or type(x) == float or type(x) == bool:
        return str(x)
    elif type(x) == list:
        return json.dumps(x)
    else:
        return 'N/A'


class Tactic:
    def __init__(self, id, name, description, link):
        self.id = id
        self.name = name
        self.description = description
        self.link = link
        self.techniques : list = []
    
    def add_technique(self, data):
        self.techniques.append(data)

class Technique:
    def __init__(self, id, name, description, link):
        self.id = id
        self.name = name
        self.description = description
        self.link = link

#mitre_attack_data = MitreAttackData("enterprise-attack.json")
#groups = mitre_attack_data.get_groups_using_technique()
#print(groups)
#virustotal_hash('246ab25a7240d684c1a6bf5abd6bcd6f13e0d86c97940883bc249e2b7cb23853')
#virustotal_hash('908B64B1971A979C7E3E8CE4621945CBA84854CB98D76367B791A6E22B5F6D53')