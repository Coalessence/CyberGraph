import requests
import json
from dotenv import load_dotenv
import os

load_dotenv()
api_key_abuseipdb = os.getenv('ABUSEIPDB_API_KEY')

#Utilizzo AbuseIPDB per reputation IP
def get_reputation(ip) -> str:
    ip_abuse = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}' 
    header = {'Key' : api_key_abuseipdb}
    response = requests.get(ip_abuse, headers=header)
    if response.status_code > 399:
        return None
    formatted_data = format_ip_abuse(response.json())
    return formatted_data

#Format and get all information needed by AbuseIPDB json
def format_ip_abuse(data) -> dict:
    ip_address = if_not_none(data.get('data').get('ipAddress'))
    is_public = if_not_none(data.get('data').get('isPublic'))
    ip_version = if_not_none(data.get('data').get('ipVersion'))
    total_reports = if_not_none(data.get('data').get('totalReports'))
    abuse_score = if_not_none(data.get('data').get('abuseConfidenceScore'))
    country_code = if_not_none(data.get('data').get('countryCode'))
    country_name = if_not_none(data.get('data').get('countryName'))
    usage_type = if_not_none(data.get('data').get('usageType'))
    isp = if_not_none(data.get('data').get('isp'))
    domain = if_not_none(data.get('data').get('domain'))
    last_reported = if_not_none(data.get('data').get('lastReportedAt'))
    x = str("{\"ip_address\":\""+ip_address+"\", \"is_public\":\""+is_public+"\", \"ip_version\":\""+ip_version+"\", \"total_reports\":\""+total_reports+"\", \"abuse_score\":\""+abuse_score+"\", \"country_code\":\""+country_code+"\", \"country_name\" :\""+country_name+"\", \"usage_type\":\""+usage_type+"\", \"isp\" :\""+isp+"\", \"domain\":\""+domain+"\", \"last_reported\":\""+last_reported+"\"}")
    y = json.loads(x)
    return y

def if_not_none(x):
    if x is not None and type(x) == str:
        return x
    elif type(x) == int or type(x) == float or type(x) == bool:
        return str(x)
    elif type(x) == list:
        return json.dumps(x)
    else:
        return 'N/A'