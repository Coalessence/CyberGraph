import requests
from dotenv import load_dotenv
import os

load_dotenv()
api_security_trails = os.getenv('SECTRAILS_API_KEY')

#Utilizzo SecurityTrails per record DNS e subdomains fornito un dominio (subdomainds gratuiti fino a 2000, oltre sono a pagamento)
def get_subdomains(domain):
    domain_securitytrails = f'https://api.securitytrails.com/v1/domain/{domain}/subdomains?children_only=false&include_inactive=false' 
    header = {'APIKEY' : api_security_trails}
    response = requests.get(domain_securitytrails, headers=header)
    if response.status_code > 399:
        return None
    formatted_data = format_subdomain_securitytrails(response.json())
    return formatted_data 

def format_subdomain_securitytrails(data):
    formatted = []
    subdomains = data.get('subdomains')
    count = data.get('subdomain_count')
    formatted.append({'subdomains' : subdomains, 'count' : count})
    return formatted

def get_dns_records(domain):
    domain_securitytrails = f'https://api.securitytrails.com/v1/domain/{domain}' 
    header = {'APIKEY' : api_security_trails}
    response = requests.get(domain_securitytrails, headers=header)
    if response.status_code > 399:
        return None
    formatted_data = format_dns_securitytrails(domain, response.json())
    return formatted_data 

def format_dns_securitytrails(data):
    formatted = []
    dns_records = data.get('current_dns')
    formatted.append({'dns_records' : dns_records})
    return formatted