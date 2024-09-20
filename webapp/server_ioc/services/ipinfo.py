import requests
import json
from dotenv import load_dotenv
import os

load_dotenv()
api_key_ipinfo = os.getenv('IPINFO_API_KEY')

#Utilizzo ipinfo per informazioni base da IP
def get_ip_base(ip) -> str:
    ip_info = f'https://ipinfo.io/{ip}/json?token={api_key_ipinfo}' 
    response = requests.get(ip_info)
    response.raise_for_status()
    formatted_data = format_ip_info(response.json())
    return formatted_data

#Format and get all information needed by AbuseIPDB json
def format_ip_info(data) -> dict:
    ip = if_not_none(data.get('ip'))
    org = if_not_none(data.get('org'))
    city = if_not_none(data.get('city')) 
    country_code = if_not_none(data.get('country'))
    geo = if_not_none(data.get('loc')).split(",")
    longitude = str(geo[0])
    latitude = str(geo[1])
    hostname = str(data.get('hostname'))
    x = str("{\"ip\":\""+ip+"\", \"org\":\""+org+"\", \"city\":\""+city+"\", \"country_code\":\""+country_code+"\", \"latitude\":\""+latitude+"\", \"longitude\":\""+longitude+"\", \"hostname\":\""+hostname+"\"}")
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