import requests
import json
from dotenv import load_dotenv
import os

load_dotenv()
api_key_shodan = os.getenv('SHODAN_API_KEY')

def get_ip_info(ip):
    ip_shodan = f'https://api.shodan.io/shodan/host/{ip}?key={api_key_shodan}' 
    response = requests.get(ip_shodan)
    if response.status_code > 399:
        return None
    formatted_data = format_ip_shodan(response.json())
    return formatted_data 


#Utilizzo Shodan per informazioni IP, è più affidabile di AbuseIPDB
def format_ip_shodan(data) -> dict:
    ip = if_not_none(data.get('ip_str'))
    asn = if_not_none(data.get('asn'))
    org = if_not_none(data.get('org'))
    city = if_not_none(data.get('city')) 
    country_name = if_not_none(data.get('country_name'))
    country_code = if_not_none(data.get('country_code'))
    isp = if_not_none(data.get('isp'))
    longitude = if_not_none(data.get('longitude'))
    latitude = if_not_none(data.get('latitude'))
    vulns = if_not_none(data.get('vulns'))
    domains = if_not_none(data.get('domains'))
    last_update = if_not_none(data.get('last_update'))
    ports = if_not_none(data.get('ports'))
    hostnames = if_not_none(data.get('hostnames'))
    data_json = data.get('data')
    #components = if_not_none(deep_search("components", data_json))
    products = if_not_none(get_products(data_json))
    x = str("{\"ip\":\""+ip+"\", \"org\":\""+org+"\", \"city\":\""+city+"\", \"country_code\":\""+country_code+"\", \"country_name\":\""+country_name+"\", \"latitude\":\""+latitude+"\", \"longitude\":\""+longitude+"\",\"asn\":\""+asn+"\", \"isp\":\""+isp+"\", \"domain\":"+domains+", \"last_update\":\""+last_update+"\", \"ports\":"+ports+", \"hostnames\":"+hostnames+", \"vulns\":"+vulns+", \"products\":"+products+"}")
    y = json.loads(x)
    return y 



def get_products(array : list):
    products = []
    for item in array:
        if item.get('product') != None and item.get('product') not in products:
            products.append(item.get('product'))
    return products


def if_not_none(x):
    if x is not None and type(x) == str:
        return x
    elif type(x) == int or type(x) == float or type(x) == bool:
        return str(x)
    elif type(x) == list:
        return json.dumps(x)
    else:
        return json.dumps([])