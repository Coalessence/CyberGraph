from services.abuseipdb import api_key_abuseipdb, get_reputation
from services.shodan import api_key_shodan, get_ip_info
import datetime

class IP:
    def __init__(self,ip):
        self.ip : str = ip
        if api_key_abuseipdb != None:
            abuse : dict = get_reputation(ip)
            if abuse != None:
                self.is_public : str = abuse.get('is_public')
                self.ip_version : str = abuse.get('ip_version')
                if self.is_public == "True":
                    self.domains = []
                    self.number_of_reports : str = abuse.get('total_reports')
                    self.last_reported : str = abuse.get('last_reported')
                    self.score : str  = abuse.get('abuse_score')
                    self.country_code : str = abuse.get('country_code')
                    self.country_name : str = abuse.get('country_name')
                    self.usage_type : str = abuse.get('usage_type')
                    self.ISP : str = abuse.get('isp')
                    self.domains.append(abuse.get('domain'))
                if api_key_shodan != None and self.is_public == "True":
                    shodan : dict  = get_ip_info(ip)
                    if shodan != None:
                        self.ASN : str = shodan.get('asn')
                        self.organization : str = shodan.get('org')
                        self.country_city : str = shodan.get('city')
                        #Override from AbuseIPDB since Shodan is more accurate
                        self.country_name : str = shodan.get('country_name')
                        self.country_code : str = shodan.get('country_code')
                        self.ISP : str = shodan.get('isp')
                        self.domains = shodan.get('domain')
                        ###############################
                        self.longitude : str = shodan.get('longitude')
                        self.latitude : str = shodan.get('latitude')
                        self.last_update : str = shodan.get('last_update')
                    else:
                        self.ASN : str = 'N/A'
                        self.organization : str = 'N/A'
                        self.country_city : str = 'N/A'
                        ###############################
                        self.longitude : str = 'N/A'
                        self.latitude : str = 'N/A'
                        self.last_update : str = 'N/A'



   
        

       