from services.shodan import api_key_shodan, get_ip_info
from services.virustotal import api_key_virustotal, get_domain_info, get_dns_update
from services.securitytrails import api_security_trails
import datetime

class DOMAIN:
    def __init__(self,stri):
        self.dns_records = []
        self.ipv4 = None
        self.organization = 'N/A'
        self.last_update = 'N/A'
        self.hostnames = []
        self.vulnerabilities = []
        self.ports = []
        self.products = []
        if api_key_virustotal != None and get_domain_info(stri) != None:
            domain_info = get_domain_info(stri)[0]
            self.domain = domain_info.get('domain')
            if self.domain != None:
                #self.creation = domain_info.get('creation')
                self.reputation = domain_info.get('reputation')
                self.malicious_score = domain_info.get('malicious')
                self.suspicious_score = domain_info.get('suspicious')
                self.dns_records.append(get_dns_update(stri)[0])
                self.dns_records_other_format = []
                self.vulnerabilities_other_format = []
                if 'A' in self.dns_records[0] and len(self.dns_records[0]['A']) != 0:
                    self.ipv4 = self.dns_records[0]['A'][0]
                if 'AAAA' in self.dns_records[0] and len(self.dns_records[0]['AAAA']) != 0:
                    self.ipv6 = self.dns_records[0]['AAAA'][0]
                for item in self.dns_records[0].keys():
                    for item2 in self.dns_records[0].get(item):
                        self.dns_records_other_format.append({
                            'key':item,
                            'value':item2
                        })
                if api_key_shodan != None: #TODO: Configure also with ipv6
                    shodan = None
                    if self.ipv4 != None:
                        shodan : dict  = get_ip_info(self.ipv4)
                    if shodan != None:
                        self.organization = shodan.get('org')
                        self.last_update = shodan.get('last_update')
                        self.hostnames = shodan.get('hostnames')
                        self.vulnerabilities = shodan.get('vulns')
                        self.ports = shodan.get('ports')
                        self.products = shodan.get('products')
                        for item in self.vulnerabilities:
                                self.vulnerabilities_other_format.append({
                                    'id':item,
                                    'url':'https://nvd.nist.gov/vuln/detail/'+item
                                })
                if api_security_trails!= None:
                    self.subdomains : list = []
                    #self.subdomains = get_subdomains(str) TODO: Uncomment

    def __init__(self,stri, ip):
        self.dns_records = []
        self.ipv4 = None
        self.organization = 'N/A'
        self.last_update = 'N/A'
        self.hostnames = []
        self.vulnerabilities = []
        self.ports = []
        self.products = []
        if api_key_virustotal != None and get_domain_info(stri) != None:
            domain_info = get_domain_info(stri)[0]
            self.domain = domain_info.get('domain')
            if self.domain != None:
                #self.creation = domain_info.get('creation')
                self.reputation = domain_info.get('reputation')
                self.malicious_score = domain_info.get('malicious')
                self.suspicious_score = domain_info.get('suspicious')
                self.dns_records.append(get_dns_update(stri)[0])
                self.dns_records_other_format = []
                self.vulnerabilities_other_format = []
                self.ipv4 = ip
                for item in self.dns_records[0].keys():
                    for item2 in self.dns_records[0].get(item):
                        self.dns_records_other_format.append({
                            'key':item,
                            'value':item2
                        })
                if api_key_shodan != None: #TODO: Configure also with ipv6
                    shodan = None
                    if self.ipv4 != None:
                        shodan : dict  = get_ip_info(self.ipv4)
                    if shodan != None:
                        self.organization = shodan.get('org')
                        self.last_update = shodan.get('last_update')
                        self.hostnames = shodan.get('hostnames')
                        self.vulnerabilities = shodan.get('vulns')
                        self.ports = shodan.get('ports')
                        self.products = shodan.get('products')
                        for item in self.vulnerabilities:
                                self.vulnerabilities_other_format.append({
                                    'id':item,
                                    'url':'https://nvd.nist.gov/vuln/detail/'+item
                                })
                if api_security_trails!= None:
                    self.subdomains : list = []
                    #self.subdomains = get_subdomains(str) TODO: Uncomment

   

        

       