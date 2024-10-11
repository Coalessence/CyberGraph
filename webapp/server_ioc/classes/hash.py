from services.virustotal import api_key_virustotal, virustotal_hash
import datetime

class HASH:
    def __init__(self,str):
        if api_key_virustotal != None:
            x = virustotal_hash(str)
            self.hash = x.get('id')
            self.type = x.get('type')
            self.link = x.get('link')
            self.first_submission = x.get('first_submission')
            self.tags = x.get('tags')
            self.extension = x.get('extension')
            self.magic = x.get('magic')
            self.type_description = x.get('type_description')
            self.threat_classification = x.get('threat_classification')
            self.names = x.get('names')
            self.malicious_votes = x.get('malicious_votes')
            self.suspicious_votes = x.get('suspicious_votes')
            self.harmless_votes = x.get('harmless_votes')
            self.undetected_votes = x.get('undetected_votes')
            if int(self.malicious_votes)+int(self.suspicious_votes) != 0:
                self.score = (int((self.malicious_votes)+int(self.suspicious_votes))/(int(self.malicious_votes)+int(self.suspicious_votes)+int(self.harmless_votes)+int(self.undetected_votes)))*100
            else:
                self.score = 0
            self.techniques = []
            for item1 in x.get('tactics'):
                for item2 in item1.get('techniques'):
                    self.techniques.append({
                        'tactic_id':item1.get('id'),
                        'tactic_name':item1.get('name'),
                        'tactic_description':item1.get('description'),
                        'tactic_link':item1.get('link'),
                        'technique_id':item2.get('id'),
                        'technique_name':item2.get('name'),
                        'technique_description':item2.get('description'),
                        'technique_link':item2.get('link'),
                    })
        

    
        

       