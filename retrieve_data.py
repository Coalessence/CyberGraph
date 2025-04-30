import requests
import os
import time
import json
import glob
import re
import gzip
from dotenv import load_dotenv
from datetime import datetime
from io import BytesIO
from urllib.request import urlopen
from zipfile import ZipFile

# Web scraping imports
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import Select
from selenium.webdriver.common.by import By

class CVE:
    def __init__(self, year=None):
        load_dotenv()
        self._api_key = os.getenv('NIST_API_KEY')
        self._retry_sleep = 5    # In seconds
        if(year is not None):
            self._year = year

    def __send_request(self,url):
        while True:
            res = requests.get(url, headers={"apiKey": self._api_key})
            if res:
                try:
                    response = res.json()
                    break
                except:
                    print("Some error occured during the JSON conversion of the API response. A new attempt will be done in {} seconds.".format(self._retry_sleep))
                    time.sleep(self._retry_sleep)
            else:
                print("The NIST API didn't responded in time. A new attempt will be done in {} seconds.".format(self._retry_sleep))
                time.sleep(self._retry_sleep)
        return response
            

    def get_number_existing_cves(self):
        response = self.__send_request("https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=1&noRejected")    
        return response["totalResults"]

    # 'filename': name of the output file (the default one is 'dump.json')
    def create_cves_dump(self, filename="dump"):
        idx = 0
        result_per_page = 2000
        total_results = self.get_number_existing_cves()
        print("CVEs found: {}".format(str(total_results)))
        print("Starting retrieving data...")
        while idx < total_results:
            print('{:.2f}% complete. Processing CVEs entries from indexes {} to {}'.format((idx/total_results)*100,idx, idx + result_per_page - 1))
            
            response = self.__send_request("https://services.nvd.nist.gov/rest/json/cves/2.0/?noRejected&resultsPerPage={}&startIndex={}".format(result_per_page,idx))

            if not idx:
                with open("{}.json".format(filename), "w") as file:
                    json.dump(response, file, indent = 4)
            else:
                with open("{}.json".format(filename), "r+") as file:
                    data = json.load(file)
                    data["vulnerabilities"].extend(response["vulnerabilities"])

                    file.seek(0)
                    json.dump(data, file, indent = 4)

            idx += result_per_page

            # Needed in order to not get banned from NIST
            time.sleep(10)
        
        print("All CVEs has been downloaded and successfully saved into the \'{}.json\' file.".format(filename))
        
        return "{}.json".format(filename)

    def get_cves_year(self, filename="dump", year=2020):
        idx = 0
        result_per_page = 2000
        total_results = 0

        
        response = self.__send_request('https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=1&noRejected&pubStartDate={}-01-01T00:00:00.000&pubEndDate={}-04-01T00:00:00.000'.format(year,year))    
        total_results=response["totalResults"]
        
        print("Starting retrieving first part of the year")
        
        while idx < total_results:
            
            response = self.__send_request("https://services.nvd.nist.gov/rest/json/cves/2.0/?noRejected&resultsPerPage={}&startIndex={}&pubStartDate={}-01-01T00:00:00.000&pubEndDate={}-04-01T00:00:00.000".format(result_per_page,idx, year, year))

            if not idx:
                with open("{}.json".format(filename), "w") as file:
                    json.dump(response, file, indent = 4)
            else:
                with open("{}.json".format(filename), "r+") as file:
                    data = json.load(file)
                    data["vulnerabilities"].extend(response["vulnerabilities"])

                    file.seek(0)
                    json.dump(data, file, indent = 4)

            idx += result_per_page
            time.sleep(10)
        
        
        idx=0
        
        print("Starting retrieving second part of the year")
        
        response = self.__send_request("https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=1&noRejected&pubStartDate={}-04-01T00:00:01.000&pubEndDate={}-07-01T00:00:00.000".format(year, year))    
        total_results+=response["totalResults"]
        
        while idx < total_results:
            
            response = self.__send_request("https://services.nvd.nist.gov/rest/json/cves/2.0/?noRejected&resultsPerPage={}&startIndex={}&pubStartDate={}-04-01T00:00:01.000&pubEndDate={}-07-01T00:00:00.000".format(result_per_page,idx, year, year))

            with open("{}.json".format(filename), "r+") as file:
                data = json.load(file)
                data["vulnerabilities"].extend(response["vulnerabilities"])

                file.seek(0)
                json.dump(data, file, indent = 4)

            idx += result_per_page
            time.sleep(10)
        
        idx=0
        
        print("Starting retrieving third part of the year")
        
        response = self.__send_request("https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=1&noRejected&pubStartDate={}-07-01T00:00:01.000&pubEndDate={}-10-01T00:00:00.000".format(year, year))    
        total_results+=response["totalResults"]
        
        while idx < total_results:
            
            response = self.__send_request("https://services.nvd.nist.gov/rest/json/cves/2.0/?noRejected&resultsPerPage={}&startIndex={}&pubStartDate={}-07-01T00:00:01.000&pubEndDate={}-10-01T00:00:00.000".format(result_per_page,idx, year, year))

            if not idx:
                with open("{}.json".format(filename), "w") as file:
                    json.dump(response, file, indent = 4)
            else:
                with open("{}.json".format(filename), "r+") as file:
                    data = json.load(file)
                    data["vulnerabilities"].extend(response["vulnerabilities"])

                    file.seek(0)
                    json.dump(data, file, indent = 4)

            time.sleep(10)
            idx += result_per_page
            
        
        print("Starting retrieving fourth part of the year")    
        
        response = self.__send_request("https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=1&noRejected&pubStartDate={}-10-01T00:00:01.000&pubEndDate={}-12-31T23:59:59.000".format(year, year))    
        total_results+=response["totalResults"]
        
        while idx < total_results:
                        
            response = self.__send_request("https://services.nvd.nist.gov/rest/json/cves/2.0/?noRejected&resultsPerPage={}&startIndex={}&pubStartDate={}-10-01T00:00:01.000&pubEndDate={}-12-31T23:59:59.000".format(result_per_page,idx, year, year))

            if not idx:
                with open("{}.json".format(filename), "w") as file:
                    json.dump(response, file, indent = 4)
            else:
                with open("{}.json".format(filename), "r+") as file:
                    data = json.load(file)
                    data["vulnerabilities"].extend(response["vulnerabilities"])

                    file.seek(0)
                    json.dump(data, file, indent = 4)

            idx += result_per_page
            time.sleep(10)
        
        print("All CVEs of {} has been downloaded and successfully saved into the \'{}.json\' file.".format(year,filename))
        
        return "{}.json".format(filename)
    
    # 'dump_filename': name of the dump file
    # The search for new updates will start from the most recent update file (if there is no update file, start from the dump one)
    # Common usage: cron job
    def get_cves_updates(self, dump_filename):
        regex = re.compile(".*([0-9]+).*")
        update_max_count = 0
        for name in glob.glob("./update[0-9]*.json"):
            n = int(regex.match(name).group(1))
            if update_max_count < n:
                update_max_count = n
        output_filename = "update{}.json".format(update_max_count + 1)

        with open(dump_filename if not update_max_count else "update{}.json".format(update_max_count), "r") as file:
            try:
                data = json.load(file)
                last_update_date = data["timestamp"]
            except:
                print("Oops, it was not possible open the specified file :(")
                return

        # Dates must follow "yyyy-MM-ddTHH:mm:ss:SSS Z" format (e.g. 2022-07-23T16:32:20:265 UTC+01:00) where either the space and the plus must be rightly encoded (' '=%20  +=%2B)
        current_date = datetime.utcnow().isoformat(sep='T', timespec='milliseconds').replace(".",":")

        idx = 0
        result_per_page = 4000
        print("Starting retrieving updates...")
        while True:
            response = self.__send_request("https://services.nvd.nist.gov/rest/json/cves/2.0/?noRejected&resultsPerPage={}&startIndex={}&changeStartDate={}&changeEndDate={}".format(result_per_page,idx,last_update_date,current_date))
            if idx >= response["totalResults"]:
                break
            
            if not idx:
                with open(output_filename, "w") as file:
                    json.dump(response, file, indent = 4)
            else:
                with open(output_filename, "r+") as file:
                    data = json.load(file)
                    data["vulnerabilities"].extend(response["vulnerabilities"])

                    file.seek(0)
                    json.dump(data, file, indent = 4)

            idx += result_per_page

            # Needed in order to not get banned from NIST
            time.sleep(5)
        
        if not idx:
            print("No new updates found.")
        else:
            print("All the updates has been downloaded and successfully saved into the \'{}\' file.".format(output_filename))

        return output_filename if idx else ""

class CPE:
    def __init__(self):
        load_dotenv()
        self._api_key = os.getenv('NIST_API_KEY')
        self._retry_sleep = 5    # In seconds

    def __send_request(self,url):
        while True:
            res = requests.get(url, headers={"apiKey": self._api_key})
            if res:
                try:
                    response = res.json()
                    break
                except:
                    print("Some error occured during the JSON conversion of the API response. A new attempt will be done in {} seconds.".format(self._retry_sleep))
                    time.sleep(self._retry_sleep)
            else:
                print("The NIST API didn't responded in time. A new attempt will be done in {} seconds.".format(self._retry_sleep))
                time.sleep(self._retry_sleep)
        return response
    
    def get_number_existing_cpes(self):
        response = self.__send_request("https://services.nvd.nist.gov/rest/json/cpes/2.0/?resultsPerPage=1")    
        return response["totalResults"]
    
    def create_cpes_dump(self, filename="dump"):
        idx = 0
        result_per_page = 2000
        total_results = self.get_number_existing_cpes()

        print("Starting retrieving data...")
        while idx < total_results:
            print('{:.2f}% complete. Processing CPEs entries from indexes {} to {}'.format((idx/total_results)*100,idx, idx + result_per_page - 1))
            
            response = self.__send_request("https://services.nvd.nist.gov/rest/json/cpes/2.0/?resultsPerPage={}&startIndex={}".format(result_per_page,idx))

            if not idx:
                with open("{}.json".format(filename), "w") as file:
                    json.dump(response, file, indent = 4)
            else:
                with open("{}.json".format(filename), "r+") as file:
                    data = json.load(file)
                    data["products"].extend(response["products"])

                    file.seek(0)
                    json.dump(data, file, indent = 4)

            # In case new CPEs have been released when the script is running
            if total_results < response["totalResults"]:
                total_results = response["totalResults"]

            idx += result_per_page

            # Needed in order to not get banned from NIST
            time.sleep(5)
        
        print("All CPEs has been downloaded and successfully saved into the \'{}.json\' file.".format(filename))
        
        return "{}.json".format(filename)
    
    def get_cpes_updates(self, dump_filename):
        regex = re.compile(".*([0-9]+).*")
        update_max_count = 0
        for name in glob.glob("./update[0-9]*.json"):
            n = int(regex.match(name).group(1))
            if update_max_count < n:
                update_max_count = n
        output_filename = "update{}.json".format(update_max_count + 1)

        with open(dump_filename if not update_max_count else "update{}.json".format(update_max_count), "r") as file:
            try:
                data = json.load(file)
                last_update_date = data["timestamp"]
            except:
                print("Oops, it was not possible open the specified file :(")
                return

        # Dates must follow "yyyy-MM-ddTHH:mm:ss.SSS%2B01:00" format (e.g. 2022-07-23T16:32:20.265 UTC+01:00) where either the space and the plus must be rightly encoded (' '=%20  +=%2B)
        current_date = datetime.utcnow().isoformat(sep='T', timespec='milliseconds') + "%2B00:00"
        idx = 0
        result_per_page = 10000
        print("Starting retrieving updates...")
        while True:
            response = self.__send_request("https://services.nvd.nist.gov/rest/json/cpes/2.0/?resultsPerPage={}&startIndex={}&modStartDate={}&modEndDate={}".format(result_per_page,idx,last_update_date,current_date))
            if idx >= response["totalResults"]:
                break
            
            if not idx:
                with open(output_filename, "w") as file:
                    json.dump(response, file, indent = 4)
            else:
                with open(output_filename, "r+") as file:
                    data = json.load(file)
                    data["products"].extend(response["products"])

                    file.seek(0)
                    json.dump(data, file, indent = 4)

            idx += result_per_page

            # Needed in order to not get banned from NIST
            time.sleep(5)
        
        if not idx:
            print("No new updates found.")
        else:
            print("All the updates has been downloaded and successfully saved into the \'{}\' file.".format(output_filename))

        return output_filename if idx else ""

class SOURCES:
    def __init__(self):
        load_dotenv()
        self._api_key = os.getenv('NIST_API_KEY')
        self._retry_sleep = 5    # In seconds

    def __send_request(self,url):
        while True:
            res = requests.get(url, headers={"apiKey": self._api_key})
            if res:
                try:
                    response = res.json()
                    break
                except:
                    print("Some error occured during the JSON conversion of the API response. A new attempt will be done in {} seconds.".format(self._retry_sleep))
                    time.sleep(self._retry_sleep)
            else:
                print("The NIST API didn't responded in time. A new attempt will be done in {} seconds.".format(self._retry_sleep))
                time.sleep(self._retry_sleep)
        return response
    
    def get_number_existing_sources(self):
        response = self.__send_request("https://services.nvd.nist.gov/rest/json/source/2.0/?resultsPerPage=1")    
        return response["totalResults"]
    
    def create_sources_dump(self, filename="dump"):
        idx = 0
        result_per_page = 1000
        total_results = self.get_number_existing_sources()

        print("Starting retrieving data...")
        while idx < total_results:
            print('{:.2f}% complete. Processing Sources entries from indexes {} to {}'.format((idx/total_results)*100,idx, idx + result_per_page - 1))
            
            response = self.__send_request("https://services.nvd.nist.gov/rest/json/source/2.0/?resultsPerPage={}&startIndex={}".format(result_per_page,idx))

            if not idx:
                with open("{}.json".format(filename), "w") as file:
                    json.dump(response, file, indent = 4)
            else:
                with open("{}.json".format(filename), "r+") as file:
                    data = json.load(file)
                    data["sources"].extend(response["sources"])

                    file.seek(0)
                    json.dump(data, file, indent = 4)

            # In case new sources have been released when the script is running
            if total_results < response["totalResults"]:
                total_results = response["totalResults"]

            idx += result_per_page

            # Needed in order to not get banned from NIST
            time.sleep(5)
        
        print("All Sources has been downloaded and successfully saved into the \'{}.json\' file.".format(filename))
        
        return "{}.json".format(filename)
    
    def get_sources_updates(self, dump_filename):
        regex = re.compile(".*([0-9]+).*")
        update_max_count = 0
        for name in glob.glob("./update[0-9]*.json"):
            n = int(regex.match(name).group(1))
            if update_max_count < n:
                update_max_count = n
        output_filename = "update{}.json".format(update_max_count + 1)

        with open(dump_filename if not update_max_count else "update{}.json".format(update_max_count), "r") as file:
            try:
                data = json.load(file)
                last_update_date = data["timestamp"]
            except:
                print("Oops, it was not possible open the specified file :(")
                return

        # Dates must follow "yyyy-MM-ddTHH:mm:ss:SSS Z" format (e.g. 2022-07-23T16:32:20:265 UTC+01:00) where either the space and the plus must be rightly encoded (' '=%20  +=%2B)
        current_date = datetime.utcnow().isoformat(sep='T', timespec='milliseconds').replace(".",":") + "%20UTC%2B00:00"

        idx = 0
        result_per_page = 1000
        print("Starting retrieving updates...")
        while True:
            response = self.__send_request("https://services.nvd.nist.gov/rest/json/source/2.0/?resultsPerPage={}&startIndex={}&modStartDate={}&modEndDate={}".format(result_per_page,idx,last_update_date,current_date))
            if idx >= response["totalResults"]:
                break
            
            if not idx:
                with open(output_filename, "w") as file:
                    json.dump(response, file, indent = 4)
            else:
                with open(output_filename, "r+") as file:
                    data = json.load(file)
                    data["sources"].extend(response["sources"])

                    file.seek(0)
                    json.dump(data, file, indent = 4)

            idx += result_per_page

            # Needed in order to not get banned from NIST
            time.sleep(5)
        
        if not idx:
            print("No new updates found.")
        else:
            print("All the updates has been downloaded and successfully saved into the \'{}\' file.".format(output_filename))

        return output_filename if idx else ""

class CWE:
    # 'filename': name of the output file (the default one is 'cwe.csv')
    # It can be used also to update the CWE list, no need for a specific function
    def create_cwes_dump(self, filename="cwe"):
        print("Starting retrieving CWEs data...")
        with urlopen("https://cwe.mitre.org/data/csv/1000.csv.zip") as zip_response:
            with ZipFile(BytesIO(zip_response.read())) as zfile:
                zfile.extractall("./")
                original_filename = zfile.namelist()
                os.rename("{}".format(original_filename[0]),"{}.csv".format(filename))

        print("All CWEs has been downloaded and successfully saved into the \'{}.csv\' file.".format(filename))
        return "{}.csv".format(filename)

class CAPEC:
    # 'filename': name of the output file (the default one is 'capec.csv')
    # It can be used also to update the CAPEC list, no need for a specific function
    def create_capec_dump(self, filename="capec"):
        print("Starting retrieving CAPECs data...")
        with urlopen("https://capec.mitre.org/data/csv/3000.csv.zip") as zip_response:
            with ZipFile(BytesIO(zip_response.read())) as zfile:
                zfile.extractall("./")
                original_filename = zfile.namelist()
                os.rename("{}".format(original_filename[0]),"{}.csv".format(filename))
        
        print("All CAPECs has been downloaded and successfully saved into the \'{}.csv\' file.".format(filename))
        return "{}.csv".format(filename)

class EPSS:
    
    def __init__(self):
        self.sleep_time=5
    #https://epss.cyentia.com/epss_scores-current.csv.gz
    
    def create_epss_dump(self, filename="epss"):
        print("Starting retrieving EPSSs data...")
        with urlopen("https://epss.cyentia.com/epss_scores-current.csv.gz") as zip_response:
            with gzip.open(BytesIO(zip_response.read())) as zfile:
                with open("{}.csv".format(filename), "wb") as file:
                    file.write(zfile.read())
        
        print("All EPSSs has been downloaded and successfully saved into the \'{}.csv\' file.".format(filename))
        return "{}.csv".format(filename)
    
    # 'filename': name of the output file (the default one is 'epss.csv')
    def create_epss_dump_json(self, filename="epss"):
        print("Starting retrieving EPSSs data...")
        url = 'https://api.first.org/data/v1/epss'
        offset = 0
        limit = 1000
        total=self.get_number_epss()
        
        while offset < total:
            print('{:.2f}% complete.'.format((offset/total)*100))
            
            response = self.send_request("https://api.first.org/data/v1/epss?limit={}&offset={}".format(limit,offset))

            if not offset:
                with open("{}.json".format(filename), "w") as file:
                    json.dump(response, file, indent = 4)
            else:
                with open("{}.json".format(filename), "r+") as file:
                    data = json.load(file)
                    data["data"].extend(response["data"])

                    file.seek(0)
                    json.dump(data, file, indent = 4)

            # In case new CVEs have been released when the script is running
            if total < response["total"]:
                total = response["total"]

            offset += limit

            # Needed in order to not get banned from NIST
            time.sleep(10)
        
        print("All EPSSs has been downloaded and successfully saved into the \'{}.json\' file.".format(filename))
        return "{}.json".format(filename)
    
    def send_request(self,url):
        while True:
            res = requests.get(url)
            if res:
                try:
                    response = res.json()
                    break
                except:
                    print("Some error occured during the JSON conversion of the API response. A new attempt will be done in {} seconds.".format(self.sleep_time))
                    time.sleep(self.sleep_time)
            else:
                print("The EPSS API didn't responded in time. A new attempt will be done in {} seconds.".format(self.sleep_time))
                time.sleep(self.sleep_time)
        return response
    
    def get_number_epss(self):
        response = self.send_request('https://api.first.org/data/v1/epss?limit=1')
        return response['total']
        
class CNA:
    # 'filename': name of the output file (the default one is 'cna.json')
    # It can be used also to update the CNA list, no need for a specific function
    def create_cna_dump(self, filename="cna"):
        # This option force to not physically open a browser tab
        options = Options()
        options.add_argument("--headless")

        driver = webdriver.Chrome(service=Service(), options=options)
        driver2 = webdriver.Chrome(service=Service(), options=options)

        print("Starting retrieving CNAs data...")
        driver.get("https://www.cve.org/PartnerInformation/ListofPartners")
        select = Select(driver.find_element(By.CSS_SELECTOR,"select[aria-label='select how many partners to show']"))
        select.select_by_visible_text('All')

        cna_partners = driver.find_elements(By.XPATH, "//table/tbody/tr")
        cnas = []
        i = 0
        for partner in cna_partners:
            i = i + 1
            link = partner.find_element(By.XPATH,"th[@data-label='Partner']/a").get_attribute('href')
            name = partner.find_element(By.XPATH,"th[@data-label='Partner']/a").text
            # Root Scope - CNA Scope
            scopes = []
            scopes_raw = partner.find_element(By.XPATH,"td[@data-label='Scope']").text
            if ("Root Scope:" in scopes_raw):
                for elem in scopes_raw.split("\n"):
                    scopes.append({
                        "type": elem.split(":")[0].strip().split()[0],
                        "description": elem.split(":")[1].strip(),
                    })
            else:
                scopes.append({
                    "type": "CNA",
                    "description": scopes_raw,
                })
            
            organization_types = [elem.strip() for elem in partner.find_element(By.XPATH,"td[@data-label='Organization Type']").text.split(",")]
            country = partner.find_element(By.XPATH,"td[@data-label='Country*']").text

            driver2.get(link)
            policies_raw = driver2.find_elements(By.XPATH,"//p[contains(text(),'Step 1: Read disclosure policy')]/following-sibling::ul/li/a")
            polices = []
            for policy in policies_raw:
                polices.append({ 
                    "name": policy.text.replace("View", "").strip(), 
                    "link": policy.get_attribute('href') 
                })
            program_roles_raw = driver2.find_elements(By.XPATH,"//th[contains(text(),'Program Role')]/following-sibling::td/ul/li")
            program_roles = [ role.text for role in program_roles_raw ]
            
            security_advisories_raw = driver2.find_elements(By.XPATH,"//th[contains(text(),'Security Advisories')]/following-sibling::td/span/ul/li/a")
            security_advisories = [ { "name": sa.text.replace("View", "").strip() , "link":sa.get_attribute('href') } for sa in security_advisories_raw ]

            contacts_raw = driver2.find_elements(By.XPATH,"//p[contains(text(),'Step 2: Contact')]/following-sibling::div/ul/li/*/a")
            contacts = []
            for contact in contacts_raw:
                contacts.append({ 
                    "name": contact.text, 
                    "contact": contact.get_attribute('href').replace("mailto:",""), 
                    "type": "email" if "mailto:" in contact.get_attribute('href') else "link"
                })

            cna_entry = {
                "name": name,
                "link_more_info": link,
                "organization_types": organization_types,
                "country": country,
                "disclosure_policies": polices,
                "program_roles": program_roles,
                "security_advisories": security_advisories,
                "contacts": contacts,
                "scopes": scopes
            }
            # Not always present
            root = driver2.find_elements(By.XPATH,"//th[contains(text(),'Root') and not(contains(text(),'Top-Level'))]")
            if(len(root)):
                cna_entry["root"] = {
                    "name": root[0].find_element(By.XPATH,"following-sibling::td/a").text,
                    "link_more_info": root[0].find_element(By.XPATH,"following-sibling::td/a").get_attribute('href')
                }
            print("CNAs found: {}".format(i))
            cnas.append(cna_entry)

        with open("{}.json".format(filename), "w") as file:
            json.dump({
                "download_timestamp": datetime.utcnow().isoformat(sep='T', timespec='milliseconds'),
                "cnas":cnas
            }, file, indent = 4)

        driver.quit()

        print("All CNAs has been downloaded and successfully saved into the \'{}.json\' file.".format(filename))
        return "{}.json".format(filename)

if __name__ == "__main__":
    cves = CVE()
    cwes = CWE()
    capec = CAPEC()
    cna = CNA()
    epss = EPSS()
    
    #epss.create_epss_dump("epss")
    cves.create_cves_dump()
    #cwes.create_cwes_dump()
    #capec.create_capec_dump()
    #cna.create_cna_dump()
