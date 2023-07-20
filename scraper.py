"""
CVE API 2.0

See: https://nvd.nist.gov/developers/vulnerabilities
"""

import requests
from requests.auth import HTTPBasicAuth
from nvd_secrets import get_secrets
import json


def v2_api_requests(start_index=None, cve_id = None, resultsPerPage=2000):
    """
    Call NVD V2 API
    Use `start_index` for bulk scheduled pulls
    Use `cve_id` for individual CVE search
    """
    if (start_index is None) and (cve_id is None):
        raise ValueError("start_index or cve_id have to be populated")
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage={}&startIndex={}".format(resultsPerPage, start_index) # CVE API -- set to 20 for testing
    if cve_id:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}".format(cve_id)
    secrets = get_secrets()
    auth = HTTPBasicAuth('apikey', secrets['apikey'])
    session = requests.Session()
    response = session.get(url=url, auth=auth)
    session.close()
    return response



def v1_api_request(start_index = None, cve_id = None):
    """
    V1 API will be shutdown in September 2023
    https://nvd.nist.gov/developers/vulnerabilities-1#
    https://nvd.nist.gov/general/news/api-20-announcements#
    """
    if (start_index is None) and (cve_id is None):
        raise ValueError("start_index or cve_id have to be populated")
    url = "https://services.nvd.nist.gov/rest/json/cves/1.0/?resultsPerPage=2000&startIndex={}".format(start_index) # CVE API
    if cve_id:
        url = "https://services.nvd.nist.gov/rest/json/cve/1.0/{}".format(cve_id)
    secrets = get_secrets()
    auth = HTTPBasicAuth('apikey', secrets['apikey'])
    session = requests.Session()
    response = session.get(url=url, auth=auth)
    session.close()
    return response


def query_new_index(max_index=100, start_index=0):
    with open("sample-v2.json", "a+") as myfile:
        status_code = None
        while status_code != 200:
            response = v2_api_requests(start_index=0, resultsPerPage=10) # returns string JSON-format 
            status_code = response.status_code
        data = json.loads(response.text)
        json.dump(data, myfile, indent=1)
    return response


def retrieve_useful_data(response):
    data = response.json()
    cves = data['vulnerabilities']
    # need id, publishdate, base score, attac vector, exploit score, base severity, description, (optional other vendor articles), cveid
    for cve in cves:
        id = cve['id']
        publishedDate = cve['published']
        lastModified = cve['lastModified']
        vulnStatus = cve['vulnStatus']
        description = description_from_json(cve)



def description_from_json(cve):
    description_list = cve['descriptions']
    # Expect {lang: en, value: the description}
    for item in description_list:
        if item['lang'] == 'en':
            return item['value']
    return str(description_list)


def metrics_from_json()



def main():
    with open("sample-v2.json", "w+") as myfile:
        response = v2_api_requests(start_index=0, resultsPerPage=10) # returns string JSON-format 
        #response = v1_api_request()
        print(response)
        data = json.loads(response.text)
        json.dump(data, myfile, indent=1)
    return response



if __name__ == "__main__":
    main()



"""
url = 'https://api_url'
headers = {'Accept': 'application/json'}
auth = HTTPBasicAuth('apikey', '1234abcd')
files = {'file': open('filename', 'rb')}
req = requests.get(url, headers=headers, auth=auth, files=files)
"""

