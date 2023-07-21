"""
CVE API 2.0

See: https://nvd.nist.gov/developers/vulnerabilities
"""

import requests
from requests.auth import HTTPBasicAuth
from nvd_secrets import get_secrets
import json
from tqdm import tqdm
import datetime as dt

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


def retrieve_useful_data(json_data):
    cves_list = json_data['vulnerabilities']
    # need id, publishdate, base score, attac vector, exploit score, base severity, description, (optional other vendor articles), cveid
    records = []
    #for cve in tqdm(cves_list):
    for cve in cves_list:
        cve = cve['cve']
        vulnStatus = cve['vulnStatus']
        if vulnStatus in ('Rejected', 'Deferred', 'Undergoing Analysis', 'Awaiting Analysis', 'Received'):
            # include rejected just for reference, but skip the data extraction
            description = description_from_json(cve)
            publishedDate = cve['published']
            cve_record = {'id': cve['id'], 'vulnStatus': vulnStatus, 'description': description, 'publishedDate': publishedDate, 'dateDownloaded': str(dt.datetime.now())}
        else:
            cve_record = extract_cve_data(cve)
            cve_record['dateDownloaded'] = str(dt.datetime.now())
        records.append(cve_record)
    return records


def extract_cve_data(cve):
    """
    `cve` should be the inner layer of the cve
    Before calling this function make sure to run
        cve = cve['cve']
    CVE is nested within the cve. Otherwise you'll get an error.
    """
    cveid = cve['id']
    publishedDate = cve['published']
    lastModified = cve['lastModified']
    vulnStatus = cve['vulnStatus']
    description = description_from_json(cve)
    metrics_data = metrics_from_json(cve)
    references_url_list = references_from_json(cve)
    metrics_data['id'] = cveid
    metrics_data['publishedDate'] = publishedDate
    metrics_data['lastModified'] = lastModified
    metrics_data['vulnStatus'] = vulnStatus
    metrics_data['description'] = description
    metrics_data['references_url_list'] = references_url_list # contains useful articles that can also be scraped
    return metrics_data


def description_from_json(cve):
    description_list = cve['descriptions']
    # Expect {lang: en, value: the description}
    for item in description_list:
        if item['lang'] == 'en':
            return item['value']
    return str(description_list)


def references_from_json(cve):
    references_list = cve['references']
    url_list = []
    for item in references_list:
        url_list.append(item['url'])
    return url_list




def metrics_from_json(cve, return_cve=False):
    """
    cve: JSON or dict object

    Notes on Metrics
    metrics can contain multiple keys (and dictionaries)
    For example, (https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-41172),
        contains "cvssMetricV2" and "cvssMetricV31". In this scenario, I think the best 
        decision would be to take version 3.1 and ignore V2.0. 

    However, cvssMetricV31 also contains multiple sub-metrics. 
        "cvssMetricV31": [{...type: Primary}, {...type: Secondary}, ...]
    In this scenario, we would prioritize the Primary type and ignore secondary. 
    """
    metrics = cve['metrics']
    keys = list(metrics.keys())
    keys.sort(reverse=True)
    try:
        version = keys[0] # the highest ranking version is default
    except IndexError:
        print(cve)
        raise IndexError
    if version == 'cvssMetricV2':
        metrics_data = v2metrics(cve=cve)
    elif version in ('cvssMetricV30', 'cvssMetricV31'):
        metrics_data = v31metrics(cve)
    else:
        print(cve)
        print("I don't know what version={} is .... needs to be reviewed!!".format(version))
        raise ValueError
    return metrics_data
    


def v2metrics(cve, return_cve=False):
    """
    cve: JSON or dict object

    Notes on Metrics
    metrics can contain multiple keys (and dictionaries)
    For example, (https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-41172),
        contains "cvssMetricV2" and "cvssMetricV31". In this scenario, I think the best 
        decision would be to take version 3.1 and ignore V2.0. 

    However, cvssMetricV31 also contains multiple sub-metrics. 
        "cvssMetricV31": [{...type: Primary}, {...type: Secondary}, ...]
    In this scenario, we would prioritize the Primary type and ignore secondary. 
    """
    metrics = cve['metrics']
    keys = list(metrics.keys())
    keys.sort(reverse=True)
    try:
        version = keys[0] # the highest ranking version is default
        baseScore = metrics[version][0]['cvssData']['baseScore']
        baseSeverity = metrics[version][0]['baseSeverity']
        if version == 'cvssMetricV2':
            attackVector = metrics[version][0]['cvssData']['accessVector']
        else:
            attackVector = metrics[version][0]['cvssData']['attackVector']
        exploitabilityScore = metrics[version][0]['exploitabilityScore']
        impactScore = metrics[version][0]['exploitabilityScore']
        metrics_data = {'version': version, 'all_versions': keys, 
                        'baseScore': baseScore, 'baseSeverity': baseSeverity, 
                        'attacVector': attackVector, 'exploitabilityScore': exploitabilityScore,
                        'impactScore': impactScore}
        if return_cve:
            return metrics_data, cve
        return metrics_data
    except (IndexError, KeyError) as e:
        print(cve)
        raise e



def v31metrics(cve, return_cve=False):
    """
    cve: JSON or dict object

    Notes on Metrics
    metrics can contain multiple keys (and dictionaries)
    For example, (https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-41172),
        contains "cvssMetricV2" and "cvssMetricV31". In this scenario, I think the best 
        decision would be to take version 3.1 and ignore V2.0. 

    However, cvssMetricV31 also contains multiple sub-metrics. 
        "cvssMetricV31": [{...type: Primary}, {...type: Secondary}, ...]
    In this scenario, we would prioritize the Primary type and ignore secondary. 
    """
    metrics = cve['metrics']
    keys = list(metrics.keys())
    keys.sort(reverse=True)
    try:
        version = keys[0] # the highest ranking version is default
        baseScore = metrics[version][0]['cvssData']['baseScore']
        baseSeverity = metrics[version][0]['cvssData']['baseSeverity']
        attackVector = metrics[version][0]['cvssData']['attackVector']
        exploitabilityScore = metrics[version][0]['exploitabilityScore']
        impactScore = metrics[version][0]['exploitabilityScore']
        metrics_data = {'version': version, 'all_versions': keys, 
                        'baseScore': baseScore, 'baseSeverity': baseSeverity, 
                        'attacVector': attackVector, 'exploitabilityScore': exploitabilityScore,
                        'impactScore': impactScore}
        if return_cve:
            return metrics_data, cve
        return metrics_data
    except (IndexError, KeyError) as e:
        print(cve)
        raise e



def simple_api_call():
    with open("sample-v2.json", "w+") as myfile:
        response = v2_api_requests(start_index=0, resultsPerPage=10) # returns string JSON-format 
        #response = v1_api_request()
        print(response)
        data = json.loads(response.text)
        json.dump(data, myfile, indent=1)
    return response



if __name__ == "__main__":
    pass



"""
url = 'https://api_url'
headers = {'Accept': 'application/json'}
auth = HTTPBasicAuth('apikey', '1234abcd')
files = {'file': open('filename', 'rb')}
req = requests.get(url, headers=headers, auth=auth, files=files)
"""

