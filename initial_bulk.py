"""
Initial bulk after implementing v2

Need CVE ID, Published Date, 
"""
import pandas as pd
from scraper import v2_api_requests, retrieve_useful_data
from tqdm import tqdm
import time
import datetime as dt
import os
import random



def nvd_queries(start_index, stop_index=None, resultsPerPage=2000):
    if stop_index is None:
        response = v2_api_requests(start_index=0, resultsPerPage=10) # query just to get the updated max results available
        stop_index = response.json()['totalResults']
    current_index = start_index # NVD uses 0 as starting index FYI
    print("startIndex={} - endIndex={} - resultsPerPage={}".format(start_index, stop_index, resultsPerPage))
    startTime = dt.datetime.now()
    counter = 1
    status_code = None
    while (current_index < stop_index):
        print("{}. Attempting to query currentIndex={} - endIndex={} - statusCode={}".format(counter, current_index, min(stop_index, current_index+resultsPerPage-1), status_code))
        response = v2_api_requests(start_index=current_index, resultsPerPage=resultsPerPage)
        status_code = response.status_code
        if response.status_code in range(200, 300):
            print("{}. Successful query - duration: {}".format(counter, dt.datetime.now()-startTime))
            json_data = response.json()
            expected_results_num = min(resultsPerPage, min(stop_index-current_index, resultsPerPage))
            n = len(json_data["vulnerabilities"]) # number of CVEs processed
            print("{}. Number of records retrieved: {} and expected: {}".format(counter, n, expected_results_num))
            data = retrieve_useful_data(json_data)
            write_to_csv(data, startIndex=current_index, resultsPerPage=min(n, resultsPerPage))
            # update counters/status_code
            current_index += resultsPerPage # default 2000
            counter += 1
            status_code = None 
            time.sleep(2)
        if response.status_code in range(500, 600):
            t = random.randint(30, 40)
            print("{}. sleeping for {} seconds....".format(counter, t))
            time.sleep(t)
    endTime = dt.datetime.now()
    print("Total duration: {}".format(endTime - startTime))
    print("Success :)")
    return None



def write_to_csv(data, startIndex, resultsPerPage):
    cols = ['id', 'version', 'all_versions', 'baseScore', 'baseSeverity',
        'attacVector', 'exploitabilityScore', 'impactScore', 
        'publishedDate', 'lastModified', 'vulnStatus', 'description',
        'references_url_list', 'dateDownloaded']
    index = pd.Index(range(startIndex, startIndex+resultsPerPage))
    df = pd.DataFrame(data, index=index)
    for c in cols:
        if c not in df.columns:
            df[c] = ''
    df = df[cols]
    output_path = "data/nvd_cve_metrics.txt"
    df.to_csv(output_path, sep="|", mode='a+', header=not os.path.exists(output_path))
    print("successfully appended data to text file")
    return True



if __name__ == "__main__":
    nvd_queries(start_index=0)