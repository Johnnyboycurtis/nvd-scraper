"""
Initial bulk after implementing v2

Need CVE ID, Published Date, 
"""
import json
from scraper import v2_api_requests


START = 0 # looking at howard's file, this is the last index



def main():
    with open("large-sample.json", "w+") as myfile:
        response = v2_api_requests(start_index=99999999) # returns string JSON-format 
        #response = v1_api_request()
        print(response)
        data = json.loads(response.text)
        json.dump(data, myfile, indent=1)
    return None



