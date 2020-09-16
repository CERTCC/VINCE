#!/usr/bin/python3

import requests,json,sys,getpass,argparse

###################################################################################
###################### Python Script to collect VINCE API ########################
###################################################################################

### Usage ###

# To run this script you must have the following:
#	Python 2.7 or Python 3 (Preferred)
#	Python modules requests,json,sys,getpass,argparse

# Simply run following command in terminal to validate json file against schema:

# ./get_vince.py [VU# case number] [output_type=cvrf]


# ***NOTE***
# If you do not specify any arguments this code will prompt you for API key
# and will print all your cases in VINCE format.

###################################################################################
###################################################################################


def error_exit(reason):
    print(json.dumps({"error":reason}))
    sys.exit(1)

def fatal_exit(ex_cls, ex, tb):
    #Send all locals into a error array back to exit
    #errors = map(str,locals())
    errors = {"ex_cls":str(ex_cls),"ex":str(ex),"tb":str(tb)}
    print(json.dumps({"errors":"Program error","info":errors}))
    sys.exit(2)
    

def safe_print(st):
    print(json.dumps(st))


def create_response(key,turl):
    r =  requests.get(turl, headers=auth_header, stream=True)
    result["debug_"+key] = {"ok":str(r.ok),"headers":dict(r.headers),
                            "url": turl,
                            "status_code": str(r.status_code)}
    if r.status_code == 200:
        result[key] = json.loads(str(r.text))

def vince_to_cvrf(vince):
    cvrf ={}
    cvrf["document"] = {}
    cvrf["document"]["title"] = vince["get_case"]["title"]
    cvrf["document"]["type"] = "CERT/CC Vulnerability Notes Database Advisory"
    cvrf["document"]["csaf_version"] = "2.0"
    cvrf["document"]["publisher"] = {"contact_details":
                                     "Email: cert@cert.org, Phone: +1412 268 5800",
		                     "issuing_authority":
                                     "CERT/CC under DHS/CISA https://www.cisa.gov/cybersecurity"+
                                     " also see https://kb.cert.org/ ",
		                     "type":"coordinator"
    }
    cvrf["document"]["tracking"] = {}
    cvrf["document"]["tracking"]["id"] = vince["get_case"]["vuid"]
    cvrf["document"]["tracking"]["status"] = "final"
    cvrf["document"]["tracking"]["version"] = "1.0"
    cvrf["document"]["tracking"]["revision_history"] = [{"number":"1.0","date":vince["get_case"]["due_date"],"description":"Public released after peer review"}]
    cvrf["document"]["tracking"]["generator"] = {"engine":"VINCE API"}
    cvrf["document"]["tracking"]["initial_release_date"] = vince["get_case"]["created"]
    cvrf["document"]["tracking"]["current_release_date"] = vince["get_case"]["due_date"]
    #three element dictionary array to provide Summary, general and legal_disclaimer
    cvrf["document"]["notes"] = [{},{},{}]
    cvrf["document"]["notes"][0]["title"] = "Summary"
    cvrf["document"]["notes"][0]["type"] = "summary"
    cvrf["document"]["notes"][0]["text"] = vince["get_case"]["summary"]
    cvrf["document"]["notes"][1]["title"] =  "Vulnerability Policy"
    cvrf["document"]["notes"][1]["type"] = "general"
    cvrf["document"]["notes"][1]["text"] = "Please visit https://vuls.cert.org/confluence/display/Wiki/Vulnerability+Disclosure+Policy for full disclosure policy document"
    cvrf["document"]["notes"][2]["title"] =  "Legal Disclaimer"
    cvrf["document"]["notes"][2]["type"] = "legal_disclaimer"
    cvrf["document"]["notes"][2]["text"] = "THIS DOCUMENT IS PROVIDED ON AN \"AS IS\" BASIS AND DOES NOT IMPLY ANY KIND OF GUARANTEE OR WARRANTY, INCLUDING THE WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR USE. YOUR USE OF THE INFORMATION ON THE DOCUMENT OR MATERIALS LINKED FROM THE DOCUMENT IS AT YOUR OWN RISK."
    cvrf["document"]["references"] = [{}]
    cvrf["document"]["references"][0]["url"] = "https://kb.cert.org/vuls/id/"+vince["get_case"]["vuid"]
    cvrf["document"]["references"][0]["description"] = "Full document of our Vulnerability Notes database"
    cvrf["document"]["acknowledgements"]=[{}]
    cvrf["document"]["acknowledgements"][0]["text"] = "Please see Acknowledgements section of "+"https://kb.cert.org/vuls/id/"+vince["get_case"]["vuid"]
    cvrf["document"]["product_tree"] = []
    #cvrf["document"]["vulnerability"] = vince["get_vuls"]
    cvrf["document"]["vulnerabilities"] = []
    #map vulnerabilities to cvrf
    for k in vince["get_vuls"]:
        cvrf["document"]["vulnerabilities"].append({"title":k["description"],
                                                    "cve":k["name"]})
    return cvrf

    
api_base = "https://kb.cert.org/vince/comm/api"
url_map = { "get_cases": api_base+'/cases/',
            "get_case": api_base+"/case/$case/",
            "get_posts": api_base+"/case/posts/$case/",
            "get_original_report": api_base+"/case/report/$case/",
            "get_vendors": api_base+"/case/vendors/$case/",
            "get_vuls": api_base+"/case/vuls/$case/"}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='VINCE API to get Case(s) and '+
                                     'convert to output formats')
    parser.add_argument('case number', nargs='?', type=str, help='VU#12345',default='')
    parser.add_argument('output-type', nargs='?',type=str, help='cvrf',default='cvrf')
    args = parser.parse_args()
    token = getpass.getpass("Enter API Token:")
    auth_header = {"Authorization": "Token {}".format(token)}
    result = {}
    sys.excepthook = fatal_exit    

    if len(sys.argv) > 1:
        result["query_info"] = "Getting a specified case data"
        result["case"] = sys.argv[1].lower().replace("vu#","")
        del url_map['get_cases']
        for k,url in url_map.items():
            url = url.replace("$case",result["case"])
            create_response(k,url)
        if len(sys.argv) > 2:
            if sys.argv[2].lower() == "cvrf":
                #print CVRF data in JSON format
                print(json.dumps((vince_to_cvrf(result))))
            else:
                print(json.dumps(result))
        sys.exit(0)
    else:
        result["query_info"] ="Getting all cases "
        create_response("get_cases",url_map["get_cases"])
    safe_print(result)
    sys.exit(0)


