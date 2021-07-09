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
    #print
    r =  requests.get(turl, headers=auth_header, stream=True)
    result["debug_"+key] = {"ok":str(r.ok),"headers":dict(r.headers),
                            "url": turl,
                            "status_code": str(r.status_code)}
    if r.status_code == 200:
        result[key] = json.loads(str(r.text))

def vince_to_cvrf(vince):
    cvrf =  { "document": {
        "acknowledgments": [
            {
                "urls": [
                    "https://kb.cert.org/vuls/id/"+vince["get_case"]["vuid"]
                    ]
            }
        ],
        "category": "generic_csaf",
        "csaf_version": "2.0",
        "notes": [
            {
                "category": "summary",
                "text": vince["get_case"]["summary"],
                "title": "Summary"
            },
            {
                "category": "faq",
                "text": "Please visit https://vuls.cert.org/confluence/display/Wiki/Vulnerability+Disclosure+Policy for full disclosure policy document",
                "title": "Vulnerability Policy"
            },
            {
                "category": "legal_disclaimer",
                "text": "THIS DOCUMENT IS PROVIDED ON AN \"AS IS\" BASIS AND DOES NOT IMPLY ANY KIND OF GUARANTEE OR WARRANTY, INCLUDING THE WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR USE. YOUR USE OF THE INFORMATION ON THE DOCUMENT OR MATERIALS LINKED FROM THE DOCUMENT IS AT YOUR OWN RISK.",
                "title": "Legal Disclaimer"
            }
        ],
        "publisher": {
            "category": "coordinator",
            "contact_details": "Email: cert@cert.org, Phone: +1412 268 5800",
            "issuing_authority": "CERT/CC under DHS/CISA https://www.cisa.gov/cybersecurity also see https://kb.cert.org/ ",
            "name": "CERT/CC",
            "namespace": "https://kb.cert.org/"
        },
        "references": [
            {
                "summary": "CERT/CC document released",
                "url": "https://kb.cert.org/vuls/id/"+vince["get_case"]["vuid"]
            }
        ],
        "title": vince["get_case"]["title"],
        "tracking": {
            "current_release_date": vince["get_case"]["due_date"],
            "generator": {
                "engine": {
                    "name": "VINCE",
                    "version": "1.30.0"
                }
            },
            "id": vince["get_case"]["vuid"],
            "initial_release_date": vince["get_case"]["created"],
            "revision_history": [
                {
                    "date": vince["get_case"]["due_date"],
                    "number": "1.0.0",
                    "summary": "Public released after peer review"
                }
            ],
            "status": "final",
            "version": "1.0.0"
        }
    }}
    cvrf["vulnerabilities"] = []
    #map vulnerabilities to cvrf
    for k in vince["get_vuls"]:
        cvrf["vulnerabilities"].append({
            "title":k["description"],
            "cve":k["name"]})
    cvrf["product_tree"] = {"branches": [{
        "category": "product_version",
        "name": vince["get_original_report"]["product_name"] 
            if vince["get_original_report"]["product_name"] else "Unspecified",
        "product": {
            "name": vince["get_original_report"]["product_name"] 
            if vince["get_original_report"]["product_name"] else "Unspecified",
            "product_id": vince["get_original_report"]["product_version"]
            if vince["get_original_report"]["product_version"] else "Unknown"
        }
    }]}
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


