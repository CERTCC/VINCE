# API Examples 
This repo contains select examples about using the [VINCE]( API to generate outputs in different vulnerability reporting formats, such as the [CSAF](https://github.com/oasis-tcs/csaf) Common Vulnerability Reporting Framework (CVRF) and [CVE JSON](https://github.com/CVEProject/automation-working-group/tree/master/cve_json_schema).

First, generate your API Key in your VINCE profile. For full VINCE API documentation including instructions on generating the key, please see the [VINCE FAQ](https://vuls.cert.org/confluence/display/VIN/API).

# Sample outputs
sample_get_cases.json : Get all cases for a specific vendor, coordinator, or a participant.
`./get_vince.py > sample_get_cases.json`
  
vu-257161-raw.json : Get case VU#257161 in raw VINCE JSON format with all available information.
`./get_vince.py 257161 raw > vu-257161-raw.json`  
  
cvrf-257161.json : Get case VU#257161 in CVRF format to import into another tool.
`./get_vince.py 257161 cvrf > cvrf-257161.json`  
  
When prompted, please enter your API key to use the above commands.



