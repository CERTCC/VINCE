# API Examples 
Select examples of using VINCE API to create various output such as CVRF underrr Oasis [CSAF](https://github.com/oasis-tcs/csaf)
working group and other outputs like [CVE JSON](https://github.com/CVEProject/automation-working-group/tree/master/cve_json_schema) 

First generate your API Key in your VINCE profile.  For full VINCE API documentation visit [https://vuls.cert.org/confluence/display/VIN/API](https://vuls.cert.org/confluence/display/VIN/API)

# Sample outputs
sample_get_cases.json : Get all cases for a vendor or a coordinator or a participant
`./get_vince.py > sample_get_cases.json`

vu-257161-raw.json : Get case VU#257161 in raw VINCE format with all available information
`./get_vince.py 257161 raw > vu-257161-raw.json`

cvrf-257161.json : Get Case VU#257161 in CVRF format for import into another tool
`./get_vince.py 257161 cvrf > cvrf-257161.json`

When prompted enter your API key for the above commands.

