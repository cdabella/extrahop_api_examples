import requests
import json

headers = {'Content-Type': 'application/json',
           'Accept': 'application/json',
           'Authorization': 'ExtraHop apikey='}

host = ''
url = 'https://' + host + '/api/v1/metrics'

data = {
    "cycle": "30sec",
    "from": -1800000,
    "metric_category": "uri_http_server_detail",
    "object_type": "device",
    "metric_specs": [
        {
            "name": "req"
        }
    ],
    "object_ids": [
        1
    ],
    "until": 0
}

rsp = requests.post(url, data=json.dumps(data), headers=headers, verify=False)
rsp_json = rsp.json()

big_topnset = {}
for time_slice in rsp_json['stats']:
    for entry in time_slice['values'][0]:
        if entry['key']['str'] in big_topnset:
            big_topnset[entry['key']['str']] = big_topnset[entry['key']['str']] + entry['value']
        else:
            big_topnset[entry['key']['str']] = entry['value']

print len(big_topnset.keys())
