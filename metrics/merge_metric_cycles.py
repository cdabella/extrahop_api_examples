import requests
import json

requests.packages.urllib3.disable_warnings()

############################ USER CONFIGURATIONS ###############################
api_key = ''
host = ''

use_relative_time = False
relative_time = -30 * 60 * 1000             # 30min in ms
absolute_timestamp_start = 1523318400000    # April 10th, 2018 00:00:00
absolute_timestamp_end = 0                  # Current time

metric_category = "ica_user_detail"
object_type = "application"
metric_spec_name = "app_launches"
########################## END USER CONFIGURATIONS #############################

headers = {'Content-Type': 'application/json',
           'Accept': 'application/json',
           'Authorization': 'ExtraHop apikey=' + api_key}


url = 'https://' + host + '/api/v1/metrics'

if use_relative_time:
    data = {
        "cycle": "auto",
        "from": relative_time,
        "metric_category": metric_category,
        "object_type": object_type,
        "metric_specs": [
            {
                "name": metric_spec_name
            }
        ],
        "object_ids": [
            0
        ],
        "until": 0
    }
else:  # Use absolute start time
    data = {
        "cycle": "auto",
        "from": absolute_timestamp_start,
        "metric_category": metric_category,
        "object_type": object_type,
        "metric_specs": [
            {
                "name": metric_spec_name
            }
        ],
        "object_ids": [
            0
        ],
        "until": absolute_timestamp_end

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
