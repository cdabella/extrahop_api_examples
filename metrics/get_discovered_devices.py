import argparse
import requests
import csv
import json
import time

requests.packages.urllib3.disable_warnings()


def parse_args():
    parser = argparse.ArgumentParser(description='Generate list of local discovered devices and IPs ')
    parser.add_argument('-p', '--host', dest='host', help='EDA or ECA Host')
    parser.add_argument('-k', '--apikey', dest='apikey', help='ExtraHop API Key')
    parser.add_argument('-o', '--output', dest='output', help='Output file')
    parser.add_argument('-l', '--lookback', dest='lookback', help='lookback, in days, to query', default=7)

    return parser.parse_args()

def get_discovered_devices(host, apikey, output, lookback):

    active_from = -1 * lookback * 24 * 60 * 60 * 1000   # 7 days in milliseconds
    active_until = 0                        # Current timestamp

    limit = 1000

    device_class_counts = {}
    local_devices = []
    device_ids = []

    headers = {'Content-Type': 'application/json',
               'Accept': 'application/json',
               'Authorization': 'ExtraHop apikey=' + apikey}

    url = 'https://' + host + '/api/v1/devices'
    params = {
        'active_from': active_from,
        'active_until': active_until,
        'limit': limit,
        'offset': 0
              }
    while True:
        try:
            rsp = requests.get(url, params=params, headers=headers, verify=False)
        except Exception as e:
            raise e
        if rsp.status_code != 200:
            raise ValueError("cursor returned %s" % rsp.status_code)

        devices = rsp.json()
        if len(devices) == 0:
            break

        params['offset'] = params['offset'] + limit

        for device in devices:
            device_class = device['device_class']
            device_class_counts[device_class] = 1 + device_class_counts.get(device_class, 0)

            device_ids.append(device['id'])
            if device_class != 'node' or not device['is_l3']:
                continue

            ipaddr = device['ipaddr4'] if device['ipaddr4'] else device['ipaddr6']
            local_devices.append(ipaddr)
    print('##### Device breakdown by type #####')
    print(json.dumps(device_class_counts, indent=4, sort_keys=True))

    if output:
        print('\n\n###### Writing local device list to {} #####'.format(output + '_local_devices.csv'))
        with open(output+ '_local_devices.csv', 'w') as results:
            results.write('ipaddr\n')
            for device in local_devices:
                results.write(device + '\n')
    else:
        print('\n\n###### Local device list #####')
        print(json.dumps(local_devices, sort_keys=True))

    get_observed_ips(host, apikey, output, device_ids, lookback)


def get_observed_ips(host, apikey, output, device_ids, lookback):
    active_from = -1 * lookback * 24 * 60 * 60 * 1000  # 7 days in milliseconds
    active_until = 0  # Current timestamp

    limit = 1000

    headers = {'Content-Type': 'application/json',
               'Accept': 'application/json',
               'Authorization': 'ExtraHop apikey=' + apikey}

    url = 'https://' + host + '/api/v1/metrics/total'

    data = {
        "cycle": "auto",
        "from": active_from,
        "metric_category": "net_detail",
        "metric_specs": [
            {"name": "bytes_in"},
            {"name": "bytes_out"},
        ],
        "object_ids": [],
        "object_type": "device",
        "until": active_until
    }

    chunk_num = 0
    num_devices = len(device_ids)
    devices = {}

    print('\n\n###### Querying {} devices for IP peers #####'.format(num_devices))

    while True:
        data['object_ids'] = device_ids[chunk_num * limit: chunk_num * limit + limit]

        try:
            rsp = requests.post(url, data=json.dumps(data), headers=headers, verify=False)
        except Exception as e:
            raise e
        if rsp.status_code != 200:
            print(data['object_ids'])
            print(chunk_num, limit)
            print(device_ids)
            print("cursor returned %s: %s" % (rsp.status_code, rsp.reason))
            time.sleep(0.5)
            continue

        rsp_json = rsp.json()
        (metric_bytes_in, metric_bytes_out) = rsp_json['stats'][0]['values']

        for entry in metric_bytes_in:
            ipaddr = entry['key']['addr']
            device = devices.get(ipaddr, {'bytes_in': 0, 'bytes_out': 0})
            device['bytes_in'] = device['bytes_in'] + entry['value']
            devices[ipaddr] = device

        for entry in metric_bytes_out:
            ipaddr = entry['key']['addr']
            device = devices.get(ipaddr, {'bytes_in': 0, 'bytes_out': 0})
            device['bytes_out'] = device['bytes_out'] + entry['value']
            devices[ipaddr] = device

        chunk_num += 1
        if chunk_num * limit > num_devices:
            break
        time.sleep(0.5)

    fields = ['ipaddr', 'bytes_in', 'bytes_out']

    if output:
        print('\n\n###### Writing visible IP list to {} #####'.format(output + '_visibile_ips.csv'))
        with open(output + '_visibile_ips.csv', 'w', newline='') as f:
            w = csv.DictWriter(f, fields)
            w.writeheader()
            for k in devices:
                w.writerow({field: devices[k].get(field) or k for field in fields})
    else:
        print('\n\n###### Visible IP list #####')
        print(json.dumps(devices, sort_keys=True))



def main():
    args = parse_args()
    print('##### Getting devices #####\n\n')
    get_discovered_devices(args.host, args.apikey, args.output, args.lookback)



if __name__ == "__main__":
    main()