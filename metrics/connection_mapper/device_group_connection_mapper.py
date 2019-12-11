'''
Capture all inbound and outbound connections to external resources and write
out in CSV format.

@author: abella
@created: 2019/10/17
@notes:
'''
import argparse
import configparser

# TODO add logging
# TODO add config file support
import os
import logging
import sys
import time

import ipaddress

import json
import ssl
import requests


# TODO move this to a function
parser = argparse.ArgumentParser(
    description='Capture all inbound and outbound connections to external resources and write out in CSV format.')
parser.add_argument('-v', '--verbose', action="store_true", default=False,
                    help='Print debug to console.')
parser.add_argument('-k', '--disable-cert-check', action="store_false", default=True,
                    help='Disable certificate validation')
parser.add_argument('-H', '--host', default=None,
                    help="Hostname or IP Address of extrahop. ")
parser.add_argument('-a', '--apikey',
                    help="API Key of Extrahop.  Used with --host option")
parser.add_argument('-p', '--path', default=None,
                    help="Location path to write CSVs. ")
parser.add_argument('-o', '--outfile', default=None,
                    help="CSV base filename")
parser.add_argument("-l", '--lookback', type=int, default=0,
                    help="Number of days from present from which to gather data.")
parser.add_argument('-g', '--group', default=None,
                    help="Device group API ID")
args = parser.parse_args()

#Build argument variables
verbose = args.verbose
disableCertCheck = args.disable_cert_check
if not disableCertCheck:
    requests.packages.urllib3.disable_warnings()
host = args.host
api_key = args.apikey
path = args.path
name = args.outfile
lookback = args.lookback * 24  # Convert days to hours
group_id = args.group

headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Authorization': 'ExtraHop apikey=' + api_key
}

def makePath(path):
    if not os.path.exists(path):
        os.makedirs(path)

def print_status_bar(numerator, denominator):
    assert denominator > 0, 'Denominator cannot be zero'
    progress = float(numerator)/denominator * 100
    sys.stdout.write("\r%.2f%%" % progress)
    sys.stdout.flush()

def is_internal(ipaddr, internal_networks):
    ip = ipaddress.ip_address(ipaddr)
    for network in internal_networks:
        if ip in network:
            return True
    return ip.is_private

def get_group_devices(id):
    if verbose:
        print('Querying for L3 devices in group ' + id + '...')
    offset = 0
    query_limit = 100

    devices = []

    while True:
        url = 'https://' + host + '/api/v1/devicegroups/' + id + '/devices?' + \
                'limit=' + str(query_limit) + '&' +      \
                'offset=' + str(offset) + '&' +          \
                'active_from=-' + str(lookback) + 'h&' + \
                'active_until=0'

        rsp = requests.get(url, headers=headers, verify=disableCertCheck)
        rsp_json = rsp.json()

        devices += filter(lambda device: device['analysis_level'] != 0, filter(lambda device: device['is_l3'] == True, rsp_json))

        if len(rsp_json) < query_limit:
            break

        offset += query_limit

    if verbose:
        print('Found {:d} devices\n'.format(len(devices)))

    return devices


def connections_to_csv(connections, counter):
    filename = os.path.join(path, name + "-" + "{:04d}".format(counter) + ".csv")
    with open(filename, "w") as f:
        f.write('Peer 1,Peer 2,L7 Protocol,Bytes In,Bytes Out\n')
        for ip1, peers in connections.items():
            for ip2, l7protos in peers.items():
                for l7proto, bytes in l7protos.items():
                    f.write((f"{ip1},{ip2},{l7proto},"
                            f"{bytes['bytes_in']},{bytes['bytes_out']}\n"))


def main():
    makePath(path)

    devices = get_group_devices(group_id)

    url = 'https://' + host + '/api/v1/metrics'

    until = 0
    step_size = 2  # window size in hours

    connections = {}

    while lookback >= until + step_size:
        print_status_bar(until, lookback)
        completed_devices = set()
        for device in devices:

            # Should always be valid as we filtered for l3 devices
            device_ip = device['ipaddr4'] if device['ipaddr4'] else device['ipaddr6']

            data = {
                "cycle": "auto",
                "until": '-' + str(until) + 'h',
                "from": '-' + str(until + lookback) + 'h',
                "metric_category": "app_detail",
                "object_type": "device",
                "metric_specs": [
                    {
                        "name": "bytes_in"
                    },
                    {
                        "name": "bytes_out"
                    }
                ],
                "object_ids": [
                    device['id']
                ]
            }

            rsp = requests.post(url, data=json.dumps(data), headers=headers, verify=disableCertCheck)
            rsp_json = rsp.json()

            # print(rsp_json)

            for time_slice in rsp_json['stats']:
                # bytes_in
                for entry in time_slice['values'][0]:
                    l7proto = entry['key']['str']
                    for peer in entry['value']:
                        peer_id = peer['key']['device_oid'] if 'device_oid' in peer['key'] else None
                        if peer_id in completed_devices:
                            continue
                        peer_ip = peer['key']['addr']
                        peer_bytes = peer['value']
                        ip1 = peer_ip if peer_ip < device_ip else device_ip
                        ip2 = peer_ip if ip1 == device_ip else device_ip
                        if ip1 in connections:
                            if ip2 in connections[ip1]:
                                if l7proto in connections[ip1][ip2]:
                                    connections[ip1][ip2][l7proto]['bytes_in'] = connections[ip1][ip2][l7proto]['bytes_in'] + peer_bytes
                                else:
                                    connections[ip1][ip2][l7proto] = {
                                        'bytes_in' : peer_bytes,
                                        'bytes_out' : 0
                                    }
                            else:
                                connections[ip1][ip2] = {
                                    l7proto : {
                                        'bytes_in' : peer_bytes,
                                        'bytes_out' : 0
                                    }
                                }
                        else:
                            connections[ip1] = {
                                ip2: {
                                    l7proto : {
                                        'bytes_in' : peer_bytes,
                                        'bytes_out' : 0
                                    }
                                }
                            }

                # bytes_out
                for entry in time_slice['values'][1]:
                    l7proto = entry['key']['str']
                    for peer in entry['value']:
                        peer_id = peer['key']['device_oid'] if 'device_oid' in peer['key'] else None
                        if peer_id in completed_devices:
                            continue
                        peer_ip = peer['key']['addr']
                        peer_bytes = peer['value']
                        ip1 = peer_ip if peer_ip < device_ip else device_ip
                        ip2 = peer_ip if ip1 == device_ip else device_ip
                        if ip1 in connections:
                            if ip2 in connections[ip1]:
                                if l7proto in connections[ip1][ip2]:
                                    connections[ip1][ip2][l7proto]['bytes_out'] = connections[ip1][ip2][l7proto]['bytes_out'] + peer_bytes
                                else:
                                    connections[ip1][ip2][l7proto] = {
                                        'bytes_in' : 0,
                                        'bytes_out' : peer_bytes
                                    }
                            else:
                                connections[ip1][ip2] = {
                                    l7proto : {
                                        'bytes_in' : 0,
                                        'bytes_out' : peer_bytes
                                    }
                                }
                        else:
                            connections[ip1] = {
                                ip2: {
                                    l7proto : {
                                        'bytes_in' : 0,
                                        'bytes_out' : peer_bytes
                                    }
                                }
                            }

            completed_devices.add(device['id'])
        if (until + step_size) % 24 == 0:
            connections_to_csv(connections, int((until + step_size) / 24))
            connections = {}
        until += 2

if __name__ == '__main__':
    main()
