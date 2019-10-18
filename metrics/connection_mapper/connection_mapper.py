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

def get_l3_devices():
    if verbose:
        print('Querying for L3 devices...')
    offset = 0
    query_limit = 100

    devices = []

    while True:
        url = 'https://' + host + '/api/v1/devices?' +   \
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


def get_internal_network():
    if verbose:
        print('Querying for Network Localities')
    url = 'https://' + host + '/api/v1/networklocalities'
    rsp = requests.get(url, headers=headers, verify=disableCertCheck)
    rsp_json = rsp.json()

    internal_networks = []
    for network in rsp_json:
        if network['external']:
            continue
        internal_networks.append(ipaddress.ip_interface(network['network']).network)

    if verbose:
        print('Found {:d} internal networks\n'.format(len(internal_networks)))

    return internal_networks

def connections_to_csv(connections, counter):
    filename = os.path.join(path, name + "-" + "{:04d}".format(counter) + ".csv")
    with open(filename, "w") as f:
        f.write('client,server\n')
        for client,servers in connections.items():
            for server in servers:
                f.write(client + ',' + server + '\n')


def main():
    makePath(path)

    devices = get_l3_devices()
    internal_networks = get_internal_network()

    url = 'https://' + host + '/api/v1/metrics'

    until = 0
    step_size = 2  # window size in hours

    connections = {}

    while lookback >= until + step_size:
        print_status_bar(until, lookback)
        for device in devices:

            # Should always be valid as we filtered for l3 devices
            device_ip = device['ipaddr4'] if device['ipaddr4'] else device['ipaddr6']

            data = {
                "cycle": "auto",
                "until": '-' + str(until) + 'h',
                "from": '-' + str(until + lookback) + 'h',
                "metric_category": "tcp_detail",
                "object_type": "device",
                "metric_specs": [
                    {
                        "name": "connected"
                    },
                    {
                        "name": "accepted"
                    }
                ],
                "object_ids": [
                    device['id']
                ]
            }

            rsp = requests.post(url, data=json.dumps(data), headers=headers, verify=disableCertCheck)
            rsp_json = rsp.json()

            device_is_internal = is_internal(device_ip, internal_networks)

            for time_slice in rsp_json['stats']:
                # connected
                for entry in time_slice['values'][0]:
                    if is_internal(entry['key']['addr'], internal_networks) and device_is_internal:
                        continue
                    if device_ip in connections:
                        connections[device_ip].add(entry['key']['addr'])
                    else:
                        connections[device_ip] = set([entry['key']['addr']])

                # accepted
                for entry in time_slice['values'][1]:
                    if is_internal(entry['key']['addr'], internal_networks) and device_is_internal:
                        continue

                    if entry['key']['addr'] in connections:
                        connections[entry['key']['addr']].add(device_ip)
                    else:
                        connections[entry['key']['addr']] = set([device_ip])

        if (until + step_size) % 24 == 0:
            connections_to_csv(connections, int((until + step_size) / 24))
            connections = {}
        until += 2

if __name__ == '__main__':
    main()
