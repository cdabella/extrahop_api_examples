import argparse
import requests
import json
import shutil

requests.packages.urllib3.disable_warnings()


def parse_args():
    parser = argparse.ArgumentParser(description='Backup ECA and EDA configs programmatically.')
    parser.add_argument('-p', '--host', dest='host', help='EDA or ECA Host')
    parser.add_argument('-a', '--apikey', dest='apikey', help='ExtraHop API Key')
    parser.add_argument('-f', '--hostfile', dest='hostfile', help='File containing ECA/EDA hosts-API key KVPs in JSON format. Ignores host and apikey arguments')
    parser.add_argument('-o', '--outdir', dest='outdir', help='Output directory')
    parser.add_argument('-n', '--name', dest='name', help='Backup name')

    return parser.parse_args()

def create_backup(host, apikey, outfile):
    headers = {'Content-Type': 'application/json',
               'Accept': 'application/json',
               'Authorization': 'ExtraHop apikey=' + apikey}

    url = 'https://' + host + '/api/v1/customizations'
    body = {'name': name}
    try:
        rsp = requests.post(url, data=json.dumps(body), headers=headers, verify=False)
    except Exception as e:
        raise e
    if rsp.status_code != 204:
        raise ValueError("cursor returned %s" % rsp.status_code)

    if not get_last_backup_success(host, apikey):
        raise RuntimeError("Backup '%s' failed")

def main():
    args = parse_args()
    multi_host_backup(args)



if __name__ == "__main__":
    main()