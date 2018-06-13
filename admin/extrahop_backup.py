import argparse
import requests
import json
import shutil

requests.packages.urllib3.disable_warnings()


def parse_args():
    parser = argparse.ArgumentParser(description='Download EXA results.')
    parser.add_argument('-p', '--host', dest='host', help='EDA or ECA Host')
    parser.add_argument('-a', '--apikey', dest='apikey', help='ExtraHop API Key')
    parser.add_argument('-f', '--hostfile', dest='hostfile', help='File containing ECA/EDA hosts-API key KVPs in JSON format. Ignores host and apikey arguments')
    parser.add_argument('-o', '--outdir', dest='outdir', help='Output directory')
    parser.add_argument('-n', '--name', dest='name', help='Backup name')

    return parser.parse_args()


def create_backup(host, apikey, name):
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

    return get_last_backup_info(host, apikey)


def get_last_backup_success(host, apikey):
    headers = {'Content-Type': 'application/json',
               'Accept': 'application/json',
               'Authorization': 'ExtraHop apikey=' + apikey}

    url = 'https://' + host + '/api/v1/customizations/status'
    try:
        rsp = requests.get(url, data=None, headers=headers, verify=False)
    except Exception as e:
        raise e
    if rsp.status_code != 200:
        raise ValueError("cursor returned %s" % rsp.status_code)

    rsp_json = rsp.json()
    return rsp_json['did_last_succeed']


def get_last_backup_info(host, apikey):
    headers = {'Content-Type': 'application/json',
               'Accept': 'application/json',
               'Authorization': 'ExtraHop apikey=' + apikey}

    url = 'https://' + host + '/api/v1/customizations'
    try:
        rsp = requests.get(url, data=None, headers=headers, verify=False)
    except Exception as e:
        raise e
    if rsp.status_code != 200:
        raise ValueError("cursor returned %s" % rsp.status_code)

    rsp_json = rsp.json()
    return rsp_json[-1]


def get_backup(host, apikey, outdir, name, backup_info):
    headers = {'Content-Type': 'application/json',
               'Accept': 'application/x-gzip',
               'Authorization': 'ExtraHop apikey=' + apikey}

    url = 'https://' + host + '/api/v1/customizations/' + str(backup_info['id']) + '/download'
    try:
        rsp = requests.post(url, data=None, headers=headers, verify=False, stream=True)
    except Exception as e:
        raise e
    if rsp.status_code != 200:
        raise ValueError("cursor returned %s" % rsp.status_code)

    filepath = (outdir + '/' if outdir else '') + '%s_%s_%s.gzip' % (host, name, str(backup_info['create_time']))
    with open(filepath, 'wb') as f:
        shutil.copyfileobj(rsp.raw, f)

def single_host_backup(host, apikey, outdir, name):
    backup_info = create_backup(host, apikey, name)
    get_backup(host, apikey, outdir, name, backup_info)


def multi_host_backup(args):
    with open(args.hostfile) as f:
        hosts = json.load(f)

    for host in hosts:
        single_host_backup(host['host'], host['apikey'], args.outdir, args.name)


def main():
    args = parse_args()
    if args.hostfile:
        multi_host_backup(args)
    else:
        single_host_backup(args.host, args.apikey, args.outdir, args.name)



if __name__ == "__main__":
    main()