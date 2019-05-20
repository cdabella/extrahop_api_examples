import requests
from pprint import pprint

requests.packages.urllib3.disable_warnings()


def main():
    host = ''
    api_key = ''

    url = 'https://' + host + '/api/v1/dashboards'

    headers = {
        'Accept': 'application/json',
        'Authorization': 'ExtraHop apikey=' + api_key,
        }

    response = requests.get(url, verify=False, headers=headers)
    pprint(response.json())


if __name__ == '__main__':
    main()

