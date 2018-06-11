import argparse
import requests
import httplib
import ssl
import json
import os
import sys

import urllib3
requests.packages.urllib3.disable_warnings()

# With the given host and apikey, run the given query and put the results
# in the given directory (which must not yet exist, or be empty if it does).
# The query is run against the REST API search endpoint, and we then continue
# to get more results using the cursor endpoint.

# Works best with queries that have absolute time ranges.

parser = argparse.ArgumentParser(description='Download EXA results.')
parser.add_argument('host', help='EDA or ECA Host')
parser.add_argument('apikey', help='ExtraHop API Key')
parser.add_argument('query', help='EXA query')
parser.add_argument('outdir', help='Output directory')

args = parser.parse_args()

headers = {'Content-Type': 'application/json',
           'Accept': 'application/json',
           'Authorization': 'ExtraHop apikey=' + args.apikey}

context_ttl = 5 * 60 * 1000  # 5 minutes


def writefile(counter, contents):
    with open(os.path.join(args.outdir, "%s.json" % counter), "wb") as outfile:
        outfile.write(contents)

# check/set up outdir. be careful not to stomp on preexisting files.
if os.path.exists(args.outdir):
    if not os.path.isdir(args.outdir):
        sys.exit("outdir exists but is not a directory")
    else:
        if os.listdir(args.outdir):
            sys.exit("outdir exists but is not empty")
else:
    os.mkdir(args.outdir)

# fix up query: override context ttl and limit
try:
    query = json.loads(args.query)
except ValueError:
    sys.exit("query must be valid JSON")
query["context_ttl"] = context_ttl
query["limit"] = 1000
query["from"] = 1523318400000
query["until"] = 0

print "Saving results to", args.outdir

# initial search
print 'Running initial query...'
url = 'https://' + args.host + '/api/v1/records/search'
rsp = requests.post(url, data=json.dumps(query), headers=headers, verify=False)
if rsp.status_code != 200:
    sys.exit("initial query failed (%s): %s" % (rsp.status_code, rsp_body))

rsp_json = rsp.json()

cursor = rsp_json.get("cursor")
if not cursor:
    sys.exit("No cursor returned. Upgrade your EDA/ECA.")

print "Initial query reports a total of %s records" % rsp_json["total"]

counter = 1
running_total = len(rsp_json["records"])
writefile(counter, json.dumps(rsp_json))

# cursor search. do these until error or no more results.
sys.stdout.write('Running cursor queries...')

while True:
    url = 'https://' + args.host + '/api/v1/records/cursor/%s?context_ttl=%s' % (cursor, context_ttl)
    sys.stdout.write('.')
    sys.stdout.flush()
    try:
        rsp = requests.get(url, data=json.dumps(query), headers=headers, verify=False)
    except Exception as e:
        print "request exception: %s" % e
        break
    if rsp.status_code != 200:
        print "cursor returned %s" % rsp.status_code
        break
    rsp_json = rsp.json()
    num_records = len(rsp_json["records"])
    if not num_records:
        print "done"
        break
    cursor = rsp_json["cursor"]
    counter += 1
    running_total += num_records
    writefile(counter, json.dumps(rsp_json))

print "Downloaded %s records to %s file(s)" % (running_total, counter)
