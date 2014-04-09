api
===

Provides an open-source Python client for the PwnedList API services.

Requirements:
- Python 2.7+
- Python Requests Library - http://docs.python-requests.org/en/latest/index.html
- Python Crypto Module - https://www.dlitz.net/software/pycrypto/

This script allows users to easily run calls against the API without the cumbersome details of properly building
HTTP requests and handling the return data. All the user needs to provide (besides the credentials) is the --path
and --payload parameters. --path is the name of the method you want to call, such as "domains.info" or "accounts.query".
--payload parameter is a JSON encoded dictionary object representing a list of key-value pairs to be passed to the API.
These are the API method arguments.

Example usage:
python2.7 ./pl-api-client.py \
    --key="YOURKEY" \
    --secret="YOURSECRET" \
    --path="domains.info" \
    --payload='{"domain_identifier":"DOMAIN.COM"}'

# Result output:
# {
#   u'domain': u'gmail.com',
#   u'first_seen': u'2007-09-04 00:00:00',
#   u'last_seen': u'2012-10-17 00:00:00',
#   u'num_entries': 2155000
# }
