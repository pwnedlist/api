#!/usr/bin/env python2.7

import hashlib
import hmac
import time
import pprint
import argparse
import json
import requests
from Crypto.Cipher import AES
import base64
import binascii

# Default verbosity is very quiet
VERBOSITY = 1

# Set to AES 128
AES.key_size = 128

# Some static vars
API_STATUS_OK = 200
API_STATUS_BAD_PARAM = 400
API_STATUS_BAD_AUTH = 403
API_STATUS_NOT_FOUND = 404
API_STATUS_TOO_MANY_REQUESTS = 503
API_STATUS_QUOTA_EXCEEDED = 507

# DEBUG
import logging

# These two lines enable debugging at httplib level (requests->urllib3->http.client)
# You will see the REQUEST, including HEADERS and DATA, and RESPONSE with HEADERS but without DATA.
# The only thing missing will be the response.body which is not logged.
try:
    import http.client as http_client
except ImportError:
    # Python 2
    import httplib as http_client
http_client.HTTPConnection.debuglevel = 1

# You must initialize logging, otherwise you'll not see debug output.
logging.basicConfig() 
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True
# END DEBUG


def retry(exceptiontocheck, tries=3, delay=3, backoff=2):
    """
    Retry decorator that let's us retry API calls multiple times before failing.
    Used in case of timeouts or service related problems.
    """

    def deco_retry(f):
        def f_retry(*args, **kwargs):
            mtries, mdelay = tries, delay
            try_one_last_time = True
            while mtries > 1:
                try:
                    return f(*args, **kwargs)
                    try_one_last_time = False
                    break
                except exceptiontocheck, e:
                    time.sleep(mdelay)
                    mtries -= 1
                    mdelay *= backoff
            if try_one_last_time:
                return f(*args, **kwargs)
            return

        return f_retry  # true decorator

    return deco_retry


def verbose(msg, verb):
    """
    Print verbose output based on value of VERBOSITY.
    """
    if VERBOSITY >= verb:
        print msg


def print_error_code(error_code):
    tbl = {
        '400': 'Bad argument. One of your arguments was invalid, or you failed to set a required argument. '
               'Check API documentation.',
        '403': 'Bad authentication request (wrong API key, old timestamp...). '
               'Check your key and/or secret parameters if you get this error.',
        '404': 'Object not found at the specified path. Check your API method path (--path argument)?',
        '405': 'Request method not expected (should be GET or POST).',
        '503': 'Client is making too many requests and is being rate limited.',
        '507': 'Client is over their API usage quota.'
    }

    error_str = str(error_code)
    if error_str in tbl:
        verbose("ERROR: %s" % tbl[error_str], 1)
    else:
        verbose("ERROR: Unknown server error", 1)


class ApiRequest:
    """
    Wrapper that creates PwnedList API requests for you. Properly assembles the payload with HMAC.
    """
    # Required for decryption of any encrypted data.
    __iv = "4r72=N>#/927643r"

    def __init__(self):
        pass

    @retry(Exception, tries=3)
    def make_request(self, request_url, method_name, payload, api_key, api_secret, request_method='GET'):
        """
        Executes a HTTP request against the API servers given the URL of the method to be executed,
        the payload (method arguments) and the request method (GET/POST).
        """
        # First we want to finish building the payload by adding required params via build_payload()
        exec_payload = self.build_payload(payload, method_name, api_key, api_secret)

        # Next, execute the request
        if request_method == 'GET':
            r = requests.get(request_url, params=exec_payload, verify=True)
        elif request_method == 'POST':
            r = requests.post(request_url, params=exec_payload, verify=True)
        else:
            raise NotImplemented("Request method '%s' has not yet been implemented." % request_method)

        # Build the response dictionary and return it
        answer = {
            'url': r.url,
            'size': len(r.text),
            'content': r.text,
            'status_code': r.status_code
        }
        return answer

    def build_payload(self, old_payload, method, api_key, api_secret):
        """
        This method augments a given payload to add parameters required by the PwnedList API service.
        There are 3 parameters which are required to be part of every API call: API_KEY, TIMESTAMP and HMAC.
        """
        old_payload['ts'] = int(time.time())
        old_payload['key'] = api_key
        old_payload['hmac'] = self.gen_hmac(method, old_payload['ts'], api_key, api_secret)
        return old_payload

    @staticmethod
    def gen_hmac(method, timestamp, api_key, api_secret):
        """
        Generate HMAC string for PwnedList API service. The string is generated as follows:
        hmac('sha1', 'API_KEY' + 'TIMESTAMP' + 'METHOD_NAME', 'API_SECRET')
        """
        msg = "%s%s%s%s" % (api_key, timestamp, method, api_secret)
        hm = hmac.new(api_secret, msg, hashlib.sha1)
        return hm.hexdigest()

    @staticmethod
    def pkcs7_unpad(text, blocksize=16):
        nl = len(text)
        val = int(binascii.hexlify(text[-1]), 16)
        if val > blocksize:
            raise ValueError('Input is not padded or padding is corrupt')
        l = nl - val
        return text[:l]

    def decrypt(self, plain, key):
        crypt_object = AES.new(key=key, mode=AES.MODE_CBC, IV=self.__iv)
        decoded = base64.b64decode(plain)
        decrypted = crypt_object.decrypt(decoded)
        return self.pkcs7_unpad(decrypted)


def run_method(args):
    """
    This methods performs a query using the PwnedList API.
    """
    # Create an ApiRequest instance
    api = ApiRequest()

    method_url_path = args.path.replace('.', '/')

    verbose("METHOD: %s" % method_url_path, 4)
    verbose("PAYLOAD: %s" % args.payload, 4)

    # Load JSON string into a dictionary
    payload = json.loads(args.payload)

    # Make the request and store the results
    r = api.make_request(args.api_url + "/" + method_url_path, args.path, payload, args.api_key, args.api_secret,
                         request_method=args.http_method)
    try:

        resp = json.loads(r['content'])
        verbose("RAW SERVER RESPONSE: %s" % r['content'], 5)

        # Decrypt passwords for certain API method calls
        if args.path == 'accounts.query':
            for a in resp['results']:
                if 'password' in a:
                    a['password'] = str(api.decrypt(a['password'], args.api_secret[:16]))
        elif args.path == 'domains.query':
            for a in resp['accounts']:
                if 'password' in a:
                    a['password'] = str(api.decrypt(a['password'], args.api_secret[:16]))
        elif args.path == 'leaks.get':
            for a in resp['accounts']:
                if 'password' in a:
                    a['password'] = str(api.decrypt(a['password'], args.api_secret[:16]))
        elif args.path == 'reports.get':
            for a in resp['accounts']:
                if 'password' in a:
                    a['password'] = str(api.decrypt(a['password'], args.api_secret[:16]))

        # Pretty print the response output (assuming its valid JSON data)
        pp.pprint(resp)

    except Exception as e:
        print_error_code(r['status_code'])


#
# MAIN Main main
#
if __name__ == "__main__":
    # Parse command line args
    parser = argparse.ArgumentParser(description="Test the PwnedList RESTful API service", epilog="And we're done.")

    parser.add_argument('-v', '--verbosity',
                        action='store',
                        type=int,
                        choices=xrange(1, 5),
                        dest='verbosity',
                        default=3,
                        metavar='LEVEL',
                        help='Set level of verbosity. Acceptable levels: %(choices)s.')
    parser.add_argument('-u', '--url',
                        action='store',
                        type=str,
                        default='https://api.pwnedlist.com/api/1',
                        dest='api_url',
                        metavar='API_URL',
                        required=True,
                        help='URL for the API service.')
    parser.add_argument('-k', '--key',
                        action='store',
                        type=str,
                        default=None,
                        dest='api_key',
                        metavar='API_KEY',
                        required=True,
                        help='API key. Equivalent to a username for the service.')
    parser.add_argument('-s', '--secret',
                        action='store',
                        type=str,
                        default=None,
                        dest='api_secret',
                        metavar='API_SECRET',
                        required=True,
                        help='API secret. This is the password for the service.')
    parser.add_argument('-t', '--httpmethod',
                        action='store',
                        choices=['GET', 'POST'],
                        default='GET',
                        dest='http_method',
                        metavar='HTTP_METHOD',
                        help='HTTP method to be used. Choices: %(choices)s.')
    parser.add_argument('--path',
                        action='store',
                        type=str,
                        default=None,
                        dest='path',
                        metavar='PATH',
                        required=True,
                        help='API method path. Examples: domains.query, leaks.info, accounts.query, etc.')
    parser.add_argument('--payload',
                        action='store',
                        type=str,
                        default=None,
                        dest='payload',
                        metavar='payload',
                        required=True,
                        help='Method payload. This must be a JSON encoded Python dictionary.')

    args = parser.parse_args()

    # Set verbosity
    VERBOSITY = args.verbosity

    # We're going to pretty print returned data
    pp = pprint.PrettyPrinter(indent=4)

    # Run
    run_method(args)
