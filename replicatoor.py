from flask import Flask, jsonify, request
from nacl.public import PrivateKey, SealedBox, PublicKey
import subprocess
import requests
import requests_unixsocket
import os
import hashlib
from eth_account import Account
from eth_account.messages import encode_defunct
import time
import json
import sys
import base64
import re
from urllib.parse import urlparse

# Untrusted environment values
ETH_RPC_URL = None

# Trusted values read from image
HELIOS_PARAM = os.environ['HELIOS_PARAM']  # e.g., opstack --network base
CONTRACT    = os.environ['CONTRACT']
SECURE_FILE = os.environ['SECURE_FILE']

# Helios light client running as a subprocess
helios_proc = None
def run_lightclient():
    global helios_proc
    assert helios_proc is None
    helios_proc = subprocess.Popen(f"/root/helios {HELIOS_PARAM} --execution-rpc {ETH_RPC_URL}", stdin=None, stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=True, text=True)

# Here's all the key state
global_state = dict(
    myKey = None,
    xPriv = None,
    addr = None,
    bootstrap_quote = None,
    onboard_quote = None,
)

app = Flask(__name__)

def get_dstack_quote(appdata):
    session = requests_unixsocket.Session()
    content = session.post('http+unix://%2Fvar%2Frun%2Ftappd.sock/prpc/Tappd.TdxQuote?json',
                           data=json.dumps(dict(report_data=appdata))).content
    quote = json.loads(content)['quote'][2:] # skip 0x
    return quote

# To get a quote
def get_quote(appdata):
    # Try to use the dstack tappd
    try:
        quote = get_dstack_quote(appdata)
        print(quote, file=sys.stderr)
        return quote
    except requests.exceptions.ConnectionError:
        # Fetch a dummy quote
        appdata = hashlib.sha512(bytes.fromhex(appdata)).hexdigest()
        cmd = f"curl -sk http://ns31695324.ip-141-94-163.eu:10080/attest/{appdata} --output - | od -An -v -tx1 | tr -d ' \n'"
        return subprocess.check_output(cmd, shell=True).decode('utf-8')

def extend_report_data(tag, report_data):
    # Recompute the appdata we're expecting
    s = tag.encode('utf-8') + b":" + report_data
    print('appdata preimage:', s, file=sys.stderr)
    appdata = hashlib.sha256(s).hexdigest()
    return appdata + "00"*32
    
# Verifies the signatures of a quote and returns
# it in a parsed form for further authorization checks
def verify_quote(quote):
    # See run.sh, go run cmd/httpserver/main.go
    url = 'http://localhost:8001/verify'
    resp = requests.post(url, data=bytes.fromhex(quote))

    # Parse out the relevant details
    obj = resp.json()
    header_user_data = base64.b64decode(obj['header']['user_data']).hex()
    report_data = base64.b64decode(obj['td_quote_body']['report_data']).hex()
    mrtd = base64.b64decode(obj['td_quote_body']['mr_td']).hex()
    rtmr0 = base64.b64decode(obj['td_quote_body']['rtmrs'][0]).hex()
    rtmr1 = base64.b64decode(obj['td_quote_body']['rtmrs'][1]).hex()
    rtmr2 = base64.b64decode(obj['td_quote_body']['rtmrs'][2]).hex()
    rtmr3 = base64.b64decode(obj['td_quote_body']['rtmrs'][3]).hex()
    chain = obj['signed_data']['certification_data']['qe_report_certification_data']['pck_certificate_chain_data']['pck_cert_chain']
    FMSPC = extract_fmspc(chain)
    obj['report_data'] = report_data
    obj['fmspc'] = FMSPC
    obj['rtmr0'] = rtmr0
    obj['rtmr1'] = rtmr1
    obj['rtmr2'] = rtmr2
    obj['rtmr3'] = rtmr3
    obj['mrtd'] = mrtd    
    return obj


def extract_fmspc(chain):
    d = base64.b64decode(chain).decode('utf-8')
    first = d.split('-----END CERTIFICATE-----')[0] +\
        '-----END CERTIFICATE-----'
    out = subprocess.check_output('openssl x509 -outform DER -out tmp.der', input=first.encode('utf-8'), shell=True)
    proc = subprocess.Popen('dumpasn1 tmp.der', stdin=None, stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=True, text=True)
    for line in proc.stdout:
        if "OBJECT IDENTIFIER '1 2 840 113741 1 13 1 4'" in line:
            octet_line = next(proc.stdout)
            # Extract hex bytes using regex
            match = re.search(r'OCTET STRING\s+([A-F0-9 ]+)', octet_line)
            if match:
                hex_value = match.group(1).replace(' ', '')
                break
    return hex_value


def is_bootstrapped():
    cmd = f"cast call --rpc-url=localhost:8545 {CONTRACT} 'xPub()'"
    out = subprocess.check_output(cmd, shell=True).decode('utf-8')
    return out.strip() != "0x"+"0"*64

def check_mrtd(mrtd, rtmr0, rtmr3):
    cmd = f"cast call --rpc-url=localhost:8545 {CONTRACT} 'get_mrtd(bytes,bytes,bytes)(bool)' 0x{mrtd} 0x{rtmr0} 0x{rtmr3}"
    out = subprocess.check_output(cmd, shell=True).decode('utf-8')
    return out.strip()

#####################
# Host interface 
#####################
# Called by the host if it's important to bootstrap

# Pass API keys and other arguments from the host
@app.route('/configure', methods=['POST'])
def configure():
    env_data = request.data.decode('utf-8')
    config = {}

    for line in env_data.splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            config[key.strip()] = value.strip()
    print('Received configuration parameters:', config, file=sys.stderr)
    global ETH_RPC_URL
    os.environ['ETH_RPC_URL'] = ETH_RPC_URL = config['ETH_RPC_URL']
    run_lightclient()
    return jsonify({"status": "success", "config": config}), 200

# Return a summary of status
@app.route('/status', methods=['GET'])
def status():
    ip_address = request.remote_addr
    d = dict(caller_address=ip_address)
    
    global global_state
    d.update(global_state)
    
    # Sanitize
    if 'xPriv' in d: del d['xPriv']
    if 'myPriv' in d: del d['myPriv']
    return d

# Request a copy of existing key
@app.route('/requestKey', methods=['POST'])
def requestKey():
    print('Requesting the key...', file=sys.stderr)

    # Generate a private key and a corresponding public key
    private_key = PrivateKey.generate()
    public_key = bytes(private_key.public_key).hex()
    print('public_key:', public_key, file=sys.stderr)

    # Generate a private key and corresponding address
    myPriv = os.urandom(32)

    # Get the quote
    appdata = extend_report_data("request", bytes.fromhex(public_key))
    quote = get_quote(appdata)

    # Store the quote for the host later
    global_state['myPriv'] = bytes(private_key).hex()
    global_state['myPub']  = public_key
    global_state['onboard_quote'] = quote

    return jsonify(dict(quote=quote, pubk=public_key)), 200

@app.route('/onboard', methods=['POST'])
def onboard():
    pubk = request.form['pubk']
    quote = request.form['quote']

    # Verify signature chains in the quote
    obj = verify_quote(quote)
    FMSPC = obj['fmspc']

    # Authorize the MRTD field
    mrtd = obj['mrtd']
    rtmr0 = obj['rtmr0']
    rtmr3 = obj['rtmr3']
    # TODO: anything else to check?
    res = check_mrtd(mrtd, rtmr0, rtmr3)
    if not res == "true":
        print('mrtd failed:', mrtd, rtmr0, rtmr3, file=sys.stderr)
        return "rtmrs check failed", 401

    # Recompute the appdata we're expecting
    print('pubk', pubk, file=sys.stderr)
    ref_report_data = extend_report_data("request", bytes.fromhex(pubk))
    ref_report_data = hashlib.sha512(bytes.fromhex(ref_report_data)).hexdigest()

    # Verify the quote in the blob against expected measurement
    if not obj['report_data'] == ref_report_data:
        return f"Invalid report_data ref:{ref_report_data} val:{obj['report_data']}", 400

    # Encrypt the entire global state as a messsage
    message = open(SECURE_FILE,'rb').read()

    # Encrypt a message using the public key
    p = PublicKey(bytes.fromhex(pubk))
    sealed_box = SealedBox(p)
    encrypted_message = bytes(sealed_box.encrypt(message)).hex()
    return encrypted_message, 200


@app.route('/receiveKey', methods=['POST'])
def receiveKey():
    # Ask the host to get us onboarded
    encrypted_message = bytes.fromhex(request.data.decode('utf-8'))

    # Decrypt the message using the private key
    private_key = bytes.fromhex(global_state['myPriv'])
    unseal_box = SealedBox(PrivateKey(private_key))
    decrypted_message = unseal_box.decrypt(encrypted_message)

    # Write to the file
    with open(SECURE_FILE,'wb') as f:
        f.write(decrypted_message)
        
    return "Loaded encrypted state", 200

@app.errorhandler(404)
def not_found(e):
    return "Not Found", 404

if __name__ == '__main__':
    port = 4001
    if len(sys.argv) == 2:
        port = int(sys.argv[1])
    app.run(host='0.0.0.0', port=port)
