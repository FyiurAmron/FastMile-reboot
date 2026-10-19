#!/usr/bin/env python3
"""Log in to the Nokia FastMile web UI and report the Reboot CGI endpoint.

This script performs the FWA login flow, extracts the session id (sid) and
csrf token, and sends the Reboot CGI request, printing the request and
response details.
"""
import base64
import hashlib
import json
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asympadding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import urllib.request
import urllib.parse

BASE = "http://192.168.1.1"
CRED_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "credentials.txt")


def read_creds(path):
    with open(path) as f:
        lines = [ln.strip() for ln in f if ln.strip()]
    if len(lines) < 2:
        raise SystemExit("credentials file must contain username and password")
    return lines[0], lines[1]


def e_func(s):
    return s.replace("+", "-").replace("/", "_").replace("=", ".")


def h_func(r, k):
    return base64.b64encode(hashlib.sha256((r + ":" + k).encode()).digest()).decode()


def sha256url(r, k):
    return e_func(h_func(r, k))


def b64url_nopad(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()



def encrypt_post_data(pubkey_pem, plaintext):
    pubkey = serialization.load_pem_public_key(pubkey_pem.encode())
    key = os.urandom(16)
    iv = os.urandom(16)
    # PKCS#7
    pad = 16 - (len(plaintext.encode()) % 16)
    padded = plaintext.encode() + bytes([pad]) * pad
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    ct = enc.update(padded) + enc.finalize()
    q = base64.b64encode(key).decode() + " " + base64.b64encode(iv).decode()
    rsa_ct = pubkey.encrypt(q.encode(), asympadding.PKCS1v15())
    ck = e_func(base64.b64encode(rsa_ct).decode())
    return "encrypted=1&ct=" + b64url_nopad(ct) + "&ck=" + ck

def post(url, data, content_type="application/x-www-form-urlencoded", headers=None):
    req = urllib.request.Request(url, data=data.encode(), method="POST")
    req.add_header("Content-Type", content_type)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    with urllib.request.urlopen(req) as resp:
        return resp.status, dict(resp.headers), resp.read().decode()


def main():
    username, password = read_creds(CRED_FILE)

    # 1. nonce
    status, headers, body = post(
        BASE + "/login_web_app.cgi?nonce",
        "userName=" + urllib.parse.quote(username),
    )
    nonce_json = json.loads(body)
    nonce = nonce_json["nonce"]
    random_key = nonce_json["randomKey"]
    pubkey_pem = nonce_json["pubkey"]
    iterations = nonce_json.get("iterations", 1)

    # 2. salt (FWA)
    userhash = sha256url(username, nonce)
    status, headers, body = post(
        BASE + "/login_web_app.cgi?salt",
        f"userhash={userhash}&nonce={e_func(nonce)}",
    )
    salt_json = json.loads(body)
    alati = ""
    if isinstance(salt_json, dict):
        if "alati" in salt_json:
            alati = salt_json["alati"]
        elif isinstance(salt_json.get("data"), dict):
            alati = salt_json["data"].get("alati", "")

    # 3. build FWA password hash
    if iterations >= 1:
        j = hashlib.sha256((alati + password).encode()).hexdigest()
    else:
        j = alati + password
    for _ in range(1, iterations):
        j = hashlib.sha256(bytes.fromhex(j)).hexdigest()

    z = h_func(username, j.lower())
    se = sha256url(z, nonce)
    q = sha256url(random_key, nonce)

    dec_key = base64.b64encode(os.urandom(16)).decode()
    dec_iv = base64.b64encode(os.urandom(16)).decode()
    enckey = e_func(dec_key)
    enciv = e_func(dec_iv)

    post_data = (
        f"userhash={userhash}&RandomKeyhash={q}&response={se}"
        f"&nonce={e_func(nonce)}&enckey={enckey}&enciv={enciv}"
    )

    # 4. login (this is the only mutating auth request we actually send)
    status, headers, body = post(BASE + "/login_web_app.cgi", post_data)
    login_json = json.loads(body)
    print("LOGIN RESULT:", login_json)

    sid = login_json.get("sid") or headers.get("X-SID")
    token = login_json.get("token")
    cookie = headers.get("Set-Cookie", "")
    print("SID:", sid)
    print("TOKEN:", token)
    print("COOKIE:", cookie)

    # 5. Execute reboot via CGI (user-initiated)
    reboot_url = BASE + "/reboot_web_app.cgi"
    reboot_plaintext = f"csrf_token={token}"
    body = encrypt_post_data(pubkey_pem, reboot_plaintext)
    print("\n--- EXECUTING REBOOT ---")
    print("URL:", reboot_url)
    print("METHOD: POST")
    print("BODY:", body)
    status, headers, resp_body = post(reboot_url, body, headers={"Cookie": f"sid={sid}"})
    print("STATUS:", status)
    print("RESPONSE:", resp_body)


if __name__ == "__main__":
    main()
