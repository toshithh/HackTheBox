#!/usr/bin/env python3
import hmac
import hashlib
import json
import requests

# === CHANGE THESE FOR YOUR CASE ===
secret = b"3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS"
url = "http://28efa8f7df.whiterabbit.htb/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d"
# ==================================

def sign_and_send(payload_dict):
    # Match n8n's body exactly — no spaces, sorted keys
    body = json.dumps(payload_dict, separators=(',', ':'))
    sig = hmac.new(secret, body.encode(), hashlib.sha256).hexdigest()
    sig_header = f"sha256={sig}"

    headers = {
        "Content-Type": "application/json",
        "x-gophish-signature": sig_header
    }

    print("[+] Sending body:", body)
    print("[+] Signature   :", sig_header)
    r = requests.post(url, headers=headers, data=body)
    print("[+] Status      :", r.status_code)
    print("[+] Response    :", r.text)

if __name__ == "__main__":
    # Example payload
    payload = {
        "campaign_id": 1,
        "email": "test@ex.com",
        "message": "Clicked Link"
    }
    sign_and_send(payload)
