#!/usr/bin/python

from OpenSSL import crypto
import requests
from http.server import HTTPServer, SimpleHTTPRequestHandler,BaseHTTPRequestHandler
import ssl
import os
import fire




def createkey(domain, output_dir):
    print("[*] Creating directory {}".format(output_dir))
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    print("[*] Generating key for domain {}...".format(domain))
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    req = crypto.X509Req()
    #req.get_subject().CN = domain
    
    req.set_pubkey(key)
    req.sign(key, "sha256")

    cert = crypto.X509()
    cert.set_serial_number(1000)
    # cert.get_subject().CN = domainz
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
    cert.set_issuer(req.get_subject())
    cert.set_subject(req.get_subject())
    cert.set_pubkey(req.get_pubkey())
    cert.sign(key, "sha256")

    with open(output_dir+"/key.pem", "wb") as key_file:
        key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    with open(output_dir+"/cert.pem", "wb") as cert_file:
        cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))


class ProxyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        url = self.path[1:]
        if "Host" in self.headers:
            url = "https://"+self.headers["Host"]+url
        print(f"URL: {url}")
        try:
            response = requests.get(url)
            self.send_response(response.status_code)
            for header, value in response.headers.items():
                self.send_header(header, value)
            self.end_headers()
            self.wfile.write(response.content)
        except Exception as e:
            self.send_error(500, str(e))


def runserver(cert_file, private_key):

    
    port = 443
    server_address = ("0.0.0.0", port)
    certfile = cert_file
    keyfile = private_key
    print(certfile)
    #httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)
    httpd = HTTPServer(server_address, ProxyHandler)

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)


    httpd.socket = context.wrap_socket(httpd.socket)

    print(f"HTTPS Server running on port {port}...")
    httpd.serve_forever()

def main_menu():
    print("[1] Start server")
    print("[2] Create key")
    print("")
    return input("> ")

def interactive():
    print("HTTP Server")
    print("")
    menu = int(main_menu())
    if menu == 1:
        certfile = input("Certfile (cert.pem): ")
        private_key = input("Private Key (key.pem): ")
        
        if not certfile:
            certfile = "cert.pem"
        
        if not private_key:
            private_key = "key.pem"

        runserver(certfile, private_key)


if __name__ == "__main__":
    fire.Fire({"createkey": createkey, 
               "runserver": runserver,
               "interactive": interactive
               })