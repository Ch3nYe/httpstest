import os
import sys
import ssl
from http.server import HTTPServer, BaseHTTPRequestHandler

#服务端证书和私钥
serverCerts = "%s\\certs\\server-cert.cer" % os.getcwd()
serverKey = "%s\\certs\\server-key.key" % os.getcwd()
#客户端证书
clientCerts = "%s\\certs\\client-cert.cer" % os.getcwd()

class RequestHandler(BaseHTTPRequestHandler):
    def _writeheaders(self):
        self.send_response(200)
        self.send_header('Content-type','text/plain')
        self.end_headers()
    def do_GET(self):
        self._writeheaders()
        self.wfile.write("OK".encode("utf-8"))

def main():
    if (len(sys.argv) != 2):
        port = 443
    else:
        port = sys.argv[1]
    server_address = ("0.0.0.0", int(port))
    server = HTTPServer(server_address, RequestHandler)
    #双向校验
    server.socket = ssl.wrap_socket(server.socket, certfile = serverCerts, server_side = True,  
                               keyfile = serverKey,
                               cert_reqs = ssl.CERT_REQUIRED,
                               ca_certs = clientCerts
                               )
    print("Starting server, listen at: %s:%s" % server_address)
    server.serve_forever()

if __name__ == "__main__":
    main()