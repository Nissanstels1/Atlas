"""Disposable HTTPS 204 endpoint for the OpenWrt snapshot integration tests."""
import http.server
import ssl
import sys

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(204 if self.path == '/generate_204' else 404)
        self.end_headers()
    def log_message(self, *args):
        pass

server = http.server.ThreadingHTTPServer(('0.0.0.0', 19443), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(sys.argv[1], sys.argv[2])
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
