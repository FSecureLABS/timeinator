#!/usr/bin/env python

import random
import SocketServer
import SimpleHTTPServer
import time


class CustomHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", 8)
        self.end_headers()
        if "exists" not in self.path:
            time.sleep(random.random()*0.4)
        self.wfile.write("response")


httpd = SocketServer.ThreadingTCPServer(
    ("", 80), CustomHandler).serve_forever()
