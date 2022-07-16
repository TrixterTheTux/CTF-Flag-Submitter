import json
import threading
import random
from http.server import BaseHTTPRequestHandler, HTTPServer
from pwn import *

# Fix CTRL+C
import signal
signal.signal(signal.SIGINT, signal.SIG_DFL)

def submissions():
    log.info('Running a submission server at port 1337.')

    while True:
        l = listen(1337)
        l.wait_for_connection()

        try:
            l.sendline(b'Welcome to a mock submission server!')
            l.sendline(b'Submit flags by separating them with a newline.')

            while True:
                flag = l.recvline()
                if random.randint(0, 100) < 25:
                    l.sendline(flag.decode().strip().encode() + b' ERR')
                else:
                    l.sendline(flag.decode().strip().encode() + b' OK')

                log.info('Received flag %s.' % flag.decode().strip())
        except:
            l.close()

class WebServer(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({ # https://6.enowars.com/setup
            'availableTeams': ['10.1.%d.1' % i for i in range(5)],
            'services': {},
        }).encode())

def competition():
    log.info('Running a competition webserver at port 1338.')

    webserver = HTTPServer(('127.0.0.1', 1338), WebServer)
    webserver.serve_forever()

def main():
    log.info('Hello world!')

    threading.Thread(target=competition).start()
    threading.Thread(target=submissions).start()

main()