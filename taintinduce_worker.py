#!/usr/bin/env python

import pyjsonrpc
import argparse
import time
from subprocess import *
from threading import Thread
import taintinduce


class RequestHandler(pyjsonrpc.HttpRequestHandler):
    @pyjsonrpc.rpcmethod
    def infer(self, archstring, bytestring):
        print("Inferring ({}) - {}".format(archstring, bytestring))
        rule = taintinduce.taintinduce_infer(archstring, bytestring)
        return rule

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('local_hostname')
    parser.add_argument('local_port',type=int)
    args = parser.parse_args()

    print("Starting TaintInduce Service...")
    hostname = args.local_hostname
    port = args.local_port
    print("URL: http://{}:{}".format(hostname, port))
    http_server = pyjsonrpc.ThreadingHttpServer(server_address=(hostname, port), RequestHandlerClass = RequestHandler)
    http_server.serve_forever()

if __name__ == '__main__':
    main()
