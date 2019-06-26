#!/usr/bin/env python2

import argparse

import pyjsonrpc
import service_core

parser = argparse.ArgumentParser()
parser.add_argument('hostname')
parser.add_argument('port')
args = parser.parse_args()

class RequestHandler(pyjsonrpc.HttpRequestHandler):

    @pyjsonrpc.rpcmethod
    def _gen_observation(self, bytestring, arch_string):
        return service_core._gen_observations(bytestring, arch_string)

    @pyjsonrpc.rpcmethod
    def _get_rule(self, bytestring, arch_string):
        return service_core._get_rule(bytestring, arch_string)

    @pyjsonrpc.rpcmethod
    def _get_rule_info(self, bytestring, arch_string):
        return service_core._get_rule_info(bytestring, arch_string)

    @pyjsonrpc.rpcmethod
    def _get_rule_b64(self, bytestring, arch_string):
        return service_core._get_rule_b64(bytestring, arch_string)

    @pyjsonrpc.rpcmethod
    def _get_rules(self):
        return service_core._get_rules()

    @pyjsonrpc.rpcmethod
    def view_jobs(self):
        return service_core.view_jobs()

    @pyjsonrpc.rpcmethod
    def view_obs_jobs(self):
        return service_core.view_obs_jobs()

    @pyjsonrpc.rpcmethod
    def view_obs(self, bytestring, arch_string):
        return service_core.view_obs(bytestring, arch_string)

    @pyjsonrpc.rpcmethod
    def create_user(self, username, password):
        return service_core.create_user(username, password)

    @pyjsonrpc.rpcmethod
    def login_user(self, username, password):
        return service_core.login_user(username, password)

    @pyjsonrpc.rpcmethod
    def logout_user(self, sid):
        return service_core.logout_user(sid)

    #@pyjsonrpc.rpcmethod
    #def process_request_check(self, sid, bytestring, arch_string, statestring=None):
    #    print(statestring)
    #    return service_core._process_request_check(sid, bytestring, arch_string, statestring)

    @pyjsonrpc.rpcmethod
    def add_obs_job_check(self, sid, bytestring, arch_string, statestring=None):
        return service_core._add_obs_job_check(sid, bytestring, arch_string, statestring)

    @pyjsonrpc.rpcmethod
    def test(self):
        dataflow_test.test()

def main():
    hostname = args.hostname
    port = int(args.port)
    http_server = pyjsonrpc.ThreadingHttpServer(server_address=(hostname, port), RequestHandlerClass = RequestHandler)
    print("Starting TaintInduce Service Worker")
    print("URL: http://{}:{}".format(hostname, port))
    http_server.serve_forever()

if __name__ == '__main__':
    main()

