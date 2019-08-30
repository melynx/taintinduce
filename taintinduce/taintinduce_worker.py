#!/usr/bin/env python3

from xmlrpc.server import SimpleXMLRPCServer
import argparse
import json

from squirrel.squirrel_serializer.serializer import SquirrelEncoder
from taintinduce.taintinduce import taintinduce_infer

def gen_obs_rule(archstring, bytestring):
    print("Inferring ({}) - {}".format(archstring, bytestring))
    insninfo, obs_list, rule = taintinduce_infer(archstring, bytestring)
    obs_str_list = [json.dumps(x, cls=SquirrelEncoder) for x in obs_list]
    return (insninfo.serialize(), obs_str_list, rule.serialize())

#def gen_observation(archstring, bytestring):
#    insn = taintinduce.gen_insninfo(archstring, bytestring)
#    obs_list = taintinduce.gen_obs(archstring, bytestring, insn.arch.cond_reg)
#    return obs_list
#
#def gen_insninfo(archstring, bytestring):
#    return taintinduce.gen_insninfo(archstring, bytestring)
#
#def infer(obs_list, cond_reg):
#    return taintinduce.infer(obs_list, cond_reg)

def test_connection():
    return True

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('local_hostname')
    parser.add_argument('local_port',type=int)
    args = parser.parse_args()

    print("Starting TaintInduce Service...")
    hostname = args.local_hostname
    port = args.local_port
    print("URL: http://{}:{}".format(hostname, port))
    server = SimpleXMLRPCServer((hostname, port))
    server.register_function(gen_obs_rule)
    server.register_function(test_connection)
        #server.register_function(gen_observation)
        #server.register_function(gen_insninfo)
        #server.register_function(infer)
    server.serve_forever()

if __name__ == '__main__':
    main()
