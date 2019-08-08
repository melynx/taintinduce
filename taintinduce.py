#!/usr/bin/env python

from unicorn_cpu.unicorn_cpu import *

import argparse
import os
import disassembler.insn_info as insn_info
import observation_engine.observation as observation_engine
import inference_engine.inference as inference_engine
#import cPickle as pickle

import binascii

from taintinduce_common import *

import time
import json


def gen_insninfo(archstring, bytestring, emu_verify=True):
    insninfo = insn_info.Disassembler(archstring, bytestring).insninfo
    if emu_verify:
        cpu = UnicornCPU(archstring)
        bytecode = binascii.unhexlify(bytestring)
        mem_regs, jump_reg = cpu.identify_memops_jump(bytecode)
        if jump_reg and jump_reg not in insninfo.state_format:
            print('{} modifies the control flow but {} not in state_format!'.format(bytestring, jump_reg.name))
            insninfo.state_format.append(jump_reg)
        for mem_reg in mem_regs:
            if mem_reg not in insninfo.state_format:
                insninfo.state_format.append(mem_reg)
    return insninfo

def gen_obs(archstring, bytestring, state_format):
    obs_engine = observation_engine.ObservationEngine(bytestring, archstring, state_format)
    obs_list = obs_engine.observe_insn()
    return obs_list

def infer(state_format, cond_reg):
    infer_engine = inference_engine.InferenceEngine()
    rule = infer_engine.infer(state_format, cond_reg)
    return rule

def taintinduce_infer(archstring, bytestring):
    insninfo = gen_insninfo(archstring, bytestring)
    obs_list = gen_obs(archstring, bytestring, insninfo.state_format)
    rule = infer(obs_list, insninfo.cond_reg)
    return insninfo, obs_list, rule

def main():
    # we don't have ARM32, MIPS YET
    parser = argparse.ArgumentParser()
    parser.add_argument('bytestring', type=str, help='Instruction bytestring in ' +
                        'hex, e.g. use dac3 for \\xda\\xc3')
    parser.add_argument('arch', type=str, choices=['X86', 'AMD64', 'ARM64'],
                        help='Select the architecture of the instruction.')
    parser.add_argument('--output-dir', type=str, default='output', help='Output directory.')
    parser.add_argument('--skip-gen', default=False, action='store_true', help='Skip generation of observation')

    args = parser.parse_args()

    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)
    insn = gen_insninfo(args.arch, args.bytestring)
    output_obs_file = args.bytestring + '_' + args.arch + '_obs.json'
    output_rule_file = args.bytestring + '_' + args.arch + '_rule.json'
    obs_path = os.path.join(args.output_dir, output_obs_file)
    rule_path = os.path.join(args.output_dir, output_rule_file)

    if args.skip_gen:
        assert(args.output_dir)
        with open(obs_path, 'rb') as f:
            obs_list = deserialize_list(json.load(f))
    else:
        obs_list = gen_obs(args.arch, insn.bytestring, insn.state_format)
        print('Writing observations to {}'.format(obs_path))
        with open(obs_path, 'wb') as f:
            json.dump(serialize_list(obs_list), f)

    rule = infer(obs_list, insn.cond_reg)
    if (args.output_dir):
        with open(rule_path, 'wb') as myfile:
            json.dump(serialize_obj(rule), myfile)

    print(rule)
    print('Writing rule to {}'.format(rule_path))
    print('')

if __name__ == '__main__':
    main()
