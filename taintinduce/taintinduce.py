#!/usr/bin/env python3

import binascii
import argparse
import os
import time
import json

import taintinduce.disassembler.insn_info as insn_info
import taintinduce.observation_engine.observation as observation_engine
import taintinduce.inference_engine.inference as inference_engine

import squirrel.acorn.acorn as acorn

from squirrel.squirrel_serializer.serializer import SquirrelEncoder, SquirrelDecoder
from taintinduce.taintinduce_common import *
from taintinduce.unicorn_cpu.unicorn_cpu import *

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
    rule = rule.convert2squirrel(archstring)
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
        with open(obs_path, 'r') as f:
            obs_list = json.load(f, cls=TaintInduceDecoder)
    else:
        obs_list = gen_obs(args.arch, insn.bytestring, insn.state_format)
        print('Writing observations to {}'.format(obs_path))
        with open(obs_path, 'w') as f:
            json.dump(obs_list, f, cls=SquirrelEncoder)

    rule = infer(obs_list, insn.cond_reg)
    rule = rule.convert2squirrel(args.arch)
    if (args.output_dir):
        with open(rule_path, 'w') as myfile:
            myfile.write(rule.serialize())

    q = rule.serialize()
    qq = acorn.TaintRule.deserialize(q)
    print(qq)
    print('Writing rule to {}'.format(rule_path))
    print('')

if __name__ == '__main__':
    main()
