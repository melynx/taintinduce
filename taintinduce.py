#!/usr/bin/env python

from unicorn_cpu.unicorn_cpu import *

import argparse
import os
import disassembler.insn_info as insn_info
import observation_engine.observation as observation_engine
import inference_engine.inference as inference_engine
import pickle as pkl

import binascii


def gen_insninfo(archstring, bytestring, emu_verify=True):
    insn = insn_info.InsnInfo(archstring, bytestring)
    if emu_verify:
        cpu = UnicornCPU(archstring)
        bytecode = binascii.unhexlify(bytestring)
        mem_regs, jump_reg = cpu.identify_memops_jump(bytecode)
        if jump_reg and jump_reg not in insn.reg_set:
            print('{} modifies the control flow but {} not in state_format!'.format(bytestring, jump_reg.name))
            insn.reg_set.append(jump_reg)
        for mem_reg in mem_regs:
            if mem_reg not in insn.reg_set:
                insn.reg_set.append(mem_reg)
    return insn

def gen_obs(archstring, bytestring, reg_set):
    obs_engine = observation_engine.ObservationEngine(bytestring, archstring, reg_set)
    obs_list = obs_engine.observe_insn()
    return obs_list

def taintinduce_infer(archstring, bytestring):
    insn = gen_insninfo(archstring, bytestring)
    obs_list = gen_obs(archstring, bytestring, insn.reg_set)
    infer_engine = inference_engine.InferenceEngine()
    rule = infer_engine.infer(bytestring, archstring, insn.reg_set, obs_list, insn)
    return pkl.dumps(rule)

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
    output_obs_file = args.bytestring + '_' + args.arch + '_obs.pkl'
    output_rule_file = args.bytestring + '_' + args.arch + '_rule.pkl'
    obs_path = os.path.join(args.output_dir, output_obs_file)
    rule_path = os.path.join(args.output_dir, output_rule_file)

    if args.skip_gen:
        assert(args.output_dir)
        with open(obs_path, 'rb') as f:
            obs_list = pkl.load(f)
    else:
        obs_list = gen_obs(args.arch, insn.bytestring, insn.reg_set)
        print('Writing observations to {}'.format(obs_path))
        with open(obs_path, 'wb') as f:
            pkl.dump(obs_list, f)

    infer_engine = inference_engine.InferenceEngine()
    rule = infer_engine.infer(insn.bytestring, args.arch, insn.reg_set, obs_list, insn)
    if (args.output_dir):
        with open(rule_path, 'wb') as myfile:
            pkl.dump(rule, myfile)

    print(rule)
    print('Writing rule to {}'.format(rule_path))
    print('')

if __name__ == '__main__':
    main()
