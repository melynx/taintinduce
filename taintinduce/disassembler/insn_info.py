#!/usr/bin/env python3

import taintinduce.isa as isa

from squirrel.squirrel_disassembler import SquirrelDisassemblerZydis, SquirrelDisassemblerCapstone
from taintinduce.taintinduce_common import InsnInfo
from squirrel.isa.registers import get_register_arch

import pdb

class ParseInsnException(Exception):
    def __str__(self):
        return "[ERROR] capstone disassemble cannot translate this instruction!"

class UnsupportedArchException(Exception):
    def __str__(self):
        return "[ERROR] TaintInduce doesnt support this arch now!"

class InsnInfoException(Exception):
    def __str__(self):
        return "[ERROR] insninfo cannot parse capstone information!"

class UnsupportedSizeException(Exception):
    def __str__(self):
        return "[ERROR] size unsupport error!"


class Disassembler(object):
    def __init__(self, arch_str, bytestring):
        """Initialize wrapper over Capstone CsInsn or Cs.

        arch_str (str)          - the architecture of the instruction (currently
                            supported: X86, AMD64)
        bytestring (str)        - the hex string corresponding to the instruction
                            bytes
        """
        self.archstring = arch_str
        ISARegister = None
        if arch_str == 'X86':
            self.arch = isa.x86.X86()
        elif arch_str == 'AMD64':
            self.arch = isa.amd64.AMD64()
        elif arch_str == 'ARM64':
            self.arch = isa.arm64.ARM64()
        else:
            raise UnsupportedArchException()

        ISARegister = get_register_arch(arch_str)

        self.bytestring = bytestring
        dis = SquirrelDisassemblerZydis(arch_str)
        insn = dis.disassemble(bytestring)

        # capstone register set
        self.cs_reg_set     = []

        for reg_name in insn.reg_reads():
            reg_name = ISARegister.get_reg_name(reg_name)
            self.cs_reg_set.append(self.arch.create_full_reg(reg_name))

        for reg_name in insn.reg_writes():
            reg_name = ISARegister.get_reg_name(reg_name)
            self.cs_reg_set.append(self.arch.create_full_reg(reg_name))

        # we don't fuck around with FPSW cause unicorn can't write stuff in it
        for reg in self.cs_reg_set:
            if reg.name == 'FPSW':
                self.cs_reg_set.remove(reg)

        reg_set = list(set(self.cs_reg_set))
        self.insninfo = InsnInfo(arch_str, bytestring, reg_set, self.arch.cond_reg)

    def _get_mem_bits(self, operand, regs):
        # for ARM32 and ARM64 capstone does not have a size
        # attribute for operands so we set it based on the other
        # operands size
        if hasattr(operand, 'size'):
            bits = operand.size * 8
        else:
            if operand.access == capstone.CS_AC_READ:
                reg0 = self.arch.name2reg(cs_insn_info.reg_name(regs[0]))
            elif operand.access == capstone.CS_AC_WRITE:
                reg0 = self.arch.name2reg(cs_insn_info.reg_name(regs[0]))
            bits = reg0.bits * 8
        return bits


    def _set_mem_reg_structure(self, reg_bytes):
        '''Took this code from yanhao. 
        THIS IS ONLY FOR IMPLICIT REGS DEFINED IN THE x86_insn_info_ct
            It sets the virtual registers for memory structure based on the
            register size.

            set args for a mem register
            92bits? doulble check
        '''
        valid_size = [8, 16, 32, 64, 128, 256]

        bits = reg_bytes * 8
        if bits == 80:
            structure = [64, 16]
        elif bits in valid_size:
            structure = [reg_bytes * 8]
        else:
            raise UnsupportedSizeException()

        return bits, structure
