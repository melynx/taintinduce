#!/usr/bin/env python

import capstone
from . import x86_insn_info_ct
from . import amd64_insn_info_ct
import isa
import traceback

from taintinduce_common import InsnInfo

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
        if arch_str == 'X86':
            self.arch = isa.x86.X86()
            insn_info_ct = x86_insn_info_ct
        elif arch_str == 'AMD64':
            self.arch = isa.amd64.AMD64()
            insn_info_ct = amd64_insn_info_ct
        elif arch_str == 'ARM64':
            self.arch = isa.arm64.ARM64()
        else:
            raise UnsupportedArchException()
        self.bytestring = bytestring
        self.bytecode = bytestring.decode('hex')
        cs = capstone.Cs(self.arch.cs_arch[0], self.arch.cs_arch[1])
        cs.detail = True
        try:
            cs_insn_info = next(cs.disasm(self.bytecode, 0x1000))
        except:
            traceback.print_exc()
            raise ParseInsnException()

        self.asm_str = "{}\t{}".format(cs_insn_info.mnemonic, cs_insn_info.op_str)
        print('Disassembling instruction: {}'.format(self.asm_str))
        # capstone register set
        self.cs_reg_set     = []
        # register set based on manually defined information in
        # arm64/x86_constaints.py
        self.manual_reg_set  = []

        # REGISTERS
        # get register set based on capstone
        # based on cs, regs_access includes all explicit & implicit registers
        regs_read, regs_write = cs_insn_info.regs_access()

        for reg in regs_read:
            reg_name = cs_insn_info.reg_name(reg)
            self.cs_reg_set.append(self.arch.create_full_reg(reg_name))

        for reg in regs_write:
            reg_name = cs_insn_info.reg_name(reg)
            self.cs_reg_set.append(self.arch.create_full_reg(reg_name))

        # we don't fuck around with FPSW cause unicorn can't write stuff in it
        for reg in self.cs_reg_set:
            if reg.name == 'FPSW':
                self.cs_reg_set.remove(reg)

        # MEMORY - Capstone
        # check memory operands and add Register objects for memory write &
        # reads
        #read = 1
        #if cs_insn_info.id in insn_info_ct.mem_override:
        #    for access_type, size in insn_info_ct.mem_override[cs_insn_info.id]:
        #        if access_type == 'r':
        #            name = 'MEM_READ{}'.format(read)
        #            read += 1
        #        elif access_type == 'w':
        #            name = 'MEM_WRITE1'
        #        else:
        #            pdb.set_trace()
        #        bits = size*8
        #        self.cs_reg_set.append(self.arch.create_full_reg(name, bits))
        #else:
        #    for operand in cs_insn_info.operands:
        #        if operand.type == capstone.CS_OP_MEM and cs_insn_info.id not in insn_info_ct.remove_mem:
        #            name = ''
        #            if operand.access & capstone.CS_AC_READ:
        #                name = 'MEM_READ{}'.format(read)
        #                read += 1
        #                bits = self._get_mem_bits(operand, regs_write)
        #                self.cs_reg_set.append(self.arch.create_full_reg(name, bits))
        #            if operand.access & capstone.CS_AC_WRITE:
        #                name = 'MEM_WRITE1'
        #                bits = self._get_mem_bits(operand, regs_read)
        #                self.cs_reg_set.append(self.arch.create_full_reg(name, bits))
        #            if not name:
        #                print("Memory operand is neither READ nor WRITE")
        #                pdb.set_trace()

        #        read = 1
        #        if cs_insn_info.id in insn_info_ct.implicit_regs:
        #            manual_info = insn_info_ct.implicit_regs[cs_insn_info.id]

        #            for _, _, reg_name in manual_info:
        #                self.manual_reg_set.append(self.arch.create_full_reg(reg_name))

        #        if cs_insn_info.id in insn_info_ct.implicit_mem:
        #            # XXX i think this should be a list but it seems like there's
        #            # only one type of memory access in x86_insn_info_ct.py
        #            (access, size) = insn_info_ct.implicit_mem[cs_insn_info.id]
        #            if 'w' in access:
        #                name = 'MEM_WRITE1'
        #            elif 'r' in access:
        #                name = 'MEM_READ{}'.format(read)
        #                read += 1

        #            bits, structure = self._set_mem_reg_structure(size)
        #            mem_reg = self.arch.create_full_reg(name, bits, structure)
        #            self.cs_reg_set.append(mem_reg)

        #print('cs reg set {}'.format(self.cs_reg_set))
        #print('manual reg set {}'.format(self.manual_reg_set))
        reg_set = sorted(list(set(self.cs_reg_set + self.manual_reg_set)))
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
