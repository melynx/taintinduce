from unicorn import *
from unicorn.x86_const import *
from capstone import *
from keystone import *

from isa import ISA
from x86_registers import *
import x86_registers

# x86 architecture
class X86(ISA):
    def __init__(self):
        self.cpu_regs = [
            X86_REG_EAX(),
            X86_REG_EBX(),
            X86_REG_ECX(),
            X86_REG_EDX(),
            X86_REG_EBP(),
            X86_REG_ESP(),
            X86_REG_EDI(),
            X86_REG_ESI(),
            X86_REG_EFLAGS(),
            X86_REG_EIP(),
            X86_REG_XMM0(),
            X86_REG_XMM1(),
            X86_REG_XMM2(),
            X86_REG_XMM3(),
            X86_REG_XMM4(),
            X86_REG_XMM5(),
            X86_REG_XMM6(),
            X86_REG_XMM7(),
            X86_REG_FP0(),
            X86_REG_FP1(),
            X86_REG_FP2(),
            X86_REG_FP3(),
            X86_REG_FP4(),
            X86_REG_FP5(),
            X86_REG_FP6(),
            X86_REG_FP7(),
            X86_REG_FPSW()
        ]

        self.full_cpu_regs = [
            # Byte Registers
            X86_REG_AL(),
            X86_REG_AH(),
            X86_REG_BH(),
            X86_REG_BL(),
            X86_REG_CH(),
            X86_REG_CL(),
            X86_REG_DH(),
            X86_REG_DL(),
            X86_REG_DIL(),
            X86_REG_SIL(),
            # Word Registers
            X86_REG_AX(),
            X86_REG_BX(),
            X86_REG_CX(),
            X86_REG_DX(),
            X86_REG_DI(),
            X86_REG_SI(),
            X86_REG_BP(),
            X86_REG_SP(),
            X86_REG_IP(),
            X86_REG_BPL(),
            X86_REG_SPL(),
            # Doubleword Registers
            X86_REG_EAX(),
            X86_REG_EBP(),
            X86_REG_EBX(),
            X86_REG_ECX(),
            X86_REG_EDI(),
            X86_REG_EDX(),
            X86_REG_EFLAGS(),
            X86_REG_EIP(),
            X86_REG_ESI(),
            X86_REG_ESP(),
            # Multiword Registers
            X86_REG_XMM0(),
            X86_REG_XMM1(),
            X86_REG_XMM2(),
            X86_REG_XMM3(),
            X86_REG_XMM4(),
            X86_REG_XMM5(),
            X86_REG_XMM6(),
            X86_REG_XMM7(),
            X86_REG_FP7(),
            X86_REG_FP0(),
            X86_REG_FP1(),
            X86_REG_FP2(),
            X86_REG_FP3(),
            X86_REG_FP4(),
            X86_REG_FP5(),
            X86_REG_FP6(),
            X86_REG_FPSW(),
        ]

        # XXX teo: can i remove these?
        self.cpu_read_emu_regs  = [X86_MEM_READ2(), X86_MEM_READ1()]
        self.cpu_write_emu_regs = [X86_MEM_WRITE1()]

        # XXX teo: do we need these ??
        self.pc_reg        = X86_REG_EIP()
        self.flag_reg      = [X86_REG_EFLAGS()]
        self.state_reg     = [X86_REG_FPSW()]

        # Sub register
        self.register_map = {
            'EAX': ['AL', 'AH', 'AX'],
            'EBX': ['BL', 'BH', 'BX'],
            'ECX': ['CL', 'CH', 'CX'],
            'EDX': ['DL', 'DH', 'DX'],
            'ESI': ['SI', 'SIL'],
            'EDI': ['DI', 'DIL'],
            'EBP': ['BP', 'BPL'],
            'ESP': ['SP', 'SPL'],
            'EIP': ['IP'],
            'FP0': ['ST(0)', 'ST0', 'MM0', 'ST'],
            'FP1': ['ST(1)', 'ST1', 'MM1'],
            'FP2': ['ST(2)', 'ST2', 'MM2'],
            'FP3': ['ST(3)', 'ST3', 'MM3'],
            'FP4': ['ST(4)', 'ST4', 'MM4'],
            'FP5': ['ST(5)', 'ST5', 'MM5'],
            'FP6': ['ST(6)', 'ST6', 'MM6'],
            'FP7': ['ST(7)', 'ST7', 'MM7']
        }

        self.register_alias = {}
        for reg_name in self.register_map:
            self.register_alias[reg_name] = reg_name
            for aliased_reg_name in self.register_map[reg_name]:
                self.register_alias[aliased_reg_name] = reg_name

        self.uc_arch = (UC_ARCH_X86, UC_MODE_32)
        self.ks_arch = (KS_ARCH_X86, KS_MODE_32)
        self.cs_arch = (CS_ARCH_X86, CS_MODE_32)
        self.code_mem = 4096
        self.code_addr = 0x6d1c000

        self.addr_space = 32

        self.cond_reg = X86_REG_EFLAGS()
        self.reg_module = x86_registers

    def name2reg(self, name):
        name = name.upper()
        name = name.replace('(','')
        name = name.replace(')','')
        if 'MEM' in name:
            return eval('X86_{}()'.format(name))

        return eval('X86_REG_{}()'.format(name))

    def create_full_reg(self, name, bits=0, structure=[]):
        name = name.upper()
        name = name.replace('(','')
        name = name.replace(')','')
        if 'MEM' in name:
            reg = eval('X86_{}()'.format(name))
            reg.bits, reg.structure = bits, structure
            return reg

        for full_reg_name, sub_regs_name in self.register_map.iteritems():
            if name in sub_regs_name:
                return eval('X86_REG_{}()'.format(full_reg_name))

        return eval('X86_REG_{}()'.format(name))
