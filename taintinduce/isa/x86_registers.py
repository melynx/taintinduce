from .isa import Register
from unicorn import *
from unicorn.x86_const import *
from capstone import *
from keystone import *


class X86_REG_AH(Register):
    def __init__(self):
        self.name = 'AH'
        self.uc_const = UC_X86_REG_AH
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class X86_REG_AL(Register):
    def __init__(self):
        self.name = 'AL'
        self.uc_const = UC_X86_REG_AL
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class X86_REG_AX(Register):
    def __init__(self):
        self.name = 'AX'
        self.uc_const = UC_X86_REG_AX
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class X86_REG_BH(Register):
    def __init__(self):
        self.name = 'BH'
        self.uc_const = UC_X86_REG_BH
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class X86_REG_BL(Register):
    def __init__(self):
        self.name = 'BL'
        self.uc_const = UC_X86_REG_BL
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class X86_REG_BP(Register):
    def __init__(self):
        self.name = 'BP'
        self.uc_const = UC_X86_REG_BP
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class X86_REG_BPL(Register):
    def __init__(self):
        self.name = 'BPL'
        self.uc_const = UC_X86_REG_BPL
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class X86_REG_BX(Register):
    def __init__(self):
        self.name = 'BX'
        self.uc_const = UC_X86_REG_BX
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class X86_REG_CH(Register):
    def __init__(self):
        self.name = 'CH'
        self.uc_const = UC_X86_REG_CH
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class X86_REG_CL(Register):
    def __init__(self):
        self.name = 'CL'
        self.uc_const = UC_X86_REG_CL
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class X86_REG_CR0(Register):
    def __init__(self):
        self.name = 'CR0'
        self.uc_const = UC_X86_REG_CR0
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_CR1(Register):
    def __init__(self):
        self.name = 'CR1'
        self.uc_const = UC_X86_REG_CR1
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_CR10(Register):
    def __init__(self):
        self.name = 'CR10'
        self.uc_const = UC_X86_REG_CR10
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_CR11(Register):
    def __init__(self):
        self.name = 'CR11'
        self.uc_const = UC_X86_REG_CR11
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_CR12(Register):
    def __init__(self):
        self.name = 'CR12'
        self.uc_const = UC_X86_REG_CR12
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_CR13(Register):
    def __init__(self):
        self.name = 'CR13'
        self.uc_const = UC_X86_REG_CR13
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_CR14(Register):
    def __init__(self):
        self.name = 'CR14'
        self.uc_const = UC_X86_REG_CR14
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_CR15(Register):
    def __init__(self):
        self.name = 'CR15'
        self.uc_const = UC_X86_REG_CR15
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_CR2(Register):
    def __init__(self):
        self.name = 'CR2'
        self.uc_const = UC_X86_REG_CR2
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_CR3(Register):
    def __init__(self):
        self.name = 'CR3'
        self.uc_const = UC_X86_REG_CR3
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_CR4(Register):
    def __init__(self):
        self.name = 'CR4'
        self.uc_const = UC_X86_REG_CR4
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_CR5(Register):
    def __init__(self):
        self.name = 'CR5'
        self.uc_const = UC_X86_REG_CR5
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_CR6(Register):
    def __init__(self):
        self.name = 'CR6'
        self.uc_const = UC_X86_REG_CR6
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_CR7(Register):
    def __init__(self):
        self.name = 'CR7'
        self.uc_const = UC_X86_REG_CR7
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_CR8(Register):
    def __init__(self):
        self.name = 'CR8'
        self.uc_const = UC_X86_REG_CR8
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_CR9(Register):
    def __init__(self):
        self.name = 'CR9'
        self.uc_const = UC_X86_REG_CR9
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_CS(Register):
    def __init__(self):
        self.name = 'CS'
        self.uc_const = UC_X86_REG_CS
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class X86_REG_CX(Register):
    def __init__(self):
        self.name = 'CX'
        self.uc_const = UC_X86_REG_CX
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class X86_REG_DH(Register):
    def __init__(self):
        self.name = 'DH'
        self.uc_const = UC_X86_REG_DH
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class X86_REG_DI(Register):
    def __init__(self):
        self.name = 'DI'
        self.uc_const = UC_X86_REG_DI
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class X86_REG_DIL(Register):
    def __init__(self):
        self.name = 'DIL'
        self.uc_const = UC_X86_REG_DIL
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class X86_REG_DL(Register):
    def __init__(self):
        self.name = 'DL'
        self.uc_const = UC_X86_REG_DL
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class X86_REG_DR0(Register):
    def __init__(self):
        self.name = 'DR0'
        self.uc_const = UC_X86_REG_DR0
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_DR1(Register):
    def __init__(self):
        self.name = 'DR1'
        self.uc_const = UC_X86_REG_DR1
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_DR10(Register):
    def __init__(self):
        self.name = 'DR10'
        self.uc_const = UC_X86_REG_DR10
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_DR11(Register):
    def __init__(self):
        self.name = 'DR11'
        self.uc_const = UC_X86_REG_DR11
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_DR12(Register):
    def __init__(self):
        self.name = 'DR12'
        self.uc_const = UC_X86_REG_DR12
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_DR13(Register):
    def __init__(self):
        self.name = 'DR13'
        self.uc_const = UC_X86_REG_DR13
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_DR14(Register):
    def __init__(self):
        self.name = 'DR14'
        self.uc_const = UC_X86_REG_DR14
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_DR15(Register):
    def __init__(self):
        self.name = 'DR15'
        self.uc_const = UC_X86_REG_DR15
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_DR2(Register):
    def __init__(self):
        self.name = 'DR2'
        self.uc_const = UC_X86_REG_DR2
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_DR3(Register):
    def __init__(self):
        self.name = 'DR3'
        self.uc_const = UC_X86_REG_DR3
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_DR4(Register):
    def __init__(self):
        self.name = 'DR4'
        self.uc_const = UC_X86_REG_DR4
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_DR5(Register):
    def __init__(self):
        self.name = 'DR5'
        self.uc_const = UC_X86_REG_DR5
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_DR6(Register):
    def __init__(self):
        self.name = 'DR6'
        self.uc_const = UC_X86_REG_DR6
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_DR7(Register):
    def __init__(self):
        self.name = 'DR7'
        self.uc_const = UC_X86_REG_DR7
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_DR8(Register):
    def __init__(self):
        self.name = 'DR8'
        self.uc_const = UC_X86_REG_DR8
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_DR9(Register):
    def __init__(self):
        self.name = 'DR9'
        self.uc_const = UC_X86_REG_DR9
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_DS(Register):
    def __init__(self):
        self.name = 'DS'
        self.uc_const = UC_X86_REG_DS
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class X86_REG_DX(Register):
    def __init__(self):
        self.name = 'DX'
        self.uc_const = UC_X86_REG_DX
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class X86_REG_EAX(Register):
    def __init__(self):
        self.name = 'EAX'
        self.uc_const = UC_X86_REG_EAX
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class X86_REG_EBP(Register):
    def __init__(self):
        self.name = 'EBP'
        self.uc_const = UC_X86_REG_EBP
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class X86_REG_EBX(Register):
    def __init__(self):
        self.name = 'EBX'
        self.uc_const = UC_X86_REG_EBX
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class X86_REG_ECX(Register):
    def __init__(self):
        self.name = 'ECX'
        self.uc_const = UC_X86_REG_ECX
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class X86_REG_EDI(Register):
    def __init__(self):
        self.name = 'EDI'
        self.uc_const = UC_X86_REG_EDI
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class X86_REG_EDX(Register):
    def __init__(self):
        self.name = 'EDX'
        self.uc_const = UC_X86_REG_EDX
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class X86_REG_EFLAGS(Register):
    def __init__(self):
        self.name = 'EFLAGS'
        self.uc_const = UC_X86_REG_EFLAGS
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class X86_REG_RFLAGS(Register):
    def __init__(self):
        self.name = 'EFLAGS'
        self.uc_const = UC_X86_REG_EFLAGS
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class X86_REG_EIP(Register):
    def __init__(self):
        self.name = 'EIP'
        self.uc_const = UC_X86_REG_EIP
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class X86_REG_EIZ(Register):
    def __init__(self):
        self.name = 'EIZ'
        self.uc_const = UC_X86_REG_EIZ
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class X86_REG_ES(Register):
    def __init__(self):
        self.name = 'ES'
        self.uc_const = UC_X86_REG_ES
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class X86_REG_ESI(Register):
    def __init__(self):
        self.name = 'ESI'
        self.uc_const = UC_X86_REG_ESI
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class X86_REG_ESP(Register):
    def __init__(self):
        self.name = 'ESP'
        self.uc_const = UC_X86_REG_ESP
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class X86_REG_FP0(Register):
    def __init__(self):
        self.name = 'FP0'
        self.uc_const = UC_X86_REG_FP0
        self.bits = 80
        self.structure = [64, 16]
        self.value = None
        self.address = None


class X86_REG_FP1(Register):
    def __init__(self):
        self.name = 'FP1'
        self.uc_const = UC_X86_REG_FP1
        self.bits = 80
        self.structure = [64, 16]
        self.value = None
        self.address = None


class X86_REG_FP2(Register):
    def __init__(self):
        self.name = 'FP2'
        self.uc_const = UC_X86_REG_FP2
        self.bits = 80
        self.structure = [64, 16]
        self.value = None
        self.address = None


class X86_REG_FP3(Register):
    def __init__(self):
        self.name = 'FP3'
        self.uc_const = UC_X86_REG_FP3
        self.bits = 80
        self.structure = [64, 16]
        self.value = None
        self.address = None


class X86_REG_FP4(Register):
    def __init__(self):
        self.name = 'FP4'
        self.uc_const = UC_X86_REG_FP4
        self.bits = 80
        self.structure = [64, 16]
        self.value = None
        self.address = None


class X86_REG_FP5(Register):
    def __init__(self):
        self.name = 'FP5'
        self.uc_const = UC_X86_REG_FP5
        self.bits = 80
        self.structure = [64, 16]
        self.value = None
        self.address = None


class X86_REG_FP6(Register):
    def __init__(self):
        self.name = 'FP6'
        self.uc_const = UC_X86_REG_FP6
        self.bits = 80
        self.structure = [64, 16]
        self.value = None
        self.address = None


class X86_REG_FP7(Register):
    def __init__(self):
        self.name = 'FP7'
        self.uc_const = UC_X86_REG_FP7
        self.bits = 80
        self.structure = [64, 16]
        self.value = None
        self.address = None


class X86_REG_FPCW(Register):
    def __init__(self):
        self.name = 'FPCW'
        self.uc_const = UC_X86_REG_FPCW
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_FPSW(Register):
    def __init__(self):
        self.name = 'FPSW'
        self.uc_const = UC_X86_REG_FPSW
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_FPTAG(Register):
    def __init__(self):
        self.name = 'FPTAG'
        self.uc_const = UC_X86_REG_FPTAG
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_FS(Register):
    def __init__(self):
        self.name = 'FS'
        self.uc_const = UC_X86_REG_FS
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class X86_REG_GDTR(Register):
    def __init__(self):
        self.name = 'GDTR'
        self.uc_const = UC_X86_REG_GDTR
        self.bits = 144
        self.structure = [16, 64, 32, 32]
        self.value = None
        self.address = None


class X86_REG_GS(Register):
    def __init__(self):
        self.name = 'GS'
        self.uc_const = UC_X86_REG_GS
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class X86_REG_IDTR(Register):
    def __init__(self):
        self.name = 'IDTR'
        self.uc_const = UC_X86_REG_IDTR
        self.bits = 144
        self.structure = [16, 64, 32, 32]
        self.value = None
        self.address = None


class X86_REG_IP(Register):
    def __init__(self):
        self.name = 'IP'
        self.uc_const = UC_X86_REG_IP
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class X86_REG_K0(Register):
    def __init__(self):
        self.name = 'K0'
        self.uc_const = UC_X86_REG_K0
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_K1(Register):
    def __init__(self):
        self.name = 'K1'
        self.uc_const = UC_X86_REG_K1
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_K2(Register):
    def __init__(self):
        self.name = 'K2'
        self.uc_const = UC_X86_REG_K2
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_K3(Register):
    def __init__(self):
        self.name = 'K3'
        self.uc_const = UC_X86_REG_K3
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_K4(Register):
    def __init__(self):
        self.name = 'K4'
        self.uc_const = UC_X86_REG_K4
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_K5(Register):
    def __init__(self):
        self.name = 'K5'
        self.uc_const = UC_X86_REG_K5
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_K6(Register):
    def __init__(self):
        self.name = 'K6'
        self.uc_const = UC_X86_REG_K6
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_K7(Register):
    def __init__(self):
        self.name = 'K7'
        self.uc_const = UC_X86_REG_K7
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_LDTR(Register):
    def __init__(self):
        self.name = 'LDTR'
        self.uc_const = UC_X86_REG_LDTR
        self.bits = 144
        self.structure = [16, 64, 32, 32]
        self.value = None
        self.address = None


class X86_REG_MM0(Register):
    def __init__(self):
        self.name = 'MM0'
        self.uc_const = UC_X86_REG_MM0
        self.bits = 80
        self.structure = [64, 16]
        self.value = None
        self.address = None


class X86_REG_MM1(Register):
    def __init__(self):
        self.name = 'MM1'
        self.uc_const = UC_X86_REG_MM1
        self.bits = 80
        self.structure = [64, 16]
        self.value = None
        self.address = None


class X86_REG_MM2(Register):
    def __init__(self):
        self.name = 'MM2'
        self.uc_const = UC_X86_REG_MM2
        self.bits = 80
        self.structure = [64, 16]
        self.value = None
        self.address = None


class X86_REG_MM3(Register):
    def __init__(self):
        self.name = 'MM3'
        self.uc_const = UC_X86_REG_MM3
        self.bits = 80
        self.structure = [64, 16]
        self.value = None
        self.address = None


class X86_REG_MM4(Register):
    def __init__(self):
        self.name = 'MM4'
        self.uc_const = UC_X86_REG_MM4
        self.bits = 80
        self.structure = [64, 16]
        self.value = None
        self.address = None


class X86_REG_MM5(Register):
    def __init__(self):
        self.name = 'MM5'
        self.uc_const = UC_X86_REG_MM5
        self.bits = 80
        self.structure = [64, 16]
        self.value = None
        self.address = None


class X86_REG_MM6(Register):
    def __init__(self):
        self.name = 'MM6'
        self.uc_const = UC_X86_REG_MM6
        self.bits = 80
        self.structure = [64, 16]
        self.value = None
        self.address = None


class X86_REG_MM7(Register):
    def __init__(self):
        self.name = 'MM7'
        self.uc_const = UC_X86_REG_MM7
        self.bits = 80
        self.structure = [64, 16]
        self.value = None
        self.address = None


class X86_REG_MSR(Register):
    def __init__(self):
        self.name = 'MSR'
        self.uc_const = UC_X86_REG_MSR
        self.bits = 96
        self.structure = [32, 64]
        self.value = None
        self.address = None


class X86_REG_R10(Register):
    def __init__(self):
        self.name = 'R10'
        self.uc_const = UC_X86_REG_R10
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_R10B(Register):
    def __init__(self):
        self.name = 'R10B'
        self.uc_const = UC_X86_REG_R10B
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class X86_REG_R10D(Register):
    def __init__(self):
        self.name = 'R10D'
        self.uc_const = UC_X86_REG_R10D
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class X86_REG_R10W(Register):
    def __init__(self):
        self.name = 'R10W'
        self.uc_const = UC_X86_REG_R10W
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class X86_REG_R11(Register):
    def __init__(self):
        self.name = 'R11'
        self.uc_const = UC_X86_REG_R11
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_R11B(Register):
    def __init__(self):
        self.name = 'R11B'
        self.uc_const = UC_X86_REG_R11B
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class X86_REG_R11D(Register):
    def __init__(self):
        self.name = 'R11D'
        self.uc_const = UC_X86_REG_R11D
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class X86_REG_R11W(Register):
    def __init__(self):
        self.name = 'R11W'
        self.uc_const = UC_X86_REG_R11W
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class X86_REG_R12(Register):
    def __init__(self):
        self.name = 'R12'
        self.uc_const = UC_X86_REG_R12
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_R12B(Register):
    def __init__(self):
        self.name = 'R12B'
        self.uc_const = UC_X86_REG_R12B
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class X86_REG_R12D(Register):
    def __init__(self):
        self.name = 'R12D'
        self.uc_const = UC_X86_REG_R12D
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class X86_REG_R12W(Register):
    def __init__(self):
        self.name = 'R12W'
        self.uc_const = UC_X86_REG_R12W
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class X86_REG_R13(Register):
    def __init__(self):
        self.name = 'R13'
        self.uc_const = UC_X86_REG_R13
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_R13B(Register):
    def __init__(self):
        self.name = 'R13B'
        self.uc_const = UC_X86_REG_R13B
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class X86_REG_R13D(Register):
    def __init__(self):
        self.name = 'R13D'
        self.uc_const = UC_X86_REG_R13D
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class X86_REG_R13W(Register):
    def __init__(self):
        self.name = 'R13W'
        self.uc_const = UC_X86_REG_R13W
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class X86_REG_R14(Register):
    def __init__(self):
        self.name = 'R14'
        self.uc_const = UC_X86_REG_R14
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_R14B(Register):
    def __init__(self):
        self.name = 'R14B'
        self.uc_const = UC_X86_REG_R14B
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class X86_REG_R14D(Register):
    def __init__(self):
        self.name = 'R14D'
        self.uc_const = UC_X86_REG_R14D
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class X86_REG_R14W(Register):
    def __init__(self):
        self.name = 'R14W'
        self.uc_const = UC_X86_REG_R14W
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class X86_REG_R15(Register):
    def __init__(self):
        self.name = 'R15'
        self.uc_const = UC_X86_REG_R15
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_R15B(Register):
    def __init__(self):
        self.name = 'R15B'
        self.uc_const = UC_X86_REG_R15B
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class X86_REG_R15D(Register):
    def __init__(self):
        self.name = 'R15D'
        self.uc_const = UC_X86_REG_R15D
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class X86_REG_R15W(Register):
    def __init__(self):
        self.name = 'R15W'
        self.uc_const = UC_X86_REG_R15W
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class X86_REG_R8(Register):
    def __init__(self):
        self.name = 'R8'
        self.uc_const = UC_X86_REG_R8
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_R8B(Register):
    def __init__(self):
        self.name = 'R8B'
        self.uc_const = UC_X86_REG_R8B
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class X86_REG_R8D(Register):
    def __init__(self):
        self.name = 'R8D'
        self.uc_const = UC_X86_REG_R8D
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class X86_REG_R8W(Register):
    def __init__(self):
        self.name = 'R8W'
        self.uc_const = UC_X86_REG_R8W
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class X86_REG_R9(Register):
    def __init__(self):
        self.name = 'R9'
        self.uc_const = UC_X86_REG_R9
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_R9B(Register):
    def __init__(self):
        self.name = 'R9B'
        self.uc_const = UC_X86_REG_R9B
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class X86_REG_R9D(Register):
    def __init__(self):
        self.name = 'R9D'
        self.uc_const = UC_X86_REG_R9D
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class X86_REG_R9W(Register):
    def __init__(self):
        self.name = 'R9W'
        self.uc_const = UC_X86_REG_R9W
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class X86_REG_RAX(Register):
    def __init__(self):
        self.name = 'RAX'
        self.uc_const = UC_X86_REG_RAX
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_RBP(Register):
    def __init__(self):
        self.name = 'RBP'
        self.uc_const = UC_X86_REG_RBP
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_RBX(Register):
    def __init__(self):
        self.name = 'RBX'
        self.uc_const = UC_X86_REG_RBX
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_RCX(Register):
    def __init__(self):
        self.name = 'RCX'
        self.uc_const = UC_X86_REG_RCX
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_RDI(Register):
    def __init__(self):
        self.name = 'RDI'
        self.uc_const = UC_X86_REG_RDI
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_RDX(Register):
    def __init__(self):
        self.name = 'RDX'
        self.uc_const = UC_X86_REG_RDX
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_RIP(Register):
    def __init__(self):
        self.name = 'RIP'
        self.uc_const = UC_X86_REG_RIP
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_RIZ(Register):
    def __init__(self):
        self.name = 'RIZ'
        self.uc_const = UC_X86_REG_RIZ
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_RSI(Register):
    def __init__(self):
        self.name = 'RSI'
        self.uc_const = UC_X86_REG_RSI
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_RSP(Register):
    def __init__(self):
        self.name = 'RSP'
        self.uc_const = UC_X86_REG_RSP
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class X86_REG_SI(Register):
    def __init__(self):
        self.name = 'SI'
        self.uc_const = UC_X86_REG_SI
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class X86_REG_SIL(Register):
    def __init__(self):
        self.name = 'SIL'
        self.uc_const = UC_X86_REG_SIL
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class X86_REG_SP(Register):
    def __init__(self):
        self.name = 'SP'
        self.uc_const = UC_X86_REG_SP
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class X86_REG_SPL(Register):
    def __init__(self):
        self.name = 'SPL'
        self.uc_const = UC_X86_REG_SPL
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class X86_REG_SS(Register):
    def __init__(self):
        self.name = 'SS'
        self.uc_const = UC_X86_REG_SS
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class X86_REG_ST0(Register):
    def __init__(self):
        self.name = 'ST0'
        self.uc_const = UC_X86_REG_ST0
        self.bits = 80
        self.structure = [64, 16]
        self.value = None
        self.address = None


class X86_REG_ST1(Register):
    def __init__(self):
        self.name = 'ST1'
        self.uc_const = UC_X86_REG_ST1
        self.bits = 80
        self.structure = [64, 16]
        self.value = None
        self.address = None


class X86_REG_ST2(Register):
    def __init__(self):
        self.name = 'ST2'
        self.uc_const = UC_X86_REG_ST2
        self.bits = 80
        self.structure = [64, 16]
        self.value = None
        self.address = None


class X86_REG_ST3(Register):
    def __init__(self):
        self.name = 'ST3'
        self.uc_const = UC_X86_REG_ST3
        self.bits = 80
        self.structure = [64, 16]
        self.value = None
        self.address = None


class X86_REG_ST4(Register):
    def __init__(self):
        self.name = 'ST4'
        self.uc_const = UC_X86_REG_ST4
        self.bits = 80
        self.structure = [64, 16]
        self.value = None
        self.address = None


class X86_REG_ST5(Register):
    def __init__(self):
        self.name = 'ST5'
        self.uc_const = UC_X86_REG_ST5
        self.bits = 80
        self.structure = [64, 16]
        self.value = None
        self.address = None


class X86_REG_ST6(Register):
    def __init__(self):
        self.name = 'ST6'
        self.uc_const = UC_X86_REG_ST6
        self.bits = 80
        self.structure = [64, 16]
        self.value = None
        self.address = None


class X86_REG_ST7(Register):
    def __init__(self):
        self.name = 'ST7'
        self.uc_const = UC_X86_REG_ST7
        self.bits = 80
        self.structure = [64, 16]
        self.value = None
        self.address = None


class X86_REG_TR(Register):
    def __init__(self):
        self.name = 'TR'
        self.uc_const = UC_X86_REG_TR
        self.bits = 144
        self.structure = [16, 64, 32, 32]
        self.value = None
        self.address = None


class X86_REG_XMM0(Register):
    def __init__(self):
        self.name = 'XMM0'
        self.uc_const = UC_X86_REG_XMM0
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class X86_REG_XMM1(Register):
    def __init__(self):
        self.name = 'XMM1'
        self.uc_const = UC_X86_REG_XMM1
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class X86_REG_XMM10(Register):
    def __init__(self):
        self.name = 'XMM10'
        self.uc_const = UC_X86_REG_XMM10
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class X86_REG_XMM11(Register):
    def __init__(self):
        self.name = 'XMM11'
        self.uc_const = UC_X86_REG_XMM11
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class X86_REG_XMM12(Register):
    def __init__(self):
        self.name = 'XMM12'
        self.uc_const = UC_X86_REG_XMM12
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class X86_REG_XMM13(Register):
    def __init__(self):
        self.name = 'XMM13'
        self.uc_const = UC_X86_REG_XMM13
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class X86_REG_XMM14(Register):
    def __init__(self):
        self.name = 'XMM14'
        self.uc_const = UC_X86_REG_XMM14
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class X86_REG_XMM15(Register):
    def __init__(self):
        self.name = 'XMM15'
        self.uc_const = UC_X86_REG_XMM15
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class X86_REG_XMM16(Register):
    def __init__(self):
        self.name = 'XMM16'
        self.uc_const = UC_X86_REG_XMM16
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class X86_REG_XMM17(Register):
    def __init__(self):
        self.name = 'XMM17'
        self.uc_const = UC_X86_REG_XMM17
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class X86_REG_XMM18(Register):
    def __init__(self):
        self.name = 'XMM18'
        self.uc_const = UC_X86_REG_XMM18
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class X86_REG_XMM19(Register):
    def __init__(self):
        self.name = 'XMM19'
        self.uc_const = UC_X86_REG_XMM19
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class X86_REG_XMM2(Register):
    def __init__(self):
        self.name = 'XMM2'
        self.uc_const = UC_X86_REG_XMM2
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class X86_REG_XMM20(Register):
    def __init__(self):
        self.name = 'XMM20'
        self.uc_const = UC_X86_REG_XMM20
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class X86_REG_XMM21(Register):
    def __init__(self):
        self.name = 'XMM21'
        self.uc_const = UC_X86_REG_XMM21
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class X86_REG_XMM22(Register):
    def __init__(self):
        self.name = 'XMM22'
        self.uc_const = UC_X86_REG_XMM22
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class X86_REG_XMM23(Register):
    def __init__(self):
        self.name = 'XMM23'
        self.uc_const = UC_X86_REG_XMM23
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class X86_REG_XMM24(Register):
    def __init__(self):
        self.name = 'XMM24'
        self.uc_const = UC_X86_REG_XMM24
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class X86_REG_XMM25(Register):
    def __init__(self):
        self.name = 'XMM25'
        self.uc_const = UC_X86_REG_XMM25
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class X86_REG_XMM26(Register):
    def __init__(self):
        self.name = 'XMM26'
        self.uc_const = UC_X86_REG_XMM26
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class X86_REG_XMM27(Register):
    def __init__(self):
        self.name = 'XMM27'
        self.uc_const = UC_X86_REG_XMM27
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class X86_REG_XMM28(Register):
    def __init__(self):
        self.name = 'XMM28'
        self.uc_const = UC_X86_REG_XMM28
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class X86_REG_XMM29(Register):
    def __init__(self):
        self.name = 'XMM29'
        self.uc_const = UC_X86_REG_XMM29
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class X86_REG_XMM3(Register):
    def __init__(self):
        self.name = 'XMM3'
        self.uc_const = UC_X86_REG_XMM3
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class X86_REG_XMM30(Register):
    def __init__(self):
        self.name = 'XMM30'
        self.uc_const = UC_X86_REG_XMM30
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class X86_REG_XMM31(Register):
    def __init__(self):
        self.name = 'XMM31'
        self.uc_const = UC_X86_REG_XMM31
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class X86_REG_XMM4(Register):
    def __init__(self):
        self.name = 'XMM4'
        self.uc_const = UC_X86_REG_XMM4
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class X86_REG_XMM5(Register):
    def __init__(self):
        self.name = 'XMM5'
        self.uc_const = UC_X86_REG_XMM5
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class X86_REG_XMM6(Register):
    def __init__(self):
        self.name = 'XMM6'
        self.uc_const = UC_X86_REG_XMM6
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class X86_REG_XMM7(Register):
    def __init__(self):
        self.name = 'XMM7'
        self.uc_const = UC_X86_REG_XMM7
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class X86_REG_XMM8(Register):
    def __init__(self):
        self.name = 'XMM8'
        self.uc_const = UC_X86_REG_XMM8
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class X86_REG_XMM9(Register):
    def __init__(self):
        self.name = 'XMM9'
        self.uc_const = UC_X86_REG_XMM9
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class X86_REG_YMM0(Register):
    def __init__(self):
        self.name = 'YMM0'
        self.uc_const = UC_X86_REG_YMM0
        self.bits = 256
        self.structure = [256]
        self.value = None
        self.address = None


class X86_REG_YMM1(Register):
    def __init__(self):
        self.name = 'YMM1'
        self.uc_const = UC_X86_REG_YMM1
        self.bits = 256
        self.structure = [256]
        self.value = None
        self.address = None


class X86_REG_YMM10(Register):
    def __init__(self):
        self.name = 'YMM10'
        self.uc_const = UC_X86_REG_YMM10
        self.bits = 256
        self.structure = [256]
        self.value = None
        self.address = None


class X86_REG_YMM11(Register):
    def __init__(self):
        self.name = 'YMM11'
        self.uc_const = UC_X86_REG_YMM11
        self.bits = 256
        self.structure = [256]
        self.value = None
        self.address = None


class X86_REG_YMM12(Register):
    def __init__(self):
        self.name = 'YMM12'
        self.uc_const = UC_X86_REG_YMM12
        self.bits = 256
        self.structure = [256]
        self.value = None
        self.address = None


class X86_REG_YMM13(Register):
    def __init__(self):
        self.name = 'YMM13'
        self.uc_const = UC_X86_REG_YMM13
        self.bits = 256
        self.structure = [256]
        self.value = None
        self.address = None


class X86_REG_YMM14(Register):
    def __init__(self):
        self.name = 'YMM14'
        self.uc_const = UC_X86_REG_YMM14
        self.bits = 256
        self.structure = [256]
        self.value = None
        self.address = None


class X86_REG_YMM15(Register):
    def __init__(self):
        self.name = 'YMM15'
        self.uc_const = UC_X86_REG_YMM15
        self.bits = 256
        self.structure = [256]
        self.value = None
        self.address = None


class X86_REG_YMM16(Register):
    def __init__(self):
        self.name = 'YMM16'
        self.uc_const = UC_X86_REG_YMM16
        self.bits = 256
        self.structure = [256]
        self.value = None
        self.address = None


class X86_REG_YMM17(Register):
    def __init__(self):
        self.name = 'YMM17'
        self.uc_const = UC_X86_REG_YMM17
        self.bits = 256
        self.structure = [256]
        self.value = None
        self.address = None


class X86_REG_YMM18(Register):
    def __init__(self):
        self.name = 'YMM18'
        self.uc_const = UC_X86_REG_YMM18
        self.bits = 256
        self.structure = [256]
        self.value = None
        self.address = None


class X86_REG_YMM19(Register):
    def __init__(self):
        self.name = 'YMM19'
        self.uc_const = UC_X86_REG_YMM19
        self.bits = 256
        self.structure = [256]
        self.value = None
        self.address = None


class X86_REG_YMM2(Register):
    def __init__(self):
        self.name = 'YMM2'
        self.uc_const = UC_X86_REG_YMM2
        self.bits = 256
        self.structure = [256]
        self.value = None
        self.address = None


class X86_REG_YMM20(Register):
    def __init__(self):
        self.name = 'YMM20'
        self.uc_const = UC_X86_REG_YMM20
        self.bits = 256
        self.structure = [256]
        self.value = None
        self.address = None


class X86_REG_YMM21(Register):
    def __init__(self):
        self.name = 'YMM21'
        self.uc_const = UC_X86_REG_YMM21
        self.bits = 256
        self.structure = [256]
        self.value = None
        self.address = None


class X86_REG_YMM22(Register):
    def __init__(self):
        self.name = 'YMM22'
        self.uc_const = UC_X86_REG_YMM22
        self.bits = 256
        self.structure = [256]
        self.value = None
        self.address = None


class X86_REG_YMM23(Register):
    def __init__(self):
        self.name = 'YMM23'
        self.uc_const = UC_X86_REG_YMM23
        self.bits = 256
        self.structure = [256]
        self.value = None
        self.address = None


class X86_REG_YMM24(Register):
    def __init__(self):
        self.name = 'YMM24'
        self.uc_const = UC_X86_REG_YMM24
        self.bits = 256
        self.structure = [256]
        self.value = None
        self.address = None


class X86_REG_YMM25(Register):
    def __init__(self):
        self.name = 'YMM25'
        self.uc_const = UC_X86_REG_YMM25
        self.bits = 256
        self.structure = [256]
        self.value = None
        self.address = None


class X86_REG_YMM26(Register):
    def __init__(self):
        self.name = 'YMM26'
        self.uc_const = UC_X86_REG_YMM26
        self.bits = 256
        self.structure = [256]
        self.value = None
        self.address = None


class X86_REG_YMM27(Register):
    def __init__(self):
        self.name = 'YMM27'
        self.uc_const = UC_X86_REG_YMM27
        self.bits = 256
        self.structure = [256]
        self.value = None
        self.address = None


class X86_REG_YMM28(Register):
    def __init__(self):
        self.name = 'YMM28'
        self.uc_const = UC_X86_REG_YMM28
        self.bits = 256
        self.structure = [256]
        self.value = None
        self.address = None


class X86_REG_YMM29(Register):
    def __init__(self):
        self.name = 'YMM29'
        self.uc_const = UC_X86_REG_YMM29
        self.bits = 256
        self.structure = [256]
        self.value = None
        self.address = None


class X86_REG_YMM3(Register):
    def __init__(self):
        self.name = 'YMM3'
        self.uc_const = UC_X86_REG_YMM3
        self.bits = 256
        self.structure = [256]
        self.value = None
        self.address = None


class X86_REG_YMM30(Register):
    def __init__(self):
        self.name = 'YMM30'
        self.uc_const = UC_X86_REG_YMM30
        self.bits = 256
        self.structure = [256]
        self.value = None
        self.address = None


class X86_REG_YMM31(Register):
    def __init__(self):
        self.name = 'YMM31'
        self.uc_const = UC_X86_REG_YMM31
        self.bits = 256
        self.structure = [256]
        self.value = None
        self.address = None


class X86_REG_YMM4(Register):
    def __init__(self):
        self.name = 'YMM4'
        self.uc_const = UC_X86_REG_YMM4
        self.bits = 256
        self.structure = [256]
        self.value = None
        self.address = None


class X86_REG_YMM5(Register):
    def __init__(self):
        self.name = 'YMM5'
        self.uc_const = UC_X86_REG_YMM5
        self.bits = 256
        self.structure = [256]
        self.value = None
        self.address = None


class X86_REG_YMM6(Register):
    def __init__(self):
        self.name = 'YMM6'
        self.uc_const = UC_X86_REG_YMM6
        self.bits = 256
        self.structure = [256]
        self.value = None
        self.address = None


class X86_REG_YMM7(Register):
    def __init__(self):
        self.name = 'YMM7'
        self.uc_const = UC_X86_REG_YMM7
        self.bits = 256
        self.structure = [256]
        self.value = None
        self.address = None


class X86_REG_YMM8(Register):
    def __init__(self):
        self.name = 'YMM8'
        self.uc_const = UC_X86_REG_YMM8
        self.bits = 256
        self.structure = [256]
        self.value = None
        self.address = None


class X86_REG_YMM9(Register):
    def __init__(self):
        self.name = 'YMM9'
        self.uc_const = UC_X86_REG_YMM9
        self.bits = 256
        self.structure = [256]
        self.value = None
        self.address = None


class X86_MEM_READ1(Register):
    def __init__(self):
        self.name = 'MEM_READ1'
        self.uc_const = UC_X86_REG_ENDING + 1
        self.bits = 0
        self.structure = []
        self.value = 0
        self.address = 0


class X86_MEM_READ2(Register):
    def __init__(self):
        self.name = 'MEM_READ2'
        self.uc_const = UC_X86_REG_ENDING + 2
        self.bits = 0
        self.structure = []
        self.value = 0
        self.address = 0


class X86_MEM_WRITE1(Register):
    def __init__(self):
        self.name = 'MEM_WRITE1'
        self.uc_const = UC_X86_REG_ENDING + 3
        self.bits = 0
        self.structure = []
        self.value = 0
        self.address = 0

# ZL: quick hack!!!
# TODO: convert to squirrel memoryslot

class X86_MEM_READ1_ADDR32(Register):
    def __init__(self):
        self.name = 'MEM_READ1_ADDR32'
        self.uc_const = UC_X86_REG_ENDING + 4
        self.bits = 32
        self.structure = []
        self.value = 0
        self.address = 0

class X86_MEM_READ2_ADDR32(Register):
    def __init__(self):
        self.name = 'MEM_READ2_ADDR32'
        self.uc_const = UC_X86_REG_ENDING + 5
        self.bits = 32
        self.structure = []
        self.value = 0
        self.address = 0

class X86_MEM_WRITE1_ADDR32(Register):
    def __init__(self):
        self.name = 'MEM_WRITE1_ADDR32'
        self.uc_const = UC_X86_REG_ENDING + 6
        self.bits = 32
        self.structure = []
        self.value = 0
        self.address = 0

class X86_MEM_READ1_ADDR64(Register):
    def __init__(self):
        self.name = 'MEM_READ1_ADDR64'
        self.uc_const = UC_X86_REG_ENDING + 7
        self.bits = 64
        self.structure = []
        self.value = 0
        self.address = 0

class X86_MEM_READ2_ADDR64(Register):
    def __init__(self):
        self.name = 'MEM_READ2_ADDR64'
        self.uc_const = UC_X86_REG_ENDING + 8
        self.bits = 64
        self.structure = []
        self.value = 0
        self.address = 0

class X86_MEM_WRITE1_ADDR64(Register):
    def __init__(self):
        self.name = 'MEM_WRITE1_ADDR64'
        self.uc_const = UC_X86_REG_ENDING + 9
        self.bits = 64
        self.structure = []
        self.value = 0
        self.address = 0
