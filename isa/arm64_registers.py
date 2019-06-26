from isa import Register
from unicorn import *
from unicorn.arm64_const import *
from capstone import *
from keystone import *

class ARM64_MEM_READ1(Register):
    def __init__(self):
        self.name = 'MEM_READ1'
        self.uc_const = UC_ARM64_REG_ENDING + 1
        self.bits = 0
        self.structure = []
        self.value = 0
        self.address = 0


class ARM64_MEM_READ2(Register):
    def __init__(self):
        self.name = 'MEM_READ2'
        self.uc_const = UC_ARM64_REG_ENDING + 2
        self.bits = 0
        self.structure = []
        self.value = 0
        self.address = 0


class ARM64_MEM_WRITE1(Register):
    def __init__(self):
        self.name = 'MEM_WRITE1'
        self.uc_const = UC_ARM64_REG_ENDING + 3
        self.bits = 0
        self.structure = []
        self.value = 0
        self.address = 0

class ARM64_REG_WSP(Register):
    def __init__(self):
        self.name = 'WSP'
        self.uc_const = UC_ARM64_REG_WSP
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None

class ARM64_REG_WSR(Register):
    def __init__(self):
        self.name = 'WZR'
        self.uc_const = UC_ARM64_REG_WZR
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None

class ARM64_REG_XZR(Register):
    def __init__(self):
        self.name = 'XZR'
        self.uc_const = UC_ARM64_REG_XZR
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None

class ARM64_REG_B0(Register):
    def __init__(self):
        self.name = 'B0'
        self.uc_const = UC_ARM64_REG_B0
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class ARM64_REG_B1(Register):
    def __init__(self):
        self.name = 'B1'
        self.uc_const = UC_ARM64_REG_B1
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class ARM64_REG_B10(Register):
    def __init__(self):
        self.name = 'B10'
        self.uc_const = UC_ARM64_REG_B10
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class ARM64_REG_B11(Register):
    def __init__(self):
        self.name = 'B11'
        self.uc_const = UC_ARM64_REG_B11
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class ARM64_REG_B12(Register):
    def __init__(self):
        self.name = 'B12'
        self.uc_const = UC_ARM64_REG_B12
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class ARM64_REG_B13(Register):
    def __init__(self):
        self.name = 'B13'
        self.uc_const = UC_ARM64_REG_B13
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class ARM64_REG_B14(Register):
    def __init__(self):
        self.name = 'B14'
        self.uc_const = UC_ARM64_REG_B14
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class ARM64_REG_B15(Register):
    def __init__(self):
        self.name = 'B15'
        self.uc_const = UC_ARM64_REG_B15
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class ARM64_REG_B16(Register):
    def __init__(self):
        self.name = 'B16'
        self.uc_const = UC_ARM64_REG_B16
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class ARM64_REG_B17(Register):
    def __init__(self):
        self.name = 'B17'
        self.uc_const = UC_ARM64_REG_B17
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class ARM64_REG_B18(Register):
    def __init__(self):
        self.name = 'B18'
        self.uc_const = UC_ARM64_REG_B18
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class ARM64_REG_B19(Register):
    def __init__(self):
        self.name = 'B19'
        self.uc_const = UC_ARM64_REG_B19
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class ARM64_REG_B2(Register):
    def __init__(self):
        self.name = 'B2'
        self.uc_const = UC_ARM64_REG_B2
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class ARM64_REG_B20(Register):
    def __init__(self):
        self.name = 'B20'
        self.uc_const = UC_ARM64_REG_B20
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class ARM64_REG_B21(Register):
    def __init__(self):
        self.name = 'B21'
        self.uc_const = UC_ARM64_REG_B21
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class ARM64_REG_B22(Register):
    def __init__(self):
        self.name = 'B22'
        self.uc_const = UC_ARM64_REG_B22
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class ARM64_REG_B23(Register):
    def __init__(self):
        self.name = 'B23'
        self.uc_const = UC_ARM64_REG_B23
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class ARM64_REG_B24(Register):
    def __init__(self):
        self.name = 'B24'
        self.uc_const = UC_ARM64_REG_B24
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class ARM64_REG_B25(Register):
    def __init__(self):
        self.name = 'B25'
        self.uc_const = UC_ARM64_REG_B25
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class ARM64_REG_B26(Register):
    def __init__(self):
        self.name = 'B26'
        self.uc_const = UC_ARM64_REG_B26
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class ARM64_REG_B27(Register):
    def __init__(self):
        self.name = 'B27'
        self.uc_const = UC_ARM64_REG_B27
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class ARM64_REG_B28(Register):
    def __init__(self):
        self.name = 'B28'
        self.uc_const = UC_ARM64_REG_B28
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class ARM64_REG_B29(Register):
    def __init__(self):
        self.name = 'B29'
        self.uc_const = UC_ARM64_REG_B29
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class ARM64_REG_B3(Register):
    def __init__(self):
        self.name = 'B3'
        self.uc_const = UC_ARM64_REG_B3
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class ARM64_REG_B30(Register):
    def __init__(self):
        self.name = 'B30'
        self.uc_const = UC_ARM64_REG_B30
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class ARM64_REG_B31(Register):
    def __init__(self):
        self.name = 'B31'
        self.uc_const = UC_ARM64_REG_B31
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class ARM64_REG_B4(Register):
    def __init__(self):
        self.name = 'B4'
        self.uc_const = UC_ARM64_REG_B4
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class ARM64_REG_B5(Register):
    def __init__(self):
        self.name = 'B5'
        self.uc_const = UC_ARM64_REG_B5
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class ARM64_REG_B6(Register):
    def __init__(self):
        self.name = 'B6'
        self.uc_const = UC_ARM64_REG_B6
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class ARM64_REG_B7(Register):
    def __init__(self):
        self.name = 'B7'
        self.uc_const = UC_ARM64_REG_B7
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class ARM64_REG_B8(Register):
    def __init__(self):
        self.name = 'B8'
        self.uc_const = UC_ARM64_REG_B8
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class ARM64_REG_B9(Register):
    def __init__(self):
        self.name = 'B9'
        self.uc_const = UC_ARM64_REG_B9
        self.bits = 8
        self.structure = [8]
        self.value = None
        self.address = None


class ARM64_REG_CPACR_EL1(Register):
    def __init__(self):
        self.name = 'EL1'
        self.uc_const = UC_ARM64_REG_CPACR_EL1
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_D0(Register):
    def __init__(self):
        self.name = 'D0'
        self.uc_const = UC_ARM64_REG_D0
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_D1(Register):
    def __init__(self):
        self.name = 'D1'
        self.uc_const = UC_ARM64_REG_D1
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_D10(Register):
    def __init__(self):
        self.name = 'D10'
        self.uc_const = UC_ARM64_REG_D10
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_D11(Register):
    def __init__(self):
        self.name = 'D11'
        self.uc_const = UC_ARM64_REG_D11
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_D12(Register):
    def __init__(self):
        self.name = 'D12'
        self.uc_const = UC_ARM64_REG_D12
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_D13(Register):
    def __init__(self):
        self.name = 'D13'
        self.uc_const = UC_ARM64_REG_D13
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_D14(Register):
    def __init__(self):
        self.name = 'D14'
        self.uc_const = UC_ARM64_REG_D14
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_D15(Register):
    def __init__(self):
        self.name = 'D15'
        self.uc_const = UC_ARM64_REG_D15
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_D16(Register):
    def __init__(self):
        self.name = 'D16'
        self.uc_const = UC_ARM64_REG_D16
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_D17(Register):
    def __init__(self):
        self.name = 'D17'
        self.uc_const = UC_ARM64_REG_D17
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_D18(Register):
    def __init__(self):
        self.name = 'D18'
        self.uc_const = UC_ARM64_REG_D18
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_D19(Register):
    def __init__(self):
        self.name = 'D19'
        self.uc_const = UC_ARM64_REG_D19
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_D2(Register):
    def __init__(self):
        self.name = 'D2'
        self.uc_const = UC_ARM64_REG_D2
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_D20(Register):
    def __init__(self):
        self.name = 'D20'
        self.uc_const = UC_ARM64_REG_D20
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_D21(Register):
    def __init__(self):
        self.name = 'D21'
        self.uc_const = UC_ARM64_REG_D21
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_D22(Register):
    def __init__(self):
        self.name = 'D22'
        self.uc_const = UC_ARM64_REG_D22
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_D23(Register):
    def __init__(self):
        self.name = 'D23'
        self.uc_const = UC_ARM64_REG_D23
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_D24(Register):
    def __init__(self):
        self.name = 'D24'
        self.uc_const = UC_ARM64_REG_D24
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_D25(Register):
    def __init__(self):
        self.name = 'D25'
        self.uc_const = UC_ARM64_REG_D25
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_D26(Register):
    def __init__(self):
        self.name = 'D26'
        self.uc_const = UC_ARM64_REG_D26
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_D27(Register):
    def __init__(self):
        self.name = 'D27'
        self.uc_const = UC_ARM64_REG_D27
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_D28(Register):
    def __init__(self):
        self.name = 'D28'
        self.uc_const = UC_ARM64_REG_D28
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_D29(Register):
    def __init__(self):
        self.name = 'D29'
        self.uc_const = UC_ARM64_REG_D29
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_D3(Register):
    def __init__(self):
        self.name = 'D3'
        self.uc_const = UC_ARM64_REG_D3
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_D30(Register):
    def __init__(self):
        self.name = 'D30'
        self.uc_const = UC_ARM64_REG_D30
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_D31(Register):
    def __init__(self):
        self.name = 'D31'
        self.uc_const = UC_ARM64_REG_D31
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_D4(Register):
    def __init__(self):
        self.name = 'D4'
        self.uc_const = UC_ARM64_REG_D4
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_D5(Register):
    def __init__(self):
        self.name = 'D5'
        self.uc_const = UC_ARM64_REG_D5
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_D6(Register):
    def __init__(self):
        self.name = 'D6'
        self.uc_const = UC_ARM64_REG_D6
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_D7(Register):
    def __init__(self):
        self.name = 'D7'
        self.uc_const = UC_ARM64_REG_D7
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_D8(Register):
    def __init__(self):
        self.name = 'D8'
        self.uc_const = UC_ARM64_REG_D8
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_D9(Register):
    def __init__(self):
        self.name = 'D9'
        self.uc_const = UC_ARM64_REG_D9
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_FP(Register):
    def __init__(self):
        self.name = 'FP'
        self.uc_const = UC_ARM64_REG_FP
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_H0(Register):
    def __init__(self):
        self.name = 'H0'
        self.uc_const = UC_ARM64_REG_H0
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class ARM64_REG_H1(Register):
    def __init__(self):
        self.name = 'H1'
        self.uc_const = UC_ARM64_REG_H1
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class ARM64_REG_H10(Register):
    def __init__(self):
        self.name = 'H10'
        self.uc_const = UC_ARM64_REG_H10
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class ARM64_REG_H11(Register):
    def __init__(self):
        self.name = 'H11'
        self.uc_const = UC_ARM64_REG_H11
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class ARM64_REG_H12(Register):
    def __init__(self):
        self.name = 'H12'
        self.uc_const = UC_ARM64_REG_H12
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class ARM64_REG_H13(Register):
    def __init__(self):
        self.name = 'H13'
        self.uc_const = UC_ARM64_REG_H13
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class ARM64_REG_H14(Register):
    def __init__(self):
        self.name = 'H14'
        self.uc_const = UC_ARM64_REG_H14
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class ARM64_REG_H15(Register):
    def __init__(self):
        self.name = 'H15'
        self.uc_const = UC_ARM64_REG_H15
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class ARM64_REG_H16(Register):
    def __init__(self):
        self.name = 'H16'
        self.uc_const = UC_ARM64_REG_H16
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class ARM64_REG_H17(Register):
    def __init__(self):
        self.name = 'H17'
        self.uc_const = UC_ARM64_REG_H17
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class ARM64_REG_H18(Register):
    def __init__(self):
        self.name = 'H18'
        self.uc_const = UC_ARM64_REG_H18
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class ARM64_REG_H19(Register):
    def __init__(self):
        self.name = 'H19'
        self.uc_const = UC_ARM64_REG_H19
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class ARM64_REG_H2(Register):
    def __init__(self):
        self.name = 'H2'
        self.uc_const = UC_ARM64_REG_H2
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class ARM64_REG_H20(Register):
    def __init__(self):
        self.name = 'H20'
        self.uc_const = UC_ARM64_REG_H20
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class ARM64_REG_H21(Register):
    def __init__(self):
        self.name = 'H21'
        self.uc_const = UC_ARM64_REG_H21
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class ARM64_REG_H22(Register):
    def __init__(self):
        self.name = 'H22'
        self.uc_const = UC_ARM64_REG_H22
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class ARM64_REG_H23(Register):
    def __init__(self):
        self.name = 'H23'
        self.uc_const = UC_ARM64_REG_H23
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class ARM64_REG_H24(Register):
    def __init__(self):
        self.name = 'H24'
        self.uc_const = UC_ARM64_REG_H24
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class ARM64_REG_H25(Register):
    def __init__(self):
        self.name = 'H25'
        self.uc_const = UC_ARM64_REG_H25
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class ARM64_REG_H26(Register):
    def __init__(self):
        self.name = 'H26'
        self.uc_const = UC_ARM64_REG_H26
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class ARM64_REG_H27(Register):
    def __init__(self):
        self.name = 'H27'
        self.uc_const = UC_ARM64_REG_H27
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class ARM64_REG_H28(Register):
    def __init__(self):
        self.name = 'H28'
        self.uc_const = UC_ARM64_REG_H28
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class ARM64_REG_H29(Register):
    def __init__(self):
        self.name = 'H29'
        self.uc_const = UC_ARM64_REG_H29
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class ARM64_REG_H3(Register):
    def __init__(self):
        self.name = 'H3'
        self.uc_const = UC_ARM64_REG_H3
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class ARM64_REG_H30(Register):
    def __init__(self):
        self.name = 'H30'
        self.uc_const = UC_ARM64_REG_H30
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class ARM64_REG_H31(Register):
    def __init__(self):
        self.name = 'H31'
        self.uc_const = UC_ARM64_REG_H31
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class ARM64_REG_H4(Register):
    def __init__(self):
        self.name = 'H4'
        self.uc_const = UC_ARM64_REG_H4
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class ARM64_REG_H5(Register):
    def __init__(self):
        self.name = 'H5'
        self.uc_const = UC_ARM64_REG_H5
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class ARM64_REG_H6(Register):
    def __init__(self):
        self.name = 'H6'
        self.uc_const = UC_ARM64_REG_H6
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class ARM64_REG_H7(Register):
    def __init__(self):
        self.name = 'H7'
        self.uc_const = UC_ARM64_REG_H7
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class ARM64_REG_H8(Register):
    def __init__(self):
        self.name = 'H8'
        self.uc_const = UC_ARM64_REG_H8
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class ARM64_REG_H9(Register):
    def __init__(self):
        self.name = 'H9'
        self.uc_const = UC_ARM64_REG_H9
        self.bits = 16
        self.structure = [16]
        self.value = None
        self.address = None


class ARM64_REG_IP0(Register):
    def __init__(self):
        self.name = 'IP0'
        self.uc_const = UC_ARM64_REG_IP0
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_IP1(Register):
    def __init__(self):
        self.name = 'IP1'
        self.uc_const = UC_ARM64_REG_IP1
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_LR(Register):
    def __init__(self):
        self.name = 'LR'
        self.uc_const = UC_ARM64_REG_LR
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_NZCV(Register):
    def __init__(self):
        self.name = 'NZCV'
        self.uc_const = UC_ARM64_REG_NZCV
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_PC(Register):
    def __init__(self):
        self.name = 'PC'
        self.uc_const = UC_ARM64_REG_PC
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_Q0(Register):
    def __init__(self):
        self.name = 'Q0'
        self.uc_const = UC_ARM64_REG_Q0
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_Q1(Register):
    def __init__(self):
        self.name = 'Q1'
        self.uc_const = UC_ARM64_REG_Q1
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_Q10(Register):
    def __init__(self):
        self.name = 'Q10'
        self.uc_const = UC_ARM64_REG_Q10
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_Q11(Register):
    def __init__(self):
        self.name = 'Q11'
        self.uc_const = UC_ARM64_REG_Q11
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_Q12(Register):
    def __init__(self):
        self.name = 'Q12'
        self.uc_const = UC_ARM64_REG_Q12
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_Q13(Register):
    def __init__(self):
        self.name = 'Q13'
        self.uc_const = UC_ARM64_REG_Q13
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_Q14(Register):
    def __init__(self):
        self.name = 'Q14'
        self.uc_const = UC_ARM64_REG_Q14
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_Q15(Register):
    def __init__(self):
        self.name = 'Q15'
        self.uc_const = UC_ARM64_REG_Q15
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_Q16(Register):
    def __init__(self):
        self.name = 'Q16'
        self.uc_const = UC_ARM64_REG_Q16
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_Q17(Register):
    def __init__(self):
        self.name = 'Q17'
        self.uc_const = UC_ARM64_REG_Q17
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_Q18(Register):
    def __init__(self):
        self.name = 'Q18'
        self.uc_const = UC_ARM64_REG_Q18
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_Q19(Register):
    def __init__(self):
        self.name = 'Q19'
        self.uc_const = UC_ARM64_REG_Q19
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_Q2(Register):
    def __init__(self):
        self.name = 'Q2'
        self.uc_const = UC_ARM64_REG_Q2
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_Q20(Register):
    def __init__(self):
        self.name = 'Q20'
        self.uc_const = UC_ARM64_REG_Q20
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_Q21(Register):
    def __init__(self):
        self.name = 'Q21'
        self.uc_const = UC_ARM64_REG_Q21
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_Q22(Register):
    def __init__(self):
        self.name = 'Q22'
        self.uc_const = UC_ARM64_REG_Q22
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_Q23(Register):
    def __init__(self):
        self.name = 'Q23'
        self.uc_const = UC_ARM64_REG_Q23
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_Q24(Register):
    def __init__(self):
        self.name = 'Q24'
        self.uc_const = UC_ARM64_REG_Q24
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_Q25(Register):
    def __init__(self):
        self.name = 'Q25'
        self.uc_const = UC_ARM64_REG_Q25
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_Q26(Register):
    def __init__(self):
        self.name = 'Q26'
        self.uc_const = UC_ARM64_REG_Q26
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_Q27(Register):
    def __init__(self):
        self.name = 'Q27'
        self.uc_const = UC_ARM64_REG_Q27
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_Q28(Register):
    def __init__(self):
        self.name = 'Q28'
        self.uc_const = UC_ARM64_REG_Q28
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_Q29(Register):
    def __init__(self):
        self.name = 'Q29'
        self.uc_const = UC_ARM64_REG_Q29
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_Q3(Register):
    def __init__(self):
        self.name = 'Q3'
        self.uc_const = UC_ARM64_REG_Q3
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_Q30(Register):
    def __init__(self):
        self.name = 'Q30'
        self.uc_const = UC_ARM64_REG_Q30
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_Q31(Register):
    def __init__(self):
        self.name = 'Q31'
        self.uc_const = UC_ARM64_REG_Q31
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_Q4(Register):
    def __init__(self):
        self.name = 'Q4'
        self.uc_const = UC_ARM64_REG_Q4
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_Q5(Register):
    def __init__(self):
        self.name = 'Q5'
        self.uc_const = UC_ARM64_REG_Q5
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_Q6(Register):
    def __init__(self):
        self.name = 'Q6'
        self.uc_const = UC_ARM64_REG_Q6
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_Q7(Register):
    def __init__(self):
        self.name = 'Q7'
        self.uc_const = UC_ARM64_REG_Q7
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_Q8(Register):
    def __init__(self):
        self.name = 'Q8'
        self.uc_const = UC_ARM64_REG_Q8
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_Q9(Register):
    def __init__(self):
        self.name = 'Q9'
        self.uc_const = UC_ARM64_REG_Q9
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_S0(Register):
    def __init__(self):
        self.name = 'S0'
        self.uc_const = UC_ARM64_REG_S0
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_S1(Register):
    def __init__(self):
        self.name = 'S1'
        self.uc_const = UC_ARM64_REG_S1
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_S10(Register):
    def __init__(self):
        self.name = 'S10'
        self.uc_const = UC_ARM64_REG_S10
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_S11(Register):
    def __init__(self):
        self.name = 'S11'
        self.uc_const = UC_ARM64_REG_S11
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_S12(Register):
    def __init__(self):
        self.name = 'S12'
        self.uc_const = UC_ARM64_REG_S12
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_S13(Register):
    def __init__(self):
        self.name = 'S13'
        self.uc_const = UC_ARM64_REG_S13
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_S14(Register):
    def __init__(self):
        self.name = 'S14'
        self.uc_const = UC_ARM64_REG_S14
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_S15(Register):
    def __init__(self):
        self.name = 'S15'
        self.uc_const = UC_ARM64_REG_S15
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_S16(Register):
    def __init__(self):
        self.name = 'S16'
        self.uc_const = UC_ARM64_REG_S16
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_S17(Register):
    def __init__(self):
        self.name = 'S17'
        self.uc_const = UC_ARM64_REG_S17
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_S18(Register):
    def __init__(self):
        self.name = 'S18'
        self.uc_const = UC_ARM64_REG_S18
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_S19(Register):
    def __init__(self):
        self.name = 'S19'
        self.uc_const = UC_ARM64_REG_S19
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_S2(Register):
    def __init__(self):
        self.name = 'S2'
        self.uc_const = UC_ARM64_REG_S2
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_S20(Register):
    def __init__(self):
        self.name = 'S20'
        self.uc_const = UC_ARM64_REG_S20
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_S21(Register):
    def __init__(self):
        self.name = 'S21'
        self.uc_const = UC_ARM64_REG_S21
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_S22(Register):
    def __init__(self):
        self.name = 'S22'
        self.uc_const = UC_ARM64_REG_S22
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_S23(Register):
    def __init__(self):
        self.name = 'S23'
        self.uc_const = UC_ARM64_REG_S23
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_S24(Register):
    def __init__(self):
        self.name = 'S24'
        self.uc_const = UC_ARM64_REG_S24
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_S25(Register):
    def __init__(self):
        self.name = 'S25'
        self.uc_const = UC_ARM64_REG_S25
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_S26(Register):
    def __init__(self):
        self.name = 'S26'
        self.uc_const = UC_ARM64_REG_S26
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_S27(Register):
    def __init__(self):
        self.name = 'S27'
        self.uc_const = UC_ARM64_REG_S27
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_S28(Register):
    def __init__(self):
        self.name = 'S28'
        self.uc_const = UC_ARM64_REG_S28
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_S29(Register):
    def __init__(self):
        self.name = 'S29'
        self.uc_const = UC_ARM64_REG_S29
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_S3(Register):
    def __init__(self):
        self.name = 'S3'
        self.uc_const = UC_ARM64_REG_S3
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_S30(Register):
    def __init__(self):
        self.name = 'S30'
        self.uc_const = UC_ARM64_REG_S30
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_S31(Register):
    def __init__(self):
        self.name = 'S31'
        self.uc_const = UC_ARM64_REG_S31
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_S4(Register):
    def __init__(self):
        self.name = 'S4'
        self.uc_const = UC_ARM64_REG_S4
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_S5(Register):
    def __init__(self):
        self.name = 'S5'
        self.uc_const = UC_ARM64_REG_S5
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_S6(Register):
    def __init__(self):
        self.name = 'S6'
        self.uc_const = UC_ARM64_REG_S6
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_S7(Register):
    def __init__(self):
        self.name = 'S7'
        self.uc_const = UC_ARM64_REG_S7
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_S8(Register):
    def __init__(self):
        self.name = 'S8'
        self.uc_const = UC_ARM64_REG_S8
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_S9(Register):
    def __init__(self):
        self.name = 'S9'
        self.uc_const = UC_ARM64_REG_S9
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_SP(Register):
    def __init__(self):
        self.name = 'SP'
        self.uc_const = UC_ARM64_REG_SP
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_TPIDRRO_EL0(Register):
    def __init__(self):
        self.name = 'EL0'
        self.uc_const = UC_ARM64_REG_TPIDRRO_EL0
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_TPIDR_EL0(Register):
    def __init__(self):
        self.name = 'EL0'
        self.uc_const = UC_ARM64_REG_TPIDR_EL0
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_TPIDR_EL1(Register):
    def __init__(self):
        self.name = 'EL1'
        self.uc_const = UC_ARM64_REG_TPIDR_EL1
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_V0(Register):
    def __init__(self):
        self.name = 'V0'
        self.uc_const = UC_ARM64_REG_V0
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_V1(Register):
    def __init__(self):
        self.name = 'V1'
        self.uc_const = UC_ARM64_REG_V1
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_V10(Register):
    def __init__(self):
        self.name = 'V10'
        self.uc_const = UC_ARM64_REG_V10
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_V11(Register):
    def __init__(self):
        self.name = 'V11'
        self.uc_const = UC_ARM64_REG_V11
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_V12(Register):
    def __init__(self):
        self.name = 'V12'
        self.uc_const = UC_ARM64_REG_V12
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_V13(Register):
    def __init__(self):
        self.name = 'V13'
        self.uc_const = UC_ARM64_REG_V13
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_V14(Register):
    def __init__(self):
        self.name = 'V14'
        self.uc_const = UC_ARM64_REG_V14
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_V15(Register):
    def __init__(self):
        self.name = 'V15'
        self.uc_const = UC_ARM64_REG_V15
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_V16(Register):
    def __init__(self):
        self.name = 'V16'
        self.uc_const = UC_ARM64_REG_V16
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_V17(Register):
    def __init__(self):
        self.name = 'V17'
        self.uc_const = UC_ARM64_REG_V17
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_V18(Register):
    def __init__(self):
        self.name = 'V18'
        self.uc_const = UC_ARM64_REG_V18
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_V19(Register):
    def __init__(self):
        self.name = 'V19'
        self.uc_const = UC_ARM64_REG_V19
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_V2(Register):
    def __init__(self):
        self.name = 'V2'
        self.uc_const = UC_ARM64_REG_V2
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_V20(Register):
    def __init__(self):
        self.name = 'V20'
        self.uc_const = UC_ARM64_REG_V20
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_V21(Register):
    def __init__(self):
        self.name = 'V21'
        self.uc_const = UC_ARM64_REG_V21
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_V22(Register):
    def __init__(self):
        self.name = 'V22'
        self.uc_const = UC_ARM64_REG_V22
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_V23(Register):
    def __init__(self):
        self.name = 'V23'
        self.uc_const = UC_ARM64_REG_V23
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_V24(Register):
    def __init__(self):
        self.name = 'V24'
        self.uc_const = UC_ARM64_REG_V24
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_V25(Register):
    def __init__(self):
        self.name = 'V25'
        self.uc_const = UC_ARM64_REG_V25
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_V26(Register):
    def __init__(self):
        self.name = 'V26'
        self.uc_const = UC_ARM64_REG_V26
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_V27(Register):
    def __init__(self):
        self.name = 'V27'
        self.uc_const = UC_ARM64_REG_V27
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_V28(Register):
    def __init__(self):
        self.name = 'V28'
        self.uc_const = UC_ARM64_REG_V28
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_V29(Register):
    def __init__(self):
        self.name = 'V29'
        self.uc_const = UC_ARM64_REG_V29
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_V3(Register):
    def __init__(self):
        self.name = 'V3'
        self.uc_const = UC_ARM64_REG_V3
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_V30(Register):
    def __init__(self):
        self.name = 'V30'
        self.uc_const = UC_ARM64_REG_V30
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_V31(Register):
    def __init__(self):
        self.name = 'V31'
        self.uc_const = UC_ARM64_REG_V31
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_V4(Register):
    def __init__(self):
        self.name = 'V4'
        self.uc_const = UC_ARM64_REG_V4
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_V5(Register):
    def __init__(self):
        self.name = 'V5'
        self.uc_const = UC_ARM64_REG_V5
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_V6(Register):
    def __init__(self):
        self.name = 'V6'
        self.uc_const = UC_ARM64_REG_V6
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_V7(Register):
    def __init__(self):
        self.name = 'V7'
        self.uc_const = UC_ARM64_REG_V7
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_V8(Register):
    def __init__(self):
        self.name = 'V8'
        self.uc_const = UC_ARM64_REG_V8
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_V9(Register):
    def __init__(self):
        self.name = 'V9'
        self.uc_const = UC_ARM64_REG_V9
        self.bits = 128
        self.structure = [128]
        self.value = None
        self.address = None


class ARM64_REG_W0(Register):
    def __init__(self):
        self.name = 'W0'
        self.uc_const = UC_ARM64_REG_W0
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_W1(Register):
    def __init__(self):
        self.name = 'W1'
        self.uc_const = UC_ARM64_REG_W1
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_W10(Register):
    def __init__(self):
        self.name = 'W10'
        self.uc_const = UC_ARM64_REG_W10
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_W11(Register):
    def __init__(self):
        self.name = 'W11'
        self.uc_const = UC_ARM64_REG_W11
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_W12(Register):
    def __init__(self):
        self.name = 'W12'
        self.uc_const = UC_ARM64_REG_W12
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_W13(Register):
    def __init__(self):
        self.name = 'W13'
        self.uc_const = UC_ARM64_REG_W13
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_W14(Register):
    def __init__(self):
        self.name = 'W14'
        self.uc_const = UC_ARM64_REG_W14
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_W15(Register):
    def __init__(self):
        self.name = 'W15'
        self.uc_const = UC_ARM64_REG_W15
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_W16(Register):
    def __init__(self):
        self.name = 'W16'
        self.uc_const = UC_ARM64_REG_W16
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_W17(Register):
    def __init__(self):
        self.name = 'W17'
        self.uc_const = UC_ARM64_REG_W17
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_W18(Register):
    def __init__(self):
        self.name = 'W18'
        self.uc_const = UC_ARM64_REG_W18
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_W19(Register):
    def __init__(self):
        self.name = 'W19'
        self.uc_const = UC_ARM64_REG_W19
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_W2(Register):
    def __init__(self):
        self.name = 'W2'
        self.uc_const = UC_ARM64_REG_W2
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_W20(Register):
    def __init__(self):
        self.name = 'W20'
        self.uc_const = UC_ARM64_REG_W20
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_W21(Register):
    def __init__(self):
        self.name = 'W21'
        self.uc_const = UC_ARM64_REG_W21
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_W22(Register):
    def __init__(self):
        self.name = 'W22'
        self.uc_const = UC_ARM64_REG_W22
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_W23(Register):
    def __init__(self):
        self.name = 'W23'
        self.uc_const = UC_ARM64_REG_W23
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_W24(Register):
    def __init__(self):
        self.name = 'W24'
        self.uc_const = UC_ARM64_REG_W24
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_W25(Register):
    def __init__(self):
        self.name = 'W25'
        self.uc_const = UC_ARM64_REG_W25
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_W26(Register):
    def __init__(self):
        self.name = 'W26'
        self.uc_const = UC_ARM64_REG_W26
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_W27(Register):
    def __init__(self):
        self.name = 'W27'
        self.uc_const = UC_ARM64_REG_W27
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_W28(Register):
    def __init__(self):
        self.name = 'W28'
        self.uc_const = UC_ARM64_REG_W28
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_W29(Register):
    def __init__(self):
        self.name = 'W29'
        self.uc_const = UC_ARM64_REG_W29
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_W3(Register):
    def __init__(self):
        self.name = 'W3'
        self.uc_const = UC_ARM64_REG_W3
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_W30(Register):
    def __init__(self):
        self.name = 'W30'
        self.uc_const = UC_ARM64_REG_W30
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_W4(Register):
    def __init__(self):
        self.name = 'W4'
        self.uc_const = UC_ARM64_REG_W4
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_W5(Register):
    def __init__(self):
        self.name = 'W5'
        self.uc_const = UC_ARM64_REG_W5
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_W6(Register):
    def __init__(self):
        self.name = 'W6'
        self.uc_const = UC_ARM64_REG_W6
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_W7(Register):
    def __init__(self):
        self.name = 'W7'
        self.uc_const = UC_ARM64_REG_W7
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_W8(Register):
    def __init__(self):
        self.name = 'W8'
        self.uc_const = UC_ARM64_REG_W8
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_W9(Register):
    def __init__(self):
        self.name = 'W9'
        self.uc_const = UC_ARM64_REG_W9
        self.bits = 32
        self.structure = [32]
        self.value = None
        self.address = None


class ARM64_REG_X0(Register):
    def __init__(self):
        self.name = 'X0'
        self.uc_const = UC_ARM64_REG_X0
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_X1(Register):
    def __init__(self):
        self.name = 'X1'
        self.uc_const = UC_ARM64_REG_X1
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_X10(Register):
    def __init__(self):
        self.name = 'X10'
        self.uc_const = UC_ARM64_REG_X10
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_X11(Register):
    def __init__(self):
        self.name = 'X11'
        self.uc_const = UC_ARM64_REG_X11
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_X12(Register):
    def __init__(self):
        self.name = 'X12'
        self.uc_const = UC_ARM64_REG_X12
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_X13(Register):
    def __init__(self):
        self.name = 'X13'
        self.uc_const = UC_ARM64_REG_X13
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_X14(Register):
    def __init__(self):
        self.name = 'X14'
        self.uc_const = UC_ARM64_REG_X14
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_X15(Register):
    def __init__(self):
        self.name = 'X15'
        self.uc_const = UC_ARM64_REG_X15
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_X16(Register):
    def __init__(self):
        self.name = 'X16'
        self.uc_const = UC_ARM64_REG_X16
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_X17(Register):
    def __init__(self):
        self.name = 'X17'
        self.uc_const = UC_ARM64_REG_X17
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_X18(Register):
    def __init__(self):
        self.name = 'X18'
        self.uc_const = UC_ARM64_REG_X18
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_X19(Register):
    def __init__(self):
        self.name = 'X19'
        self.uc_const = UC_ARM64_REG_X19
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_X2(Register):
    def __init__(self):
        self.name = 'X2'
        self.uc_const = UC_ARM64_REG_X2
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_X20(Register):
    def __init__(self):
        self.name = 'X20'
        self.uc_const = UC_ARM64_REG_X20
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_X21(Register):
    def __init__(self):
        self.name = 'X21'
        self.uc_const = UC_ARM64_REG_X21
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_X22(Register):
    def __init__(self):
        self.name = 'X22'
        self.uc_const = UC_ARM64_REG_X22
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_X23(Register):
    def __init__(self):
        self.name = 'X23'
        self.uc_const = UC_ARM64_REG_X23
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_X24(Register):
    def __init__(self):
        self.name = 'X24'
        self.uc_const = UC_ARM64_REG_X24
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_X25(Register):
    def __init__(self):
        self.name = 'X25'
        self.uc_const = UC_ARM64_REG_X25
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_X26(Register):
    def __init__(self):
        self.name = 'X26'
        self.uc_const = UC_ARM64_REG_X26
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_X27(Register):
    def __init__(self):
        self.name = 'X27'
        self.uc_const = UC_ARM64_REG_X27
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_X28(Register):
    def __init__(self):
        self.name = 'X28'
        self.uc_const = UC_ARM64_REG_X28
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_X29(Register):
    def __init__(self):
        self.name = 'X29'
        self.uc_const = UC_ARM64_REG_X29
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_X3(Register):
    def __init__(self):
        self.name = 'X3'
        self.uc_const = UC_ARM64_REG_X3
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_X30(Register):
    def __init__(self):
        self.name = 'X30'
        self.uc_const = UC_ARM64_REG_X30
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_X4(Register):
    def __init__(self):
        self.name = 'X4'
        self.uc_const = UC_ARM64_REG_X4
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_X5(Register):
    def __init__(self):
        self.name = 'X5'
        self.uc_const = UC_ARM64_REG_X5
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_X6(Register):
    def __init__(self):
        self.name = 'X6'
        self.uc_const = UC_ARM64_REG_X6
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_X7(Register):
    def __init__(self):
        self.name = 'X7'
        self.uc_const = UC_ARM64_REG_X7
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_X8(Register):
    def __init__(self):
        self.name = 'X8'
        self.uc_const = UC_ARM64_REG_X8
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None


class ARM64_REG_X9(Register):
    def __init__(self):
        self.name = 'X9'
        self.uc_const = UC_ARM64_REG_X9
        self.bits = 64
        self.structure = [64]
        self.value = None
        self.address = None
