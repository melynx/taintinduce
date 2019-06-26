from unicorn import *
#from unicorn.x86_const import *
from capstone import *
from keystone import *

class Register(object):
    structure = []
    def __init__(self):
        self.name = None
        self.uc_const = None
        self.bits = None
        self.structure = None
        self.value = None
        self.address = None

    def __repr__(self):
        return str(self.__dict__)

    def __hash__(self):
        return hash(self.uc_const)

    def __eq__(self, other):
        return (self.uc_const == other.uc_const)

    def __ne__(self, other):
        return not(self == other)

class ISA(object):
    name = None
    cpu_regs = None

    def __init__(self):
        pass

    def name2reg(self, name):
        pass

    def create_full_reg(self, name, bits=0, structure=[]):
        pass

