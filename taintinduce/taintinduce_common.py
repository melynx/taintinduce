import operator
import sys
import itertools
import json

import squirrel.acorn.acorn as acorn

from taintinduce.isa.arm64_registers import *
from taintinduce.isa.x86_registers import *
from squirrel.isa.registers import MemorySlot, get_register_arch

import pdb

# TODO: All these classes should be shared with engine.py
def query_yes_no(question, default="yes"):
    """Ask a yes/no question via raw_input() and return their answer.
    "question" is a string that is presented to the user.
    "default" is the presumed answer if the user just hits <Enter>.
        It must be "yes" (the default), "no" or None (meaning
        an answer is required of the user).
    The "answer" return value is one of "yes" or "no".
    """
    valid = {"yes":True,   "y":True,  "ye":True,
             "no":False,     "n":False}
    if default == None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = raw_input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "\
                             "(or 'y' or 'n').\n")

def check_ones(value):
    """Obtains the position of bits that are set
    """
    result_set = set()
    pos = 0
    while (value):
        if value & 1:
            result_set.add(pos)
        value>>= 1
        pos += 1
    return result_set

def reg2pos(all_regs, reg):
    ''' Function which convert reg to its start postition in State value
    Attribute:
        all_regs : a list of reg class
        reg: reg class
    Return:
        pos (int) 
    '''
    regs_list = sorted(all_regs, key = lambda reg: reg.uc_const)
    pos = 0
    for r in regs_list:
        if r == reg:
            break
        pos += r.bits
    return pos

def convert2rpn(all_regs, regs, masks, values):
    '''convert reg+mask+values to condition rpn 
    Attribute:
        regs (a list of reg class)
        masks (a list of int): a list of reg mask
        values (a list of int): a list of reg value
    Return:
        rpn (): see Condition class
    '''
    if len(regs) == 1:
        reg  = regs[0]
        mask = masks[0]
        val  = values[0]
        state_mask = mask << reg2pos(all_regs, reg)
        state_val  = val  << reg2pos(all_regs, reg)
        return state_mask, state_val
    elif len(regs) == 2:
        arg = list()
        for reg in regs:
            arg.append(((1<<reg.bits)-1)<<reg2pos(all_regs, reg))
        arg1 = arg[0]
        arg2 = arg[1]
        return arg1, arg2
    else:
        return None, None


def pos2reg(state1, state2, regs):
    ''' trans posval to reg '''
    pos_val = list(state1.diff(state2))
    pos_val = sorted(pos_val, reverse=True)
    regs_list = sorted(regs, key = lambda reg: reg.uc_const)
    pos = 0
    res_regs = set()

    for reg in regs_list:
        bpos = pos
        pos += reg.bits
        while pos_val:
            p = pos_val[-1]
            if p < pos:
                res_regs.add((reg, p-bpos))
                pos_val.pop()
            else:
                break

    return list(res_regs)

def regs2bits(cpustate, state_format):
    ''' Converts CPUState into a State object using state_format
        state: cpu_state dict()
    '''
    bits  = 0
    value = 0
    for reg in state_format:
        value |= cpustate[reg] << bits
        bits  += reg.bits

    return State(bits, value)

def regs2bits2(cpustate, state_format):
    ''' Converts CPUState into a State object using state_format
        state: cpu_state dict()
    '''
    bits  = 0
    value = 0
    for reg in state_format:
        #print('a:{}->{}'.format(bits, cpustate[reg]))
        print('bin:{:0128b}'.format(cpustate[reg]<<bits))
        value |= cpustate[reg] << bits
        bits  += reg.bits

    return State(bits, value)

def bits2regs(state, regs):
    ''' trans state object to cpu_state dict() 
        state: State object
        reg  : regs list
    '''
    cpu_state = dict()
    value = state.state_value
    regs_list = sorted(regs, key = lambda reg: reg.uc_const)
    for reg in regs_list:
        cpu_state[reg] = ((2**reg.bits)-1)&value
        value = value >> reg.bits
    return cpu_state


def bitpos2reg(bitpos, state_format):
    remaining_pos = bitpos
    for reg in state_format:
        remaining_pos -= reg.bits
        if remaining_pos <= 0:
            break
    return reg

def extract_reg2bits(state, reg, state_format):
    reg_start_pos = reg_pos(reg, state_format)
    reg_mask = (1 << reg.bits) - 1

    # mask for the state to isolate the register
    state_mask = reg_mask << reg_start_pos
    isolated_reg_value = state.state_value & state_mask
    reg_value = isolated_reg_value >> reg_start_pos

    return State(reg.bits, reg_value)

def print_bin(value):
    print('{:064b}'.format(value))

def reg_pos(reg, state_format):
    reg_start_pos = 0
    for reg2 in state_format:
        if reg == reg2:
            break
        reg_start_pos += reg2.bits
    return reg_start_pos


'''Some bit manipulation functions
'''
def set_bit(value, pos):
    return value | (1 << pos)

def unset_bit(value, pos):
    return value & (~(1 << pos))

def invert_bit(value, pos):
    return value ^ (1 << pos)

def shift_espresso(espresso_cond, reg, state_format):
    reg_start_pos = reg_pos(reg, state_format)
    new_espresso_cond = set()
    for conditional_bitmask, conditional_value in espresso_cond:
        new_bitmask = conditional_bitmask << reg_start_pos
        new_value = conditional_value << reg_start_pos
        new_espresso_cond.add((new_bitmask, new_value))
    return new_espresso_cond


def espresso2cond(espresso_cond):
    """Converts ESPRESSO conditions into Condition object
    """
    return Condition(('DNF', list(espresso_cond)))

def serialize_list(baseobj_list):
    return [serialize_obj(x) for x in baseobj_list]

def deserialize_list(baseobj_list):
    return [deserialize_obj(x) for x in baseobj_list]

def serialize_obj(myobj):
    return (myobj.__class__.__name__, repr(myobj))

def deserialize_obj(serialized_str):
    #print(serialized_str)
    class_name, obj_str = serialized_str
    class_obj = globals()[class_name]()
    class_obj.deserialize(obj_str)
    return class_obj

class State(acorn.Acorn):
    """Represention of the input / output of an instruction.
    Attributes:
        num_bits (int): Size of state in number of bits.
        state_bits (int): Bitvector to represent the state stored as an integer.
    """

    def __init__(self, num_bits=None, state_value=None, repr_str=None):
        """Initializes the State object to length num_bits.
        
        The __init__ method takes in an argument num_bits and initializes the state_array.
        
        Args:
            num_bits (int): Size of State in bits.
            state_value (int): Integer value representing the bit array.
        Returns:
            None
        Raises:
            None
        """

        if repr_str:
            self.deserialize(repr_str)
        else:
            self.num_bits = num_bits
            self.state_value = state_value

    def __str__(self):
        """Produces the corresponding bit string for the given state.
        Args:
            None
        Returns:
            A bitstring representing the state. For example, for the argument (8, 2), the corresponding string returned
                is "00000010"
        """

        bitstring = '{{:<0{}b}}'.format(self.num_bits).format(self.state_value)
        return bitstring

    def diff(self, other_state):
        """Obtains the difference between two States.
        Args:
            other_state (State): The other state which we will be comparing against.
        
        Returns:
            A set of integers which identifies which position are different between the two States.
        """

        value_changed = self.state_value ^ other_state.state_value
        result_set = check_ones(value_changed)

        return result_set

class Observation(acorn.Acorn):
    """Collection of states that represents a single observation.
    Made up of an initial input seed state, followed by a set of mutated states obtained by performing a single bit-flip.
    For each state, an 'output' state is included forming a tuple (input_state, output_state) called IOPair. 
    Attributes:
        seed_io (IOPair): A tuple representing the seed state. (input_state, output_state).
        mutated_ios (list of IOPair): A list containing all IOPairs of mutated states.
    """

    def __init__(self, iopair=None, mutated_iopairs=None, bytestring=None, archstring=None, state_format=None, repr_str=None):
        """Initializes the Observation object with the .
        
        The __init__ method takes in an argument num_bits and initializes the state_array
        
        Args:
            iopair ((State, State)): seed_state of the form (input_state, output_state)
            mutated_iopairs (list of (State, State)): list of tuple of mutated States of the form [(in_1, out_1), ...]
        Returns:
            None
        Raises:
            None
        """

        if repr_str:
            self.deserialize(repr_str)
        else:
            self.seed_io = iopair
            self.mutated_ios = mutated_iopairs
            self.bytestring = bytestring
            self.archstring = archstring
            self.state_format = state_format

class Condition(acorn.Acorn):
    """Condition is a class that represents a condition bisecting a partition into two.

    Attributes:
        OPS_FN_MAP (dict{String: String}): A mapping that maps the operation string to its function name.

    The condition is represented as a tuple containing the operator in string and 
    a list of the arguments to be performed based on the operator. (String, [])
    For example, a DNF can be represented as [('DNF', [(1024, 0),(64,1),...]), ...]
    """
    OPS_FN_MAP = {'DNF': '_dnf_eval',
                  'LOGIC': '_logic_eval',
                  'CMP': '_cmp_eval'}

    def __init__(self, conditions=None, repr_str=None):
        if repr_str:
            self.deserialize(repr_str)
        else:
            self.condition_ops = conditions

    def eval(self, state):
        """The eval() method takes in a State object and checks if the condition evaluates to True or False.
        Args:
            state (State): The State object to which the condition is being evaluated on.
        Returns:
            True if the condition evaluates is satisfied else False.
        Raises:
            None
        """
        result = True
        ops_name, ops_args = self.condition_ops
        result &= getattr(self, self.OPS_FN_MAP[ops_name])(state, ops_args)
        return result

    def get_cond_bits(self):
        ops_name, ops_args = self.condition_ops
        cond_bits = set()
        if ops_name == "DNF":
            for mask, _ in ops_args:
                cond_bits |= check_ones(mask)
        return cond_bits


    def _dnf_eval(self, state, dnf_args):
        result = any([(state.state_value & bitmask == value) for bitmask, value in dnf_args])
        return result


    def _logic_eval(self, state, logic_args):
        raise Exception('Not yet implemented!')

    def _cmp_eval(self, state, cmp_args):
        raise Exception('Not yet implemented!')


def reg2memslot(reg):
    assert('MEM' in reg.name)
    mem_access = None
    mem_slot = None
    q = reg.name.split('_')
    mem_type = MemorySlot.ADDR if len(q) == 3 else MemorySlot.VALUE
    t = q[1]
    if 'WRITE' in t:
        mem_access = MemorySlot.WRITE
        mem_slot = int(t[5:])
    elif 'READ' in t:
        mem_access = MemorySlot.READ
        mem_slot = int(t[4:])
    mem_size = reg.bits // 8
    #pdb.set_trace()
    temp_mem = MemorySlot.get_mem(mem_slot, mem_access, mem_size, mem_type)
    return temp_mem


class Rule(acorn.Acorn):
    """Object which represents how data is propagated within a blackbox function.
            
    Attributes:
        state_format (list of Register): a list of registers that defines the format of the state.
        conditions (list of Condition): a list of strings which represents the condition (reverse polish notation)
        dataflows ({True:{int: set(int)}}, False:{int:set(int)}): a list of dictionaries with key being the bit position being used and the set being the bit position
            being defined. 
    """

    def __init__(self, state_format=None, conditions=None, dataflows=None, repr_str=None):
        if repr_str:
            self.deserialize(repr_str)
        else:
            self.state_format = state_format
            self.conditions = conditions
            self.dataflows = dataflows

    def convert2squirrel(self, archstring):
        g = archstring
        ISARegister = get_register_arch(g)
        reg_list = []
        mem_list = []
        for reg in self.state_format:
            if 'MEM' in reg.name:
                mem_list.append(reg2memslot(reg))
            else:
                sq_reg = ISARegister.get_reg(reg.name)
                reg_list.append(sq_reg)
        state_format = acorn.StateFormat(g, reg_list, mem_list)
        condition_list = []
        for condition in self.conditions:
            op, data = condition.condition_ops
            if 'DNF' in op:
                op = acorn.Condition.CondOps.DNF
            else:
                raise Exception('Illegal condition ops')
            condition_list.append(acorn.Condition(op, data))
        taintrule = acorn.TaintRule(state_format, condition_list)

        for df_id, dataflow in enumerate(self.dataflows):
            for src_pos in dataflow:
                taintrule.dataflows[df_id][src_pos] = dataflow[src_pos].copy()
        return taintrule

    def web_string(self):
        mystr_list = []
        mystr_list.append(str(self.state_format))
        mystr_list.append('')
        dep_list = list(itertools.izip_longest(self.conditions, self.dataflows))
        for condition, dataflow in dep_list:
            mystr_list.append('Condition:')
            mystr_list.append('{}'.format(condition))
            mystr_list.append('')
            mystr_list.append('Dataflows: &lt;in bit&gt; &rarr; &lt;out bit&gt;')
            for def_bit in dataflow:
                mystr_list.append('{} &rarr; {}'.format(def_bit, dataflow[def_bit]))
        return '<br/>'.join(mystr_list)


class InsnInfo(acorn.Acorn):
    def __init__(self, archstring=None, bytestring=None, state_format=None, cond_reg=None, repr_str=None):
        if repr_str:
            self.deserialize(repr_str)
        else:
            self.archstring = archstring
            self.bytestring = bytestring
            self.state_format = state_format
            self.cond_reg = cond_reg
