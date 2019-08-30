
import binascii
from binascii import unhexlify

from taintinduce.isa.x86_registers import *
from taintinduce.isa.arm64_registers import *

from taintinduce.observation_engine.strategy import *

from taintinduce.isa.x86 import *
from taintinduce.isa.amd64 import *
from taintinduce.isa.arm64 import *

from . import cpu

import unicorn
import capstone
import keystone

import random
import struct
import sys
import pdb

def is_overlap(x1,x2,y1,y2):
    return x1 <= y2 and y1 <= x2

def sign2unsign(value, bits):
    if value >= 0:
        return value
    return (value+2**(bits-1)) | 2**(bits-1)


def filter_address(address, size, state):
    if state[2] != None:
        # the previous address check resulted in a cross page access
        if(not is_overlap(address, address+size, state[0], state[1])):
            pdb.set_trace()
        # we'll remove the current accessed set from the intended access set
        current = set(range(address, address+size))
        state[2].difference_update(current)
        if len(state[2]) == 0:
            state[0] = None
            state[1] = None
            state[2] = None
        return False

    # check if address cross two page
    start_page = address & ~0b111111111111
    end_page = (address+size) & ~0b111111111111
    if start_page != end_page:
        state[0] = address
        state[1] = address + size
        state[2] = set(range(state[0], state[1]))
    return True

def is_increase(address, size, state):
    addr_end = address + size
    # [0] - start, [1] - size, [2] - merge
    #print('{} -- {}'.format(state, (address,size)))

    # first memory access
    if all([x == None for x in state]):
        state[0] = address
        state[1] = size
        state[2] = False
        return True

    if state[0] + state[1] == address:
        # consective memory...
        state[1] = state[1] + size      # update size
        state[2] = True                 # we just merged
    elif (state[0] <= address and addr_end <= state[0] + state[1]):
        # access within the bounds of 2 previous accesses
        # probably a cross page mem access
        state[2] = False
    else:
        state[0] = address
        state[1] = size
        state[2] = False
        return True
    return False


def long_to_bytes (val, bits, endianness='little'):
    """
    Use :ref:`string formatting` and :func:`~binascii.unhexlify` to
    convert ``val``, a :func:`long`, to a byte :func:`str`.

    :param long val: The value to pack
    :param str endianness: The endianness of the result. ``'big'`` for
      big-endian, ``'little'`` for little-endian.

    If you want byte- and word-ordering to differ, you're on your own.
    Using :ref:`string formatting` lets us use Python's C innards.
    """

    # one (1) hex digit per four (4) bits
    width = bits
    # unhexlify wants an even multiple of eight (8) bits, but we don't
    # want more digits than we need (hence the ternary-ish 'or')
    width += 8 - ((width % 8) or 8)
    # format width specifier: four (4) bits per hex digit
    fmt = '%%0%dx' % (width // 4)
    # prepend zero (0) to the width, to zero-pad the output
    s = unhexlify(fmt % val)
    if endianness == 'little':
        # see http://stackoverflow.com/a/931095/309233
        s = s[::-1]
    return s

class OutOfRangeException(Exception):
    pass

class UnicornCPU(cpu.CPU):
    def __init__(self, archstring, debug=False):
        self.debug = debug
        self.arch = globals()[archstring]()
        self.ks = keystone.Ks(self.arch.ks_arch[0], self.arch.ks_arch[1])
        self.mu = unicorn.Uc(self.arch.uc_arch[0], self.arch.uc_arch[1])
        self.md = capstone.Cs(self.arch.cs_arch[0], self.arch.cs_arch[1])


        self.pc_reg     = self.arch.pc_reg
        self.state_reg  = self.arch.state_reg
        self.cpu_regs   = self.arch.cpu_regs
        self.mem_regs   = {}
        self.mem_addrs  = {}

        self.mu.mem_map(self.arch.code_addr, self.arch.code_mem)
        self._mem_invalid_hook = self.mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, self._invalid_mem)
        #self._mem_invalid_hook2 = self.mu.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, self._invalid_mem_fetch)
        self._code_hook = self.mu.hook_add(UC_HOOK_CODE, self._code_hook, None, self.arch.code_addr, self.arch.code_addr + self.arch.code_mem)

        self.pages = set()

        # TODO: have to figure out how to remove this state... :(
        #self.rw_struct = [[0,0],[None, None, None], False]
        self.rw_struct = [[0,0],[None, None, False], False]
        self._mem_rw_hook = self.mu.hook_add(UC_HOOK_MEM_WRITE |
                                             UC_HOOK_MEM_READ, self._mem_hook, self.rw_struct)
        pass

    def _code_hook(self, uc, address, size, user_data):
        if self.rep_cnt < 1:
            self.rep_cnt += 1
        else:
            self.mu.emu_stop()
        return True

    def _invalid_mem_fetch(self, uc, access, address, size, value, user_data):
        print('Invalid Mem fetch: {}'.format(hex(address)))
        return True

    def _invalid_mem(self, uc, access, address, size, value, user_data):
        #print('Invalid Mem: {}'.format(hex(address)))
        page_addresses = set()
        page_addresses.add(address & ~0b111111111111)
        page_addresses.add(address+size & ~0b111111111111)
        for page_address in page_addresses:
            uc.mem_map(page_address, 4096)
            #for x in range(4096):
            #    uc.mem_write(page_address+x, '\x04')
            self.pages.add(page_address)
        return True

    def _mem_read(self, address, size, value, count):
        mem_reg_name = 'MEM_READ{}'.format(count)
        mem_reg = globals()['X86_{}'.format(mem_reg_name)]()
        mem_addr_reg = globals()['X86_{}_ADDR{}'.format(mem_reg_name,
            self.arch.addr_space)]()
        assert(mem_reg)
        try:
            self.mu.mem_write(address, long_to_bytes(self.mem_regs[mem_reg], size*8))
            self.mem_addrs[mem_addr_reg] = address
        except Exception as e:
            #print(self.mem_regs[mem_reg])
            print(e)
        return True

    def _mem_write(self, address, size, value, count):
        mem_reg_name = 'MEM_WRITE{}'.format(count)
        mem_reg = globals()['X86_{}'.format(mem_reg_name)]()
        mem_addr_reg = globals()['X86_{}_ADDR{}'.format(mem_reg_name,
            self.arch.addr_space)]()
        assert(mem_reg)
        self.write_reg(mem_reg, value)
        self.mem_addrs[mem_addr_reg] = address
        return True

    def _mem_hook(self, uc, access, address, size, value, user_data):
        # check if address is valid
        if user_data[2] or address + size >= 2**self.arch.addr_space:
            user_data[2] = True
            #print("Hook: OutOfRange!")
            return False
        #if not filter_address(address, size, user_data[1]):
        #    #print('skip')
        #    return True
        value = sign2unsign(value, size*8)
        if is_increase(address, size, user_data[1]):
            if access == UC_MEM_READ:
                user_data[0][0] += 1
            elif access == UC_MEM_WRITE:
                user_data[0][1] += 1
        if access == UC_MEM_READ:
            #user_data[0][0] += 1
            self._mem_read(address, size, value, user_data[0][0])
        elif access == UC_MEM_WRITE:
            #user_data[0][1] += 1
            self._mem_write(address, size, value, user_data[0][1])
        else:
            raise Exception("Unhandled access type in mem_hook!")
        return True


    def _test_mem(self, uc, access, address, size, value, user_data):
        #print("addr:{}".format(hex(address)))
        #print('access:{}'.format(access))
        #print('size:{}'.format(size))
        #pdb.set_trace()
        mem_access, state = user_data
        value = sign2unsign(value, size*8)
        if (filter_address(address, size, state)):
            mem_access[address] = (access, size, value)
        return True

    def identify_memops_jump(self, code):
        print('Identifying memops')
        jump_reg = None
        mem_set_set = set()
        mem_access = {}
        state = [None, None, None]
        test_mem_state = (mem_access, state)
        h = self.mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
                             self._test_mem, test_mem_state)
        self.mu.hook_del(self._mem_rw_hook)

        count = 0
        fail = 0
        while count < 100:
            mem_set = set()
            mem_access.clear()
            state[0] = None
            state[1] = None
            state[2] = None
            self.randomize_regs()
            try:
                sa, sb = self.execute(code)
            except UcError as e:
                #print(e)
                #print(e.errno)
                fail += 1
                if fail < 10000:
                    continue
                else:
                    raise Exception('Failed a total of 10000 times in identify memops')
            except OutOfRangeException as e:
                continue
            start_pc = sa[self.pc_reg]
            end_pc = sb[self.pc_reg]
            if start_pc != end_pc - len(code) and start_pc != end_pc:
                #print('{:064b} - {}'.format(start_pc,start_pc))
                #print('{:064b} - {}'.format(end_pc,end_pc))
                #print('len:{}'.format(len(code)))
                jump_reg = self.pc_reg

            count += 1

            # process mem_access to obtain number of memory access
            # we'll try to consolidate the memory accesses
            # each memory access is represented as a range

            # we'll check memory using filter_address instead of is_increase
            # the two methods should agree...

            # [0] - addr, [1] - size, [2] - value (not in use)
            temp_mem_addr = set()
            for addr in mem_access:
                temp_mem_addr.add((addr, addr+mem_access[addr][1]))

            # ensure that none of the range overlap
            # while doing that, merge consecutive filtered address...
            temp_mem_addr = list(temp_mem_addr)
            temp_mem_addr.sort(key=lambda x : x[0])

            for x_idx in range(len(temp_mem_addr[:-1])):
                if temp_mem_addr[x_idx][1] > temp_mem_addr[x_idx+1][0]:
                    pdb.set_trace()
                    raise Exception
                elif temp_mem_addr[x_idx][1] == temp_mem_addr[x_idx+1][0]:
                    chunk1_addr     = temp_mem_addr[x_idx][0]
                    chunk1_access   = mem_access[chunk1_addr][0]
                    chunk1_size     = temp_mem_addr[x_idx][1] - chunk1_addr
                    chunk2_addr     = temp_mem_addr[x_idx+1][0]
                    chunk2_access   = mem_access[chunk2_addr][0]
                    chunk2_size     = temp_mem_addr[x_idx+1][1] - chunk2_addr

                    if chunk1_access != chunk2_access:
                        break

                    # consective, merge it
                    mem_access[chunk1_addr] = (chunk1_access, chunk1_size +
                            chunk2_size, None)
                    assert(chunk2_addr in mem_access)
                    mem_access.pop(chunk2_addr)

            # at this point, we can create the memory operands.
            wc = 0
            rc = 0
            for addr in mem_access:
                access, size, value = mem_access[addr]
                mem_reg = None
                if access == UC_MEM_WRITE:
                    wc += 1
                    mem_reg, addr_reg = self.arch.name2reg('MEM_WRITE{}'.format(wc))
                elif access == UC_MEM_READ:
                    rc += 1
                    mem_reg, addr_reg = self.arch.name2reg('MEM_READ{}'.format(rc))
                else:
                    raise Exception

                assert(mem_reg)
                assert(addr_reg)
                mem_reg.bits = size * 8
                mem_reg.structure.append(mem_reg.bits)
                mem_set.add(mem_reg)
                mem_set.add(addr_reg)

            mem_set_set.add(frozenset(mem_set))


        assert(len(mem_set_set) == 1)
        mem_registers = mem_set_set.pop()

        self.mu.hook_del(h)
        self._mem_rw_hook = self.mu.hook_add(UC_HOOK_MEM_WRITE |
                                             UC_HOOK_MEM_READ, self._mem_hook, self.rw_struct)
        print('Done identifying memops')

        return mem_registers, jump_reg

    def set_memregs(self, mem_regs):
        for mem_reg in mem_regs:
            if "ADDR" in mem_reg.name:
                self.mem_addrs[mem_reg] = 0
            else:
                self.mem_regs[mem_reg] = 0


    def asm2bin(self, asm_string):
        encoding, count = self.ks.asm(asm_string)
        return str(bytearray(encoding))

    def format_print(self, msg):
        print(("="*24+"%-10s"+"="*24) % (msg))

    def write_reg(self, reg, value):
        if reg in self.mem_regs:
            # store the memory stuff...
            self.mem_regs[reg] = value
        elif reg in self.cpu_regs:
            value_set = []
            for size in reg.structure:
                value_mask = (1<<size) - 1
                value_set.append(value & value_mask)
                value >>= size
            if len(value_set) == 1:
                self.mu.reg_write(reg.uc_const, value_set[0])
            else:
                self.mu.reg_write(reg.uc_const, value_set)
        elif reg in self.mem_addrs:
            self.mem_addrs[reg] = value
        else:
            pdb.set_trace()

    def write_regs(self, regs, values):
        if not hasattr(values, '__iter__'):
            temp = []
            for reg in regs:
                temp.append(values)
            values = temp
        if len(regs) != len(values):
            raise
        max_length = len(regs)
        for count in range(max_length):
            self.write_reg(regs[count], values[count])

    def read_reg(self, reg):
        value = None
        if reg in self.mem_regs:
            value = self.mem_regs[reg]
        elif reg in self.cpu_regs:
            value_set = self.mu.reg_read(reg.uc_const)
            value = 0
            if hasattr(value_set, '__iter__'):
                values_len = len(value_set)
                if values_len != len(reg.structure):
                    raise
                for x in range(values_len):
                    value |= value_set[x] << sum(reg.structure[:x])
            else:
                value = value_set
        elif reg in self.mem_addrs:
            value = self.mem_addrs[reg]
        else:
            pdb.set_trace()
        return value

    def print_regs(self, reg_list):
        for reg in reg_list:
            fstr = '{{: <8}}: {{:0{}b}}'.format(reg.bits)
            print(fstr.format(reg.name, self.read_reg(reg)))

    def get_cpu_state(self):
        result = {}

        for reg in self.cpu_regs:
            result[reg] = self.read_reg(reg)
        for reg in self.mem_regs:
            result[reg] = self.read_reg(reg)
        for reg in self.mem_addrs:
            result[reg] = self.mem_addrs[reg]

        return result

    def set_cpu_state(self, cpu_state):
        for reg in cpu_state:
            self.write_reg(reg, cpu_state[reg])

    def randomize_regs(self, reg_list=None):
        if reg_list == None:
            reg_list = self.cpu_regs + list(self.mem_regs)

        # randomly initialize all cpu regs
        for reg in reg_list:
            random_number = random.getrandbits(reg.bits)
            self.write_reg(reg, random_number)

    def clear_page(self):
        for page_address in self.pages:
            self.mu.mem_unmap(page_address, 4096)
        self.pages.clear()

    def init_state(self):
        if isinstance(self.arch, AMD64) or isinstance(self.arch, X86):
            self.write_reg(X86_REG_FPSW(), 0)

        # TODO: have to figure out how to remove this state... :(
        self.rw_struct[0] = [0,0]
        self.rw_struct[1] = [None, None, None]
        self.rw_struct[2] = False

    def execute(self, code, test_jump=False):
        self.init_state()
        self.clear_page()
        self.rep_cnt = 0
        self.write_reg(self.pc_reg, self.arch.code_addr)
        state_before = self.get_cpu_state()
        try:
            self.mu.mem_write(self.arch.code_addr, code)
            start_pc = self.read_reg(self.pc_reg)
            self.mu.emu_start(self.arch.code_addr, self.arch.code_addr + len(code))
        except UcError as e:
            if e.errno != UC_ERR_FETCH_UNMAPPED:
                raise e

        if self.rw_struct[2]:
            raise OutOfRangeException()
        state_after = self.get_cpu_state()
        return (state_before, state_after)

def main():
    cpu = UnicornCPU('X86')
    #cpu.identify_memops('\x8b\x45\x08')
    #cpu.identify_memops('\xa4')
    #cpu.identify_memops('\x48\xa7')

    #mem_registers = cpu.identify_memops('\x48\x8b\x03')
    #cpu.randomize_regs()
    #cpu.execute('\x48\x8b\x03')

    #mem_registers = cpu.identify_memops('\x48\x89\x18')
    #cpu.randomize_regs()
    #cpu.execute('\x48\x89\x18')

    #mem_registers = cpu.identify_memops('\x89\x18')
    #cpu.randomize_regs()
    #cpu.execute('\x89\x18')

    #mem_registers = cpu.identify_memops('\x8b\x03')
    #cpu.set_memregs(mem_registers)
    #cpu.randomize_regs()
    #cpu.write_reg(isa.x86_registers.X86_REG_EBX(), 2**64-1)
    #cpu.write_reg(isa.x86_registers.X86_MEM_READ1(), 2**64-1)
    #cpu.print_regs(list(cpu.get_cpu_state()))
    #a,b = cpu.execute('\x8b\x03')
    #cpu.print_regs(list(cpu.get_cpu_state()))

    #mem_registers, is_jump = cpu.identify_memops_jump('\xc3')
    #mem_registers, is_jump = cpu.identify_memops_jump('\x8b\x03')
    mem_registers, is_jump = cpu.identify_memops_jump('\xf3\xab')
    cpu.set_memregs(mem_registers)
    print(mem_registers)
    print(is_jump)

if __name__ == "__main__":
    main()
