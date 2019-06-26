'''
ZL: This is a piece of crap, gotta rewrite it...

 ==------------Unicorn CPU-----------==
 This file contains the instruction execution stuff. 

 by mcgrady and melynx.
'''
from cpu import *
from isa.x86_registers import *
from isa.arm64_registers import *
from isa.x86 import *
from isa.amd64 import *
from isa.arm64 import *
# remember to replace this module
from observation_engine.strategy import *
from enum import Enum

from unicorn import *
from unicorn.x86_const import *
from capstone import *
from keystone import *

import random
import struct
import time
import sys

import pdb

# gpr = general register
# cpr = complex register => xmm, mm...
# mem = memory emulate register
reg_type = Enum('reg_type',('gpr', 'cpr', 'mem'))
mem_type = Enum('mem_type',('r','w'))

class UnicornCPU(CPU):
    def __init__(self, arch, debug=False):
        self.debug = debug
        self.arch = arch
        self.ks = Ks(self.arch.ks_arch[0], self.arch.ks_arch[1])
        self.mu = Uc(self.arch.uc_arch[0], self.arch.uc_arch[1])
        self.md = Cs(self.arch.cs_arch[0], self.arch.cs_arch[1])
        random_number = random.randint(10, 100)
        # pdb.set_trace() 
        # arch.initial_vars() 
        self.pc_reg       = self.arch.pc_reg.uc_const
        self.state_reg    = self.arch.state_reg[0].uc_const
        self.cpu_regs     = self.arch.cpu_regs
        self.mem_emu_regs = list()

        self.mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self.hook_mem_access)
        self.mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, self.hook_invalid_mem)
        # use to check reptition instruction
        self.mu.hook_add(UC_HOOK_CODE, self.check_rep_instruction, None, self.arch.code_addr, self.arch.code_addr + 20)

        self.mu.mem_map(self.arch.code_addr, self.arch.code_mem)

        self.mem_read_emu_reg  = self.arch.cpu_read_emu_regs
        self.mem_write_emu_reg = self.arch.cpu_write_emu_regs

        '''
            @To handle the memory access recognition, we have to add some vars
        '''

        ''' some operation executes in test mode, eg,.mem access analysis '''
        self.is_test = False
        self.has_mem_access = False
        ''' Found no memory access exception '''
        self.mem_access_normal = False
        self.mem_address_invalid = False
        ''' memory access times doesnt exceed threshold '''
        self.mem_access_exceed = False
        self.mem_try_num = 10
        ''' number of current execution '''
        self.mem_read_counter  = 0
        self.mem_read_op_num   = 0
        self.mem_write_ope_num = 0
        self.mem_write_counter = 0
        ''' limit of mem access times '''
        self.mem_read_max  = 128
        self.mem_write_max = 128
        # To address unicorn mem access bug
        ''' in FSTP xword ptr [eax], for some mem address, unicorn will access only 8 bytes ''' 
        self.write_mem_size_check = False
        ''' mem address list in one time '''
        self.mem_reads  = []
        self.mem_writes = []
        self.mem_read_lists  = []
        self.mem_write_lists = []
        self.map_page = []

        ''' repeate instruction handler '''
        self.is_rep = False
        self.rep_time = 0

    
    def asm2bin(self, asm_string):
        encoding, count = self.ks.asm(asm_string)
        return str(bytearray(encoding))

    def format_print(self, msg):
        print(("="*24+"%-10s"+"="*24) % (msg))

    ''' 
        @ register handler functions
        @ This group contains all functions about how to access registers 
    '''

    def get_reg_type(self, reg):
        ''' Get type of the target register '''        
        if len(reg.structure) > 1:
            return reg_type.cpr
        elif reg in self.mem_emu_regs:
            return reg_type.mem
        else:
            return reg_type.gpr

    def write_reg(self, reg, value):
        _reg_type = self.get_reg_type(reg)

        if _reg_type == reg_type.mem:
            # ZL: GG!!! Temp fix to this piece of sh**
            # We'll look for the register in the mem_emu_reg and write the value there
            for gg_mem_reg in self.mem_emu_regs:
                if gg_mem_reg == reg:
                    gg_mem_reg.value = value
        elif _reg_type == reg_type.cpr:
            value_set = []
            for size in reg.structure:
                value_mask = (1 << size) - 1
                value_set.append(value & value_mask)
                value >>= size
            self.mu.reg_write(reg.uc_const, value_set)

        else:
            self.mu.reg_write(reg.uc_const, value)

    def write_value_in_emu_reg(self, reg, value):
        ''' clean the address and assign a new value '''
        if reg in self.mem_emu_regs:
            reg.value   = value
            reg.address = 0
        else:
            raise Exception("mem assignment error")

    def read_reg(self, reg):
        value_set = self.mu.reg_read(reg.uc_const)
        value = value_set
        if hasattr(value_set, '__iter__'):
            values_len = len(value_set)
            if values_len != len(reg.structure):
                raise
            if values_len > 1:
                value = value_set[0]
                for x in range(1, values_len):
                    value |= value_set[x] << sum(reg.structure[:x])
        return value

    def write_regs(self, reg_list, values):
        if not hasattr(values, '__iter__'):
            temp = []
            for reg in reg_list:
                temp.append(values)
            values = temp
        if len(reg_list) != len(values):
            raise
        max_length = len(reg_list)
        for count in range(max_length):
            self.write_reg(reg_list[count], values[count])

    def read_regs(self, reg_list):
        result = []
        for reg in reg_list:
            result.append(self.read_reg(reg))
        return result

    def print_regs(self, reg_list):
        for reg in reg_list:
            print('{: <8}: {:064b}'.format(reg.name, self.mu.reg_read(reg.uc_const)))

    ''' 
        @ system state handler 
        @ This group contains all functions about how to access system state 
    '''

    def get_cpu_state(self):
        result = {}
        if len(self.mem_emu_regs) == 0:
            for reg in self.cpu_regs:
                result[reg] = self.read_reg(reg)
        else:
            for reg in self.cpu_regs:
                if reg not in self.mem_emu_regs:
                    result[reg] = self.read_reg(reg)
                else:
                    result[reg] = reg.value

        return result

    def set_cpu_state(self, cpu_state):
        if len(self.mem_emu_regs) == 0:
            for reg in cpu_state:
                self.write_reg(reg, cpu_state[reg])
        else:
            for reg in cpu_state:
                if reg not in self.mem_emu_regs:
                    self.write_reg(reg, cpu_state[reg])
                else:
                    self.write_value_in_emu_reg(reg, cpu_state[reg])

    def randomize_regs(self, reg_list=None):
        if reg_list == None:
            reg_list = self.cpu_regs
        # randomly initialize all cpu regs
        for reg in reg_list:
            random_number = random.getrandbits(reg.bits)
            self.write_reg(reg, random_number)

        if len(self.mem_emu_regs) == 0:
            for reg in reg_list:
                random_number = random.getrandbits(reg.bits)
                self.write_reg(reg, random_number)

        else:
            for reg in reg_list:
                if reg not in self.mem_emu_regs:
                    random_number = random.getrandbits(reg.bits)
                    self.write_reg(reg, random_number)
                else:
                    random_number = random.getrandbits(reg.bits)
                    self.write_value_in_emu_reg(reg, random_number)

    ''' 
        @ instruction execution handler 
        @ This group contains all functions about how to run a instruction
    '''

    def debug_state(self, msg):
        if self.debug:
            self.format_print(msg)
            self.print_regs(self.cpu_regs)

    def identify_call(self, code, start_pc):
        ''' 
            @ Special case
            @ call eip => [esp] <- eip 
        '''
        for reg in self.mem_emu_regs:
            if reg.value == len(code) + self.arch.code_addr:
                reg.value = start_pc

    def state_initial(self):
        ''' initial system state for cpu '''
        # pdb.set_trace()
        if isinstance(self.arch, X86) or isinstance(self.arch, AMD64):
            self.write_reg(X86_REG_FPSW(), 0x0)
            #self.mu.reg_write(self.state_reg, 0x0000)

    def execute(self, code):
        ''' core engine of the cpu '''
        self.state_initial()
        self.debug_state("[p] Before execution")
        state_before = self.get_cpu_state()

        try:
            self.mu.mem_write(self.arch.code_addr, code)
            start_pc = self.mu.reg_read(self.pc_reg)
            
            self.mu.emu_start(self.arch.code_addr, self.arch.code_addr + len(code))

            self.mem_access_normal = True
            self.mu.reg_write(self.pc_reg, start_pc)
            
        except Exception as e:
            if (self.mu.reg_read(self.pc_reg) - len(code)) == self.arch.code_addr:
                self.mem_access_normal = False
            else:
                self.mem_access_normal = True
        
        self.identify_call(code, start_pc)
        state_after = self.get_cpu_state()
        self.debug_state("[p] After Execution")
           
        res = None
        if not(self.mem_access_normal) or self.mem_access_exceed or self.mem_address_invalid:
            pass
        elif not(self.is_test) and not(self.write_mem_size_check) and (X86_MEM_WRITE1() in self.mem_emu_regs) and (X86_MEM_WRITE1().bits == 80):
            pass
        else:
            res = (state_before, state_after)

        if not(self.is_test) and self.mem_read_counter < self.mem_read_op_num:
            res = None

        # clear memory access affect and all state
        if self.is_test:
            self.mem_clean_test()
        else:
            self.mem_clean()
        self.clear_rep_counter()

        if res == None:
            raise UcError(0)

        return res

    ''' memory access handler '''
    def hook_mem_access(self, uc, access, address, size, value, user_data):
        ''' check mem access '''
        self.has_mem_access = True
        if self.is_test:
            result = self.mem_access_test(access, address, size, value)
        else:
            result = self.mem_access_analysis(access, address, size, value)
        if not(result):
            self.mem_access_normal = False
        return result

    def hook_invalid_mem(self, uc, access, address, size, value, user_data):
        ''' check invalid mem access '''
        self.has_mem_access = True
        page_address = address & ~0b111111111111
        uc.mem_map(page_address, 4096)
        self.map_page.append(page_address)

        if self.is_test:
            result = self.mem_access_test(access, address, size, value)
        else:
            result = self.mem_access_analysis(access, address, size, value)

        if not(result):
            self.mem_access_normal = False
        return result

    def check_mem_address(self, address, size):
        if (address + size) > (address | 0b111111111111) or address == 0 or address == 0x1000:
            self.mem_address_invalid = True
            return False

        return True

    def write_mem_value(self, address, size, value):
        if size == 1:
            pattern = (1, '<B')
        elif size == 2:
            pattern = (1, '<H')
        elif size == 4:
            pattern = (1, '<I')
        elif size == 8:
            pattern = (1, '<Q')
        elif size == 10:
            pattern = (2, '<Q', '<H')
        elif size == 16:
            pattern = (2, '<Q', '<Q')
        else:
            self.format_print("Memory write size not supported!")
            return False

        if pattern[0] == 1:
            random_bytes = struct.pack(pattern[1], value)
        else:
            low  = value & 0b1111111111111111111111111111111111111111111111111111111111111111
            high = value >> 64
            random_bytes_low  = struct.pack(pattern[1], low)
            random_bytes_high = struct.pack(pattern[2], high)
            random_bytes  = random_bytes_low + random_bytes_high

        try:
            self.mu.mem_write(address, random_bytes)
            return True
        except Exception as e:
            return False

    def write_mem_random_value(self, address, size):
        random_number = random.getrandbits(size*8)
        success = self.write_mem_value(address, size, random_number)        
        if success:
            self.mem_reads.append((address, size))     
        return success

    def write_mem_reg_value(self, address, size):
        ''' write value in to simulative mem register '''
        for reg in self.mem_emu_regs:
            if (reg.address == 0) and (reg.bits/8 == size) and ('READ' in reg.name):
                reg.address = address
                res = self.write_mem_value(address, size, reg.value)
                if res:
                    self.mem_reads.append((address, size))     
                return res
            elif (reg.address == 0) and (reg.bits/8 == 10) and (size == 8) and ('READ' in reg.name):
                reg.address = address
                res = self.write_mem_value(address, 10, reg.value)
                if res:
                    self.mem_reads.append((address, 10))     
                return res
            elif (reg.address == 0) and (reg.bits/8 == 16) and (size == 8) and ('READ' in reg.name):
                reg.address = address
                res = self.write_mem_value(address, 16, reg.value)
                if res:
                    self.mem_reads.append((address, 16))     
                return res
            elif (reg.address != 0) and (reg.bits/8 == 10) and (size == 2) and ('READ' in reg.name):
                return True
            elif (reg.address != 0) and (reg.bits/8 == 16) and (size == 8) and ('READ' in reg.name):
                return True
            elif reg.address == address:
                return True
            else:
                continue
        return False

    def set_mem_write_emu_reg(self, address, size, value):
        '''
        Handle the unalign problem.
        Our bit walk generationg strategy will generate reg value like xxxx000, if the reg is edi,
        the locations will cross two page, one location will be written two times 
        '''
        #print(hex(value&0xffffffffffffffff))
        for reg in self.mem_emu_regs:
            if 'WRITE' in reg.name:
                if (reg.address == 0) and (reg.bits/8 == size):
                    if (reg.bits/8 == 8):
                        reg.value = value&0xffffffffffffffff
                    else:
                        reg.value = value
                    reg.address = address
                    return True
                elif (reg.address == 0) and (reg.bits/8 == 10) and (size == 8):
                    reg.address = address
                    reg.value = value&0xffffffffffffffff
                    return True
                elif (reg.address == 0) and (reg.bits/8 == 16) and (size == 8):
                    reg.address = address
                    reg.value = value&0xffffffffffffffff   
                    return True
                elif (reg.address <= address) and (address + size*8 <= reg.address + reg.bits*8):
                    if (reg.address != 0) and (reg.bits/8 == 10) and (size == 2):
                        self.write_mem_size_check = True
                        reg.value |= (value&0xffffffffffffffff) << 64
                        return True
                    elif (reg.address != 0) and (reg.bits/8 == 16) and (size == 8):
                        reg.value |= (value&0xffffffffffffffff) << 64
                        return True
                    else:
                        return True
                else:
                    continue
        return False 

    def mem_access_test(self, access, address, size, value, test = True):
        ''' record the locations that instruction accesses '''
        if access == UC_MEM_READ_UNMAPPED or access == UC_MEM_READ:
            self.mem_read_counter += 1
            if self.mem_read_counter >= self.mem_read_max:
                self.mem_access_exceed = True
                self.mu.emu_stop()
            else:
                return self.write_mem_random_value(address, size)

        elif access == UC_MEM_WRITE:
            self.mem_write_counter += 1
            if self.mem_write_counter > self.mem_write_max:
                self.mem_access_exceed = True
                self.mu.emu_stop()
            else:
                self.mem_writes.append((address, size))
                return True

        elif access == UC_MEM_WRITE_UNMAPPED:
            pass

        else:
            ''' error occurs '''
            self.format_print("unknown access number")
            return False

        return True

    def mem_access_analysis(self, access, address, size, value, test = True):
        ''' check the number of memory access if less than the threshold? '''
        if access == UC_MEM_READ_UNMAPPED:
            self.mem_read_counter += 1
            if self.mem_read_counter >= self.mem_read_max:
                self.mem_access_exceed = True
                self.mu.emu_stop()
            else:
                if not(self.check_mem_address(address, size)):
                    return False
                return self.write_mem_reg_value(address, size)

        elif access == UC_MEM_READ:
            self.mem_read_counter += 1
            if self.mem_read_counter >= self.mem_read_max:
                self.mem_access_exceed = True
                self.mu.emu_stop()
            else:
                if address not in self.mem_reads:
                    self.check_mem_address(address, size)
                    return self.write_mem_reg_value(address, size)
                else:
                    if not(self.check_mem_address(address, size)):
                        return False
                    return self.write_mem_reg_value(address, size)

        elif access == UC_MEM_WRITE:
            self.mem_write_counter += 1
            if self.mem_write_counter > self.mem_write_max:
                self.mem_access_exceed = True
                self.mu.emu_stop()
                raise
            else:
                self.mem_writes.append((address, size))
                self.check_mem_address(address, size)
                return self.set_mem_write_emu_reg(address, size, value)

        elif access == UC_MEM_WRITE_UNMAPPED:          
            pass 

        else:
            ''' some errors occur '''
            self.format_print("unknown access number")
            return False

        return True

    def mem_access_num_asm(self, asm):
        code = self.asm2bin(asm)
        return self.mem_access_num(code)

    def mem_access_num(self, code):
        ''' detect the number of a instruction '''
        self.is_test = True
        strategies = [RandomNumber(100), Bitwalk(), ZeroWalk(), BitFill(), IEEE754Extended(10)]
        for strategy in strategies:
            for input_candidates, values in strategy.generator(self.cpu_regs):
                initial_state = self.get_cpu_state()
                try:
                    initial_state, __ = self.find_feasible_state(code, num_tries=256)
                except UcError:
                    continue
                self.set_cpu_state(initial_state)
                try:
                    self.write_regs(input_candidates, values)
                    state_before, state_after = self.execute(code)
                    if self.mem_try_num == 0:
                        self.create_mem_emu_register()
                        self.is_test = False
                        return
                except UcError as e:
                    continue

    def find_feasible_state(self, code, num_tries=256):
        result = None
        for x in range(num_tries):
            try:
                self.randomize_regs()
                result = self.execute(code)
                break
            except UcError as e:
                if x == num_tries-1:
                    raise Exception('Max tries reached to find random state')
                continue
        return result

    def create_mem_emu_register(self):
        # print(len(self.cpu_regs))
        read_mem_emu_reg  = self.mem_read_emu_reg
        write_mem_emu_reg = self.mem_write_emu_reg
        for key in self.mem_read_op:
            for i in range(0,self.mem_read_op[key]):
                reg = read_mem_emu_reg.pop()
                reg.bits = key * 8
                reg.structure = [key * 8]
                self.cpu_regs.append(reg)
                self.mem_emu_regs.append(reg)

        for key in self.mem_write_op:
            for i in range(0,self.mem_write_op[key]):
                reg = write_mem_emu_reg.pop()
                reg.bits = key * 8
                reg.structure = [key * 8]
                self.cpu_regs.append(reg)
                self.mem_emu_regs.append(reg)

    def clear_mem_state(self):
        ''' clear the memory for once execution '''
        self.mem_reads  = []
        self.mem_writes = []
        self.mem_read_counter  = 0
        self.mem_write_counter = 0
        for page in self.map_page:
            self.mu.mem_unmap(page, 4096)
        self.map_page = []
        self.mem_access_exceed = False

    def clear_mem_state_for_test(self):
        ''' clear the memory for all try runs '''
        self.clear_mem_state()
        self.mem_read_lists  = []
        self.mem_write_lists = []

    def mem_value_clean(self):
        # clean the memory data
        for mem in self.mem_reads:
            self.mu.mem_write(mem[0], '\x00' * mem[1])
        for mem in self.mem_writes:
            self.mu.mem_write(mem[0], '\x00' * mem[1])

    def mem_op_filter(self, mem_lists):
        wrong = False
        op_num_list = []
        new_mem_lists = []

        for mem_list in mem_lists:
            new_mem_lists.append(sorted(list(set(mem_list)), key=lambda x:(x[1], x[0])))
            op_num_list.append(len(new_mem_lists[-1]))

        if len(set(op_num_list)) == 0:
            op_number = 0
        elif len(set(op_num_list)) == 0:
            op_number = op_num_list[0]
        else:
            op_number = max(op_num_list)
            wrong = True

        return (new_mem_lists, op_number, wrong)

    def mem_op_filter_for_one(self):
        #print(self.mem_writes)
        if len(self.mem_reads) != 0:
            mem_list = self.mem_reads
            new_mem_list = sorted(list(set(mem_list)), key=lambda x:(x[1], x[0]))
            if len(new_mem_list) > self.mem_read_op_num:
                #if len(self.fix_FPU_XMM_mem_error(self.unicorn_error_fix_for_one(new_mem_list))) > self.mem_read_op_num:
                    # save cpu state
                    # set self.is_test = True and self.restart_flag = True
                    # rase excecption and break from test loop
                if len(self.unicorn_error_fix_for_one(new_mem_list)) > self.mem_read_op_num:
                    return False
            
            #self.write_value_in_emu_reg(True)

        if len(self.mem_writes) != 0:
            mem_list = self.mem_writes
            new_mem_list = sorted(list(set(mem_list)), key=lambda x:(x[1], x[0]))
            if len(new_mem_list) > self.mem_write_op_num:
                if len(self.unicorn_error_fix_for_one(new_mem_list)) > self.mem_write_op_num:
                    return False
            
            #self.write_value_in_emu_reg(False)

    def mem_op_num(self, read=None):

        if read == mem_type.r:
            mem_lists = self.mem_read_lists
        else:
            mem_lists = self.mem_write_lists

        # Get number of mem operand
        new_mem_lists, op_number, wrong = self.mem_op_filter(mem_lists)
        
        #pdb.set_trace()
        #wrong means the mem_list can be optmized
        if wrong == True:
            new_mem_lists = self.unicorn_error_fix(new_mem_lists, op_number)
            #print(new_mem_lists)
            if read == False:
                op_number = 2
            new_mem_lists = self.fix_FPU_XMM_mem_error(new_mem_lists, op_number)
            #print(new_mem_lists)
            new_mem_lists, op_number, wrong = self.mem_op_filter(new_mem_lists)
        else:
            #pdb.set_trace()
            pass
            
        #Delete empty list in new_mem_lists, 16 bytes or 10 bytes mem op will meet this problem
        old_mem_lists = new_mem_lists
        new_mem_lists = []
        for mem_list_item in old_mem_lists:
            if mem_list_item == [] and op_number > 0:
                pass
            else:
                new_mem_lists.append(mem_list_item)
        error = self.unicorn_error_check(op_number, read)

        if error == False:
            return False

        # Get the size of mem operand
        # To address xmm and fpu problem
        op_size = {}
        if op_number == 1:
            op_size[sorted(new_mem_lists,key=lambda t: (t[0][1], t[0][0]))[-1][0][1]] = 1
        else:
            for mem_list in new_mem_lists:
                tmp_op_size = {}
                for mem in mem_list:
                    if tmp_op_size.has_key(mem[1]):
                        tmp_op_size[mem[1]] += 1
                    else:
                        tmp_op_size[mem[1]] = 1

                for key in tmp_op_size:
                    if op_size.has_key(key):
                        if op_size[key] < tmp_op_size[key]:
                            op_size[key] = tmp_op_size[key]
                        else:
                            continue
                    else:
                        op_size[key] = tmp_op_size[key]    

        if read == mem_type.r:
            self.mem_read_op_num = op_number
            self.mem_read_op = op_size
        else:
            self.mem_write_op_num = op_number
            self.mem_write_op = op_size
        
        #print(op_number)
        #print(op_size)

    def show_mem_op(self):
        print ("mem_read_num: %d" % self.mem_read_op_num)
        if self.mem_read_op:
            print self.mem_read_op
        print ("mem_write_num: %d" % self.mem_write_op_num)
        if self.mem_write_op:
            print self.mem_write_op

    def mem_clean_test(self):
        self.mem_value_clean()
        ''' to address float point load error '''
        self.write_mem_size_check = False
        ''' check the mem state '''
        if self.mem_access_normal and not(self.mem_access_exceed):
            if self.mem_try_num > 0:
                self.mem_try_num -= 1
                self.mem_read_lists.append(self.mem_reads)
                self.mem_write_lists.append(self.mem_writes)
                self.clear_mem_state()
             
            if self.mem_try_num == 0:
                self.mem_op_num(mem_type.r)
                self.mem_op_num(mem_type.w)
                self.clear_mem_state_for_test()
        else:
            self.clear_mem_state()
            
        self.mem_address_invalid = False

    def mem_clean(self):
        self.mem_value_clean()
        ''' to address float point load error '''
        self.write_mem_size_check = False
        ''' check the mem state '''
        if self.mem_access_normal and not(self.mem_access_exceed):
            # check op_number is right or not
            # write mem value in emu register
            self.mem_op_filter_for_one()
            self.clear_mem_state()
        else:
            self.clear_mem_state()
            
        self.mem_address_invalid = False

    ''' rep instruction handler '''
    def check_rep_instruction(self, uc, address, size, user_data):
        eip = uc.reg_read(self.pc_reg)
        if eip == self.arch.code_addr:
            self.rep_time += 1
        if self.rep_time >1:
            if self.is_rep == False:
                self.is_rep = True
            self.mu.emu_stop()

    def clear_rep_counter(self):
        self.rep_time = 0

    '''
        @ unicorn error handler
    '''
    def unicorn_error_check(self, op_number, read=True):
        # check for intel, not sure for arm and other archi
        if read == True:
            if op_number >= 3:
                print("read memory number error")
                return False
            else:
                return True
        else:
            if op_number >= 2:
                print("write memory number error")
                return False
            else:
                return True

    def fix_FPU_XMM_mem_error_for_one(self, mem_list):
        '''
        delete redundant mem read or write operand
        '''
        new_mem_list = []
        delete_list = []
        delete_size = 0
        mem_list = sorted(mem_list, key=lambda t: (t[0], t[1]))
        op_number = len(mem_list)
        #pdb.set_trace()
        for i in range(0, op_number):
            if i in delete_list:
                continue
            delete = False
            for j in range(i+1, op_number):
                if mem_list[j][0] == mem_list[i][0] + mem_list[i][1]:
                    delete = True
                    delete_list.append(j)
                    break
                else:
                    continue
            if delete == True:
                new_mem_list.append((mem_list[i][0],mem_list[i][1] + mem_list[delete_list[-1]][1]))
            else:
                new_mem_list.append(mem_list[i])
        #pdb.set_trace()
        return new_mem_list

    def fix_FPU_XMM_mem_error(self, mem_lists, op_number):
        new_mem_lists = []

        for mem_list in mem_lists:
           
            if len(mem_list) == op_number:
                new_mem_lists.append(self.fix_FPU_XMM_mem_error_for_one(mem_list))
            elif len(mem_list) < op_number:
                new_mem_lists.append(mem_list)

        return new_mem_lists

    def unicorn_error_fix_for_one(self, mem_list):
        '''
        delete redundant mem write tuple in the mem_list,
        it could be a bug of unicorn, not sure.
        '''
        new_mem_list = []
        op_number = len(mem_list)
        for i in range(0, op_number):
            delete = False
            for j in range(i+1, op_number):
                if mem_list[i][0] >= mem_list[j][0] and (mem_list[i][0] + mem_list[i][1]) <= (mem_list[j][0] + mem_list[j][1]):
                    delete = True
                    break
                else:
                    continue
            if delete == True:
                continue
            else:
                new_mem_list.append(mem_list[i])
        return new_mem_list

    def unicorn_error_fix(self, mem_lists, op_number):
        new_mem_lists = []
        
        for mem_list in mem_lists:
            new_mem_list = []
            if len(mem_list) == op_number:
                new_mem_lists.append(self.unicorn_error_fix_for_one(mem_list))
            else:
                new_mem_lists.append(mem_list)

        return new_mem_lists

if __name__ == "__main__":
    ucpu = UnicornCPU(X86)
    ucpu.test()
