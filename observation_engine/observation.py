
from observation_engine.strategy import *
from unicorn_cpu.unicorn_cpu_new import *

from taintinduce_common import *

from isa.x86 import *
from isa.amd64 import *
from isa.arm64 import *

import pdb

class ObservationEngine(object):
    def __init__(self, bytestring, archstring, state_format):
        # ZL: I really really hate to do this but the whole memory subsystem in UnicornCPU is just stupid
        # The whole thing is just spaghetti code with global states set everywhere.
        # Currently we'll have to instantiate the ObservationEngine with the bytestring, archstring and format.
        # Then UnicornCPU will perform the memory subsystem initialization using mem_access_num().
        # mem_access_num() is a MONSTER!!! Don't look at it, you'll cry and feel that life has no meaning.

        # A quick summary of what this nonsense thing does...

        # Some global states that are used
        # is_test is a global state that sets triggers a separate behavior for the memory hooks and execution.
        # mem_try_num is a global counter that sets the number of memory accesses that has been made, as a kind of threshold guard

        # mem_access_num():
        # 1. Sets is_test to True
        # 2. Executes a bunch of instructions.
        # 2a. In each execution, check mem_try_num == 0
        # 2b. If True, creates a memory register using create_emu_reg(), how does that work, I have no idea

        # mem_try_num, the global counter is modified in mem_clean_test()
        # mem_clean_test() has a bunch of tests, accordingly decreases the counter and adds the memory access to a list
        # At this point I gave up T.T, let's just use a global CPU.
        # TODO: Rewrite the memory subsystem in UnicornCPU and remove this global cpu state.
        self.bytestring = bytestring
        self.archstring = archstring
        self.state_format = state_format
        self.DEBUG_LOG = False

        arch = eval('{}()'.format(archstring))
        self.cpu = UnicornCPU(arch)
        bytecode = bytestring.decode('hex')
        self.cpu.mem_access_num(bytecode)

    def observe_insn(self): #(, bytestring, archstring, state_format):
        """Produces the observations for a particular instruction.

        The planned signature of the method is as follows. 
            bytestring (string): String representing the bytes of the instruction in hex without space
            archstring (string): Architecture String (X86, AMD64, ARM32, ARM64)
            state_format (list(Register)): A list of registers which defines the order of the State object

        But due to the extremely badly written UnicornCPU (the crazy memory stuff), 
        we'll have to create the ObservationEngine in such a way that it instantiate the CPU once for the entire observation routine,
        or the performance will be extremely bad.

        Args:
            None
        Returns:
            A list of Observations
        Raises:
            None
        """

        bytestring = self.bytestring
        archstring = self.archstring
        state_format = self.state_format

        observations = []
        seed_ios = self._gen_seeds(bytestring, archstring, state_format)
        for seed_io in seed_ios:
            observations.append(self._gen_observation(bytestring, archstring, state_format, seed_io))
        return observations

    def _gen_observation(self, bytestring, archstring, state_format, seed_io):
        """Generates the Observation object for the provided seed state by performing a one-bit bitflip.

        Args:
            bytestring (string): String representing the bytes of the instruction in hex without space
            archstring (string): Architecture String (X86, AMD64, ARM32, ARM64)
            state_format (list(Register)): A list of registers which defines the order of the State object
        Returns:
            A single Observation object for the provided seed.
        Raises:
            None
        """

        cpu = self.cpu
        bytecode = bytestring.decode('hex')
        seed_in, seed_out = seed_io
        sss = regs2bits(seed_in, state_format)
        rss = regs2bits(seed_out, state_format)
        state_list = list()

        # for reg in self.potential_use_regs:
        for reg in self.state_format:
            for x in range(reg.bits):
                try:
                    cpu.set_cpu_state(seed_in)
                    pos_val = (1<<x)
                    mutate_val = seed_in[reg] ^ pos_val
                    cpu.write_reg(reg, mutate_val)
                    # ZL: DEBUG stuff for the stupid CPU mem not writing bug
                    aa = cpu.read_reg(reg)
                    if type(reg) == X86_REG_FPSW:
                        aa = cpu.read_reg(reg)
                        if mutate_val != aa:
                            print('aaaaaa')
                            print(reg)
                            print(mutate_val)
                            print(aa)
                            print('ERROR')

                    sb, sa = cpu.execute(bytecode)
                    sbs = regs2bits(sb, state_format)
                    sas = regs2bits(sa, state_format)
                    if not sss.diff(sbs):
                        print(state_format)
                        print(pos_val)
                        print(reg)

                        print(aa)
                        print(seed_in[reg])
                        print(sb[reg])
                        qwe=(regs2bits2(seed_in, state_format))
                        asd=(regs2bits2(sb, state_format))
                        print(extract_reg2bits(qwe, reg, state_format))
                        print(extract_reg2bits(asd, reg, state_format))
                        print(qwe.diff(asd))
                        print(state_format[0])
                        print(seed_in[reg] ^ sb[reg])
                    assert(sss.diff(sbs))
                    #print('{} : {}'.format(sb[X86_REG_FPSW()]))
                    #if 'EFLAGS' in reg.name and cpu.read_reg(X86_REG_EFLAGS()) & 1 == 1:
                    #    print('EFLAG origin: {:032b}'.format(seed_in[reg]))
                    #    print('EFLAG mutate: {:032b}'.format(mutate_val))
                    #    print('FP0   origin: {:080b}'.format(sb[X86_REG_FP0()]))
                    #    print('FP0   mutate: {:080b}'.format(sa[X86_REG_FP0()]))
                    #    print('FP3   origin: {:080b}'.format(seed_in[X86_REG_FP3()]))
                    #    print('FP3   origin: {:080b}'.format(sb[X86_REG_FP3()]))
                    #    print('FP3   mutate: {:080b}'.format(sa[X86_REG_FP3()]))

                    #print(sbs)
                    #print(sas)
                    #if sbs.state_value == regs2bits(seed_in,state_format).state_value:
                    #    print('ERROR - reg {}'.format(reg))
                    #    print(seed_in[reg])
                    #    print(mutate_val)
                    #    raise
                    state_list.append((sbs, sas))
                except UcError as e:
                    continue
        return Observation((sss, rss), state_list, bytestring, archstring, state_format)

    def _gen_seeds(self, bytestring, archstring, state_format, strategies=None):
        """Generates a set of seed states based on the state_format using the strategies defined.

        Args:
            bytestring (string): String representing the bytes of the instruction in hex without space
            archstring (string): Architecture String (X86, AMD64, ARM32, ARM64)
            state_format (list(Register)): A list of registers which defines the order of the State object
        Returns:
            A list of seed state IO tuples
        Raises:
            None
        """
        if not strategies:
            strategies = [RandomNumber(100), Bitwalk(), ZeroWalk(), BitFill(), IEEE754Extended(10)]

        seed_states = []

        for strategy in strategies:
            for seed_variation in strategy.generator(state_format):
                seed_io = self._gen_random_seed_io(bytestring, archstring, seed_variation) 
                # check if its successful or not, if not debug print
                if seed_io:
                    seed_states.append(seed_io)
                else:
                    if self.DEBUG_LOG:
                        print("MAX_TRIES-{}-{}-{}-{}".format(bytestring, archstring, state_format, seed_variation))
                    continue

        return seed_states

    def _gen_seed_io(self, bytestring, archstring, seed_in, num_tries=255):
        """Generates a pair of in / out CPUState, seed_in, seed_out, by executing the instruction using a the provided CPUState

        Args:
            bytestring (string): String representing the bytes of the instruction in hex without space
            archstring (string): Architecture String (X86, AMD64, ARM32, ARM64)
            seed_in ( dict{Register:Integer } ): The input seed state
        Returns:
            Returns the seed input / output states as tuple(CPUState, CPUState) if successful.
            Otherwise returns None if it fails to find within num_tries
        Raises:
            Exception 
        """

        cpu = self.cpu
        bytecode = bytestring.decode('hex')

        for x in range(num_tries):
            try:
                cpu.set_cpu_state(seed_in)
                sb, sa = cpu.execute(bytecode)
                break
            except UcError as e:
                if x == num_tries-1:
                    return None
                continue
        return sb,sa

    def _gen_random_seed_io(self, bytestring, archstring, seed_variation, num_tries=255):
        """Generates a pair of in / out CPUState, seed_in, seed_out, by executing the instruction using a randomly generated CPUState with the seed_variation applied.

        Args:
            bytestring (string): String representing the bytes of the instruction in hex without space
            archstring (string): Architecture String (X86, AMD64, ARM32, ARM64)
            seed_variation ( tuple(tuple(Register), tuple(Integer) ): The seed variation, each Register and Integer corresponding to a modification. (cpu_state[Register] = Integer)
        Returns:
            Returns the seed input / output states as tuple(CPUState, CPUState) if successful.
            Otherwise returns None if it fails to find within num_tries
        Raises:
            Exception 
        """

        cpu = self.cpu
        bytecode = bytestring.decode('hex')
        regs2mod, vals2mod = seed_variation

        for x in range(num_tries):
            try:
                cpu.randomize_regs()
                cpu.write_regs(regs2mod, vals2mod)
                sb, sa = cpu.execute(bytecode)
                break
            except UcError as e:
                if x == num_tries-1:
                    return None
                continue
        return sb,sa
