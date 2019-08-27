
from .strategy import *
from taintinduce.unicorn_cpu.unicorn_cpu import *

from taintinduce.taintinduce_common import *

from taintinduce.isa.x86 import *
from taintinduce.isa.amd64 import *
from taintinduce.isa.arm64 import *

import pdb
from tqdm import tqdm

class ObservationEngine(object):
    def __init__(self, bytestring, archstring, state_format):
        self.arch = globals()[archstring]()
        self.cpu = UnicornCPU(archstring)
        bytecode = bytes.fromhex(bytestring)

        mem_regs = [x for x in state_format if 'MEM' in x.name]
        self.cpu.set_memregs(mem_regs)

        state_string = ' '.join(['({},{})'.format(x.name, x.bits) for x in state_format])
        print('')
        print('state_format: {}'.format(state_string))
        print('')

        self.bytestring = bytestring
        self.archstring = archstring
        self.state_format = state_format
        self.DEBUG_LOG = False


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
        for seed_io in tqdm(seed_ios):
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
        bytecode = bytes.fromhex(bytestring)
        seed_in, seed_out = seed_io
        sss = regs2bits(seed_in, state_format)
        rss = regs2bits(seed_out, state_format)
        state_list = list()

        # for reg in self.potential_use_regs:
        for reg in self.state_format:
            if 'WRITE' in reg.name or 'ADDR' in reg.name:
                continue
            #for x in tqdm(range(reg.bits)):
            for x in (range(reg.bits)):
                cpu.set_cpu_state(seed_in)
                pos_val = (1<<x)
                mutate_val = seed_in[reg] ^ pos_val
                cpu.write_reg(reg, mutate_val)
                try:
                    sb, sa = cpu.execute(bytecode)
                except UcError as e:
                    continue
                except OutOfRangeException as e:
                    continue
                sbs = regs2bits(sb, state_format)
                sas = regs2bits(sa, state_format)
                if not sss.diff(sbs):
                    continue
                assert(sss.diff(sbs))
                state_list.append((sbs, sas))
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

        # TODO: HACK to speed up, we'll ignore write and addr
        temp_state_format = [x for x in state_format if ('WRITE' not in x.name
            and 'ADDR' not in x.name)]
        for strategy in strategies:
            for seed_variation in tqdm(strategy.generator(temp_state_format)):
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
            except OutOfRangeException as e:
                if x == num_tries-1:
                    return None
                continue
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
        bytecode = bytes.fromhex(bytestring)
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
            except OutOfRangeException as e:
                if x == num_tries-1:
                    return None
                continue
        return sb,sa
