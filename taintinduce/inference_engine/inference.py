from collections import defaultdict
from itertools import zip_longest

from .logic import Espresso
from .logic import EspressoException, NonOrthogonalException
from taintinduce.taintinduce_common import espresso2cond, extract_reg2bits, shift_espresso, Rule
from taintinduce.isa.x86_registers import X86_REG_EFLAGS

from squirrel.acorn.acorn import TaintRule

import pdb



class InferenceEngine(object):
    def __init__(self, espresso_path='./inference_engine/espresso'):
        self.espresso = Espresso(espresso_path)

    def infer(self, observations, cond_reg):
        """Infers the dataflow of the instruction using the obesrvations.

        Args:
            observations ([Observation]): List of observations to infer on.
            insn_info (InsnInfo): Optional argument to provide additional information about the insn.
        Returns:
            A list of Observations
        Raises:
            None
        """

        obs_deps = []
        unique_conditions = defaultdict(set)

        if len(observations) < 1:
            return Rule()

        # zl: we have the state_format in observation, assert that all observations in obs_list have the same state_format
        state_formats = [x.state_format for x in observations]
        state_format = state_formats[0]
        assert(not state_formats or state_formats.count(state_formats[0]) == len(state_formats))

        for observation in observations:
            # single_obs_dep contains the dependency for a single observation
            obs_dep = {}
            obs_mutate_in = {}
            seed_in, seed_out = observation.seed_io
            for mutate_in, mutate_out in observation.mutated_ios:
                bitflip_pos = seed_in.diff(mutate_in).pop()
                bitchanges_pos = seed_out.diff(mutate_out)
                obs_dep[bitflip_pos] = bitchanges_pos
                obs_mutate_in[bitflip_pos] = mutate_in
            obs_deps.append((obs_dep, obs_mutate_in, seed_in))

        # iterate through all the dependencies from the observations and identify what are the possible flows
        possible_flows = defaultdict(set)
        for obs_dep, _, _ in obs_deps:
            for use_bit_pos in obs_dep:
                possible_flows[use_bit_pos].add(frozenset(obs_dep[use_bit_pos]))

        condition_threshold = 10
        for use_bit_pos in possible_flows:
            bit_conditions = []
            bit_dataflows = []
            num_partitions = len(possible_flows[use_bit_pos])
            assert(num_partitions > 0)
            #print(num_partitions)

            # ZL: ugly hack to collect all the possibly failed cond identification
            no_cond_dataflow_set = set()
            # ZL: TODO: Hack for cond_reg, do a check if state_format contains the cond_reg, if no, then skip condition inference
            if num_partitions > 1 and num_partitions < condition_threshold and cond_reg in state_format:
                # generate the two sets...
                # iterate across all observations and extract the behavior for the partitions...
                partitions = defaultdict(set)

                # for each observation, get the dep behavior, and add the seed to it
                for obs_dep, obs_mutate_in, seed_in in obs_deps:
                    if use_bit_pos in obs_dep and use_bit_pos in obs_mutate_in:
                        partitions[frozenset(obs_dep[use_bit_pos])].add(obs_mutate_in[use_bit_pos])
                    #partitions[frozenset(obs_dep[use_bit_pos])].add(seed_in)

                # ZL: The current heuristic is to always select the smaller partition first since
                # it lowers the chances of the DNF exploding.
                sorted_behavior = sorted(partitions.keys(), key=lambda x: len(partitions[x]), reverse=True)

                for behavior in sorted_behavior[:-1]:
                    partition = set()
                    not_partition = set()
                    for behavior2 in partitions:
                        if behavior != behavior2:
                            current_partition = not_partition
                        else:
                            current_partition = partition

                        for state in partitions[behavior2]:
                            current_partition.add(state)

                    mycond = self._gen_condition(partition, not_partition, state_format, cond_reg)
                    if mycond:
                        bit_conditions.append(mycond)
                        bit_dataflows.append(behavior)
                    else:
                        no_cond_dataflow_set.add(behavior)
                remaining_behavior = sorted_behavior[-1]
                if no_cond_dataflow_set:
                    for behavior in no_cond_dataflow_set:
                        remaining_behavior |= behavior
                bit_dataflows.append(remaining_behavior)
            else:
                for behavior in possible_flows[use_bit_pos]:
                    no_cond_dataflow_set |= behavior
                no_cond_dataflow_set = frozenset(no_cond_dataflow_set)
                bit_dataflows.append(no_cond_dataflow_set)


            bit_conditions = tuple(bit_conditions)
            bit_dataflows = tuple(bit_dataflows)
            unique_conditions[bit_conditions].add((use_bit_pos, bit_dataflows))

        # at this point, we have all the conditions for all the bits
        # merge the condition and create the rule...
        # TODO: ZL: Have to take a look at how correct this is.
        # Don't think this is correct in general
        # The assumption here is that there will always be 2 sets, empty and the actual 
        # condition list.

        if tuple() not in unique_conditions:
            global_dataflows = []
        else:
            global_dataflows = unique_conditions.pop(tuple())
        dataflows = []
        condition_array = []
        dataflows.append(defaultdict(set))

        if len(unique_conditions) == 1:
            condition_array = list(unique_conditions.keys())[0]
            use_bit_dataflows = unique_conditions.pop(condition_array)

            cond_bits_list = []
            # ZL: this cond_bits_list is probably not needed
            # i think we just need a set of all the cond_bits...
            # but ah well, let's keep it that way
            # This list is used later to collect all the bits that are 
            # defined in the condition so that we can remove the indirect
            # flows
            for condition in condition_array:
                cond_bits = condition.get_cond_bits()
                cond_bits_list.append(cond_bits)

            # ZL: my brain can't work anymore, i'm just going to make it work and fix it later
            for _ in range(len(condition_array)):
                dataflows.append(defaultdict(set))

            # stuff_to_destroy contains the indirect flows we're going to remove
            stuff_to_destroy = defaultdict(set)
            for use_bit, use_bit_dataflow in use_bit_dataflows:
                assert(len(cond_bits_list) == len(use_bit_dataflow)-1)
                for dataflow_id, dep_set in enumerate(use_bit_dataflow):
                    if dataflow_id < len(cond_bits_list):
                        cond_bits = cond_bits_list[dataflow_id]
                        for cond_bit in cond_bits:
                            stuff_to_destroy[cond_bit] |= dep_set
                    dataflows[dataflow_id][use_bit] |= dep_set

            # remove the global flows...
            old = global_dataflows
            global_dataflows = set()
            for use_bit, def_bits in old:
                if use_bit in stuff_to_destroy:
                    qq = def_bits[0] - stuff_to_destroy[use_bit]
                else:
                    qq = def_bits[0]
                global_dataflows.add((use_bit, (frozenset(qq),)))

        else:
            print("not 1 unique condition... merge")
            merged_dataflows = defaultdict(set)
            for condition_array in list(unique_conditions):
                use_bit_dataflows = unique_conditions.pop(condition_array)
                for use_bit, use_bit_dataflow in use_bit_dataflows:
                    for dep_set in use_bit_dataflow:
                        merged_dataflows[use_bit] |= dep_set
            for use_bit in merged_dataflows:
                dataflows[-1][use_bit] |= merged_dataflows[use_bit]
            condition_array = []
        assert(len(unique_conditions) == 0)

        # add in the always true flows
        for dataflow in dataflows:
            for use_bit, dep_set in global_dataflows:
                dataflow[use_bit] |= dep_set[0]

        rule = Rule(state_format, condition_array, dataflows)

        #for conditions in unique_conditions:
        #    dataflow = defaultdict(set)
        #    for use_bit, dataflows in unique_conditions[conditions]:
        #        print(use_bit)
        #        print tuple(izip_longest(conditions, dataflows, fillvalue=None))


        return rule

    def _gen_condition(self, partition1, partition2, state_format, cond_reg=None):
        """
        Args:
            partition1 (set{State}): Set of input States which belongs in the True partition.
            partition2 (set{State}): Set of input States which belongs to the False partition.
        Returns:
            Condition object if there exists a condition.
            None if no condition can be inferred.
        Raises:
            None
        """
        partition_true = set()
        partition_false = set()
        #pdb.set_trace()
        state_bits = 0
        if cond_reg:
            for state in partition1:
                cond_reg_value = extract_reg2bits(state, cond_reg, state_format).state_value
                partition_true.add(cond_reg_value)
            for state in partition2:
                cond_reg_value = extract_reg2bits(state, cond_reg, state_format).state_value
                partition_false.add(cond_reg_value)
            state_bits = cond_reg.bits
        else:
            for state in partition1:
                partition_true.add(state.state_value)
            for state in partition2:
                partition_false.add(state.state_value)
            state_bits = sum([reg.bits for reg in state_format])

        #print('True')
        #for val in partition_true:
        #    print('{:064b}'.format(val))
        #print('False')
        #for val in partition_false:
        #    print('{:064b}'.format(val))

        partitions = {1:partition_true, 0:partition_false}
        try:
            dnf_condition = self.espresso.minimize(state_bits, 1, 'fr', partitions)
        except NonOrthogonalException as e:
            return None
        except EspressoException as e:
            # ZL: have to make it a specific exception
            if 'ON-set and OFF-set are not orthogonal' in str(e):
                return None
            pdb.set_trace()

        # dnf_conditions (set{(int, int)}): A set of tuples (mask, value) representing a DNF formula. Each tuple is a boolean formula in CNF (input & mask == value).
        dnf_condition = shift_espresso(dnf_condition, cond_reg, state_format)
        condition = espresso2cond(dnf_condition)
        return condition

