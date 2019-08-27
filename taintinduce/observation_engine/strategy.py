import math
import random
import itertools


'''
All Strategy classes must implement generator(regs) that returns a list of seed_variations.

Each seed variation is a tuple of the form tuple(tuple(Register,...), tuple(value,...) ).

These are the values to modify on an initial seed state, hence varying the seed value.
'''

class Strategy(object):
    def __init__(self, num_runs=1):
        self.num_runs = num_runs

    # generator produces a list of values and the corresponding register it should modify
    def generator(self, regs):
        raise('Not implemented!')

class SpecialIMM(Strategy):
    # generate special value that same with the imm
    def generator(self, regs):
        imm_value = self.num_runs
        inputs = []
        for reg in regs:
            t_random_number = tuple([imm_value])
            t_reg = tuple([reg])
            inputs.append((t_reg, t_random_number))
        return inputs

class RandomNumber(Strategy):
    def generator(self, regs):
        inputs = []
        for reg in regs:
            for _ in range(self.num_runs):
                t_random_number = tuple([random.getrandbits(reg.bits)])
                t_reg = tuple([reg])
                inputs.append((t_reg, t_random_number))
        return inputs

class Bitwalk(Strategy):
    def generator(self, regs):
        inputs = []
        for reg in regs:
            pattern = 1
            for x in range(reg.bits):
                t_pattern = tuple([pattern << (x)])
                t_reg = tuple([reg])
                inputs.append((t_reg, t_pattern))
        return inputs

class BitFill(Strategy):
    def generator(self, regs):
        inputs = []
        for reg in regs:
            pattern = 1
            for x in range(reg.bits+1):
                t_pattern = tuple([(pattern << x) - 1])
                t_reg = tuple([reg])
                inputs.append((t_reg, t_pattern))
        return inputs

class ZeroWalk(Strategy):
    def generator(self, regs):
        inputs = []
        for reg in regs:
            pattern = (1 << reg.bits) - 1
            for x in range(reg.bits):
                flip_bit = 1 << x
                t_pattern = tuple([pattern ^ flip_bit])
                t_reg = tuple([reg])
                inputs.append((t_reg, t_pattern))
        return inputs

class TwoSame(Strategy):
    def generator(self, regs):
        inputs = []
        for pair in itertools.combinations(regs, 2):
            if pair[0].bits == pair[1].bits:
                for _ in range(self.num_runs):
                    pattern = random.getrandbits(pair[0].bits)
                    t_reg = tuple(pair)
                    t_pattern = tuple([pattern] * len(pair))
                    inputs.append((t_reg, t_pattern))
        return inputs

class TwoDiff(Strategy):
    def generator(self, regs):
        inputs = []
        for pair in itertools.combinations(regs, 2):
            if pair[0].bits == pair[1].bits:
                for _ in range(self.num_runs):
                    while True:
                        t_random_number_1 = random.getrandbits(pair[0].bits)
                        t_random_number_2 = random.getrandbits(pair[1].bits)
                        if t_random_number_1 != t_random_number_2:
                            break
                    t_reg = tuple(pair)
                    t_pattern = tuple([t_random_number_1, t_random_number_2])
                    inputs.append((t_reg, t_pattern))
        return inputs

class IEEE754Extended(Strategy):
    def generator(self, regs):
        inputs = []
        regs = [x for x in regs if x.bits == 80]

        for _ in range(self.num_runs):
            # regs are all 80bit registers
            for reg in regs:
                # this is fpX register
                # do a bitwalk for the exponent from 1 to 2**14
                # note that we do not want exponent to be all 0s or 1s
                # we also want the exponent to be greater than 2**14-1
                exponent = 0
                while exponent == 0 or exponent == 2**15-1 or exponent < 16383:
                    exponent = random.getrandbits(15)
                exponent <<= 63
                temp = self._gen_big_small(reg, regs, exponent)
                self._check_val(temp[1])
                inputs.append(temp)
                temp = self._gen_small_big(reg, regs, exponent)
                self._check_val(temp[1])
                inputs.append(temp)
            
        return inputs

    def _check_val(self, vals):
        for val in vals:
            assert((val & 0x80000000000000000000) == 0)


    def _gen_small_big(self, small_reg, regs, exponent):
        t_regs = []
        float_values = []

        # bit 80
        sign = 0
        # bit 63, msb of significand
        bit_63 = 1 << 62

        mantissa = random.getrandbits(6)
        float_value = mantissa + exponent + sign 
        t_regs.append(small_reg)
        float_values.append(float_value)

        # generate a random value for the fractional part of the significand
        for reg in regs:
            if reg != small_reg:
                mantissa = random.getrandbits(62)
            float_value = mantissa + exponent + sign 
            t_regs.append(reg)
            float_values.append(float_value)
        return (tuple(t_regs), tuple(float_values))

    def _gen_big_small(self, big_reg, regs, exponent):
        t_regs = []
        float_values = []

        # bit 80
        sign = 0
        # bit 63, msb of significand
        bit_63 = 1 << 62

        mantissa = random.getrandbits(62)
        float_value = mantissa + exponent + sign 
        t_regs.append(big_reg)
        float_values.append(float_value)

        # generate a random value for the fractional part of the significand
        for reg in regs:
            if reg != big_reg:
                mantissa = random.getrandbits(6)
            float_value = mantissa + exponent + sign 
            t_regs.append(reg)
            float_values.append(float_value)
        return (tuple(t_regs), tuple(float_values))


#class Float_xu(Strategy):
#    def generator(self, regs):
#        rands_for_lens = {}
#        rands_for_ops = []
#
#        if not(regs):
#            return set()
#
#        for reg in regs:
#            if reg.bits not in rands_for_lens:
#                if reg.bits == 32:
#                    rands = Float32.rand()
#                elif reg.bits == 64:
#                    rands = Float64.rand()
#                elif reg.bits == 80:
#                    rands = Float80.rand()
#                elif reg.bits == 128:
#                    rands = Float128.rand()
#                else:
#                    rands = Int.rand(reg.bits)
#                rands_for_lens[reg.bits] = rands
#
#        lens_mul = 1
#        for reg in regs:
#            lens_mul *= len(rands_for_lens[reg.bits])
#        if lens_mul > self.num_runs:
#            mul_factor = math.pow(float(self.num_runs) / lens_mul, 1.0 / len(regs))
#            for k in rands_for_lens:
#                new_len = int(math.ceil(len(rands_for_lens[k]) * mul_factor))
#                new_len = min(new_len, len(rands_for_lens[k]))
#                rands_for_lens[k] = random.sample(rands_for_lens[k], new_len)
#
#        for reg in regs:
#            rands_for_ops+=[rands_for_lens[reg.bits]]
#
#        outputs_gen = itertools.product(*rands_for_ops)
#        inputs = [(tuple(regs), tuple(c)) for c in outputs_gen]
#        return inputs[:self.num_runs]

