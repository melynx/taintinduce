import itertools
import random


class BaseMutate(object):
    bitwalk_array = None
    bitfill_array = None
    zerowalk_array = None
    @staticmethod
    def Bitwalk(bitnum):
        if BaseMutate.bitwalk_array is None:
            BaseMutate.bitwalk_array = []
            for i in range(256):
                BaseMutate.bitwalk_array += [1 << i]
        return BaseMutate.bitwalk_array[:bitnum]

    @staticmethod
    def Bitfill(bitnum):
        if BaseMutate.bitfill_array is None:
            BaseMutate.bitfill_array = []
            for i in range(256):
                BaseMutate.bitfill_array += [(1 << (i + 1)) - 1]
        return BaseMutate.bitfill_array[:bitnum]

    @staticmethod
    def Zerowalk(bitnum):
        mask = 0xffffffffffffffffffffffffffffffff  # 128bit 1
        mask2 = (1 << bitnum) - 1
        if BaseMutate.zerowalk_array is None:
            BaseMutate.zerowalk_array = []
            for i in range(256):
                BaseMutate.zerowalk_array += [mask ^ (1 << i)]
        return [c & mask2 for c in BaseMutate.zerowalk_array[:bitnum]]

    @staticmethod
    def Rannum(bitnum):
        inputs = []
        for i in range(bitnum):
            inputs += [random.getrandbits(bitnum)]
        return inputs


class Int(object):
    def __init__(self,bitsnum):
        self.value = random.getrandbits(bitsnum)

    @staticmethod
    def rand(bitsnum):
        return set(BaseMutate.Bitfill(bitsnum)+BaseMutate.Bitwalk(bitsnum)+BaseMutate.Zerowalk(bitsnum)+BaseMutate.Rannum(bitsnum))

class Float16(object):
    def __init__(self, s=None, e=None, f=None):
        self.value=random.getrandbits(16)
        if s is not None and e is not None and f is not None:
            self.s=s
            self.e=e
            self.f=f

    @property
    def s(self):
        return self.value >> 15

    @s.setter
    def s(self, value):
        self.value = (self.value & ((1 << 15) - 1)) + ((value & 0x1) << 15)

    @property
    def e(self):
        return (self.value & ((1 << 15) - 1)) >> 10

    @e.setter
    def e(self, value):
        self.value = (self.value & ((1 << 15) + ((1 << 10) - 1))) + (( value & ((1<<5)-1) ) << 10)

    @property
    def f(self):
        return self.value & ((1 << 10) - 1)

    @f.setter
    def f(self, value):
        self.value = (self.value & ((1 << 16) - 1 - ((1 << 10) - 1))) + (value & ((1 << 10) - 1))

    def __repr__(self):
        return "{:x}".format(self.value)

    @staticmethod
    def rand():
        ss = [0]
        es = BaseMutate.Bitfill(5) + BaseMutate.Bitwalk(5) + BaseMutate.Zerowalk(5) + BaseMutate.Rannum(5)
        fs = BaseMutate.Bitfill(10) + BaseMutate.Bitwalk(10) + BaseMutate.Zerowalk(10) + BaseMutate.Rannum(10)
        outputs = set({})
        for s, e, f in itertools.product(ss, es, fs):
            outputs.add(Float16(s, e, f).value)
        return outputs

class Float32(object):
    def __init__(self, s=None, e=None, f=None):
        self.value=random.getrandbits(32)
        if s is not None and e is not None and f is not None:
            self.s=s
            self.e=e
            self.f=f
            pass

    @property
    def s(self):
        return self.value>>31

    @s.setter
    def s(self,value):
        self.value = (self.value&0x7fffffff) + ((value&0x1)<<31)

    @property
    def e(self):
        return (self.value & 0x7fffffff) >> 23

    @e.setter
    def e(self,value):
        self.value=(self.value&0x807fffff) + ((value&0xff)<<23)

    @property
    def f(self):
        return self.value & 0x7fffff

    @f.setter
    def f(self,value):
        self.value=(self.value&0xff800000)+(value&0x7fffff)

    def __repr__(self):
        return "{:x}".format(self.value)

    def __cmp__(self, other):
        return self.value-other.value

    @staticmethod
    def rand():
        ss=[0]
        es=BaseMutate.Bitfill(8)+BaseMutate.Bitwalk(8)+BaseMutate.Zerowalk(8)+BaseMutate.Rannum(8)
        fs=BaseMutate.Bitfill(23)+BaseMutate.Bitwalk(23)+BaseMutate.Zerowalk(23)+BaseMutate.Rannum(23)
        outputs=set({})
        for s,e,f in itertools.product(ss,es,fs):
            outputs.add(Float32(s,e,f).value)
        return outputs

class Float64(object):
    def __init__(self, s=None, e=None, f=None):
        self.value = random.getrandbits(64)
        if s is not None and e is not None and f is not None:
            self.s = s
            self.e = e
            self.f = f

    @property
    def s(self):
        return self.value >> 63

    @s.setter
    def s(self, value):
        self.value = (self.value & 0x7fffffffffffffff) + ((value & 0x1) << 63)

    @property
    def e(self):
        return (self.value & 0x7fffffffffffffff) >> 52

    @e.setter
    def e(self, value):
        self.value = (self.value & 0x800fffffffffffff) + ((value & 0x7ff) << 52)

    @property
    def f(self):
        return self.value & 0xfffffffffffff

    @f.setter
    def f(self, value):
        self.value = (self.value & 0xfff0000000000000) + (value & 0xfffffffffffff)

    def __repr__(self):
        return "{:x}".format(self.value)

    def __cmp__(self, other):
        return self.value - other.value

    @staticmethod
    def rand():
        ss = [0]
        es = BaseMutate.Bitfill(11) + BaseMutate.Bitwalk(11) + BaseMutate.Zerowalk(11) + BaseMutate.Rannum(11)
        fs = BaseMutate.Bitfill(52) + BaseMutate.Bitwalk(52) + BaseMutate.Zerowalk(52) + BaseMutate.Rannum(52)
        outputs = set({})
        for s, e, f in itertools.product(ss, es, fs):
            outputs.add(Float64(s, e, f).value)
        return outputs

class Float80(object):
    def __init__(self, s=None, e=None, f=None):
        self.value = random.getrandbits(80)
        self.value |= (1 << 63)
        if s is not None and e is not None and f is not None:
            self.s = s
            self.e = e
            self.f = f

    @property
    def s(self):
        return self.value >> 79

    @s.setter
    def s(self, value):
        self.value = (self.value & 0x7fffffffffffffffffff) + ((value & 0x1) << 79)

    @property
    def e(self):
        return (self.value & 0x7fffffffffffffffffff) >> 64

    @e.setter
    def e(self, value):
        self.value = (self.value & 0x8000ffffffffffffffff) + ((value & 0x7fff) << 64)

    @property
    def f(self):
        return self.value & 0x7fffffffffffffff

    @f.setter
    def f(self, value):
        self.value = (self.value & 0xffff8000000000000000) + (value & 0x7fffffffffffffff)

    def __repr__(self):
        return "{:x}".format(self.value)

    def __cmp__(self, other):
        return self.value - other.value

    @staticmethod
    def rand():
        ss = [0]
        es = BaseMutate.Bitfill(15) + BaseMutate.Bitwalk(15) + BaseMutate.Zerowalk(15) + BaseMutate.Rannum(15)
        fs = BaseMutate.Bitfill(63) + BaseMutate.Bitwalk(63) + BaseMutate.Zerowalk(63) + BaseMutate.Rannum(63)
        outputs = set({})
        for s, e, f in itertools.product(ss, es, fs):
            outputs.add(Float80(s, e, f).value)
        return outputs

class Float128(object):
    def __init__(self, s=None, e=None, f=None):
        self.value = random.getrandbits(128)
        self.value |= (1 << 112)
        if s is not None and e is not None and f is not None:
            self.s = s
            self.e = e
            self.f = f

    @property
    def s(self):
        return self.value >> 127

    @s.setter
    def s(self, value):
        self.value = (self.value & ((1<<127)-1)) + ((value & 0x1) << 127)

    @property
    def e(self):
        return (self.value & ((1<<127)-1)) >> 112

    @e.setter
    def e(self, value):
        self.value = (self.value & ((1<<127)+((1<<112)-1))) + ((value & 0x7fff) << 112)

    @property
    def f(self):
        return self.value & ((1<<112)-1)

    @f.setter
    def f(self, value):
        self.value = (self.value & ((1<<128)-1-((1<<112)-1))) + (value & ((1<<112)-1) )

    def __repr__(self):
        return "{:x}".format(self.value)


    @staticmethod
    def rand():
        ss = [0]
        es = BaseMutate.Bitfill(15) + BaseMutate.Bitwalk(15) + BaseMutate.Zerowalk(15) + BaseMutate.Rannum(15)
        fs = BaseMutate.Bitfill(112) + BaseMutate.Bitwalk(112) + BaseMutate.Zerowalk(112) + BaseMutate.Rannum(112)
        outputs = set({})
        for s, e, f in itertools.product(ss, es, fs):
            outputs.add(Float128(s, e, f).value)
        return outputs

class Float256(object):
    def __init__(self, s=None, e=None, f=None):
        self.value=random.getrandbits(256)
        if s is not None and e is not None and f is not None:
            self.s=s
            self.e=e
            self.f=f

    @property
    def s(self):
        return self.value >> 255

    @s.setter
    def s(self, value):
        self.value = (self.value & ((1 << 255) - 1)) + ((value & 0x1) << 255)

    @property
    def e(self):
        return (self.value & ((1 << 255) - 1)) >> 236

    @e.setter
    def e(self, value):
        self.value = (self.value & ((1 << 255) + ((1 << 236) - 1))) + (( value & ((1<<19)-1) ) << 236)

    @property
    def f(self):
        return self.value & ((1 << 236) - 1)

    @f.setter
    def f(self, value):
        self.value = (self.value & ((1 << 256) - 1 - ((1 << 236) - 1))) + (value & ((1 << 236) - 1))

    def __repr__(self):
        return "{:x}".format(self.value)

    @staticmethod
    def rand():
        ss = [0]
        es = BaseMutate.Bitfill(19) + BaseMutate.Bitwalk(19) + BaseMutate.Zerowalk(19) + BaseMutate.Rannum(19)
        fs = BaseMutate.Bitfill(236) + BaseMutate.Bitwalk(236) + BaseMutate.Zerowalk(236) + BaseMutate.Rannum(236)
        outputs = set({})
        for s, e, f in itertools.product(ss, es, fs):
            outputs.add(Float256(s, e, f).value)
        return outputs