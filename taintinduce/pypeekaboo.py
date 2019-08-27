import os
import sys
import struct

from ctypes import Structure, c_uint64, c_uint32, c_uint16, c_uint8, sizeof

def read_struct(myfile, mystruct):
    x = mystruct()
    assert(myfile.readinto(x) == sizeof(mystruct))
    return x


class GPR_AMD64(Structure):
    _fields_ = [('rdi', c_uint64),
                ('rsi', c_uint64),
                ('rsp', c_uint64),
                ('rbp', c_uint64),
                ('rbx', c_uint64),
                ('rdx', c_uint64),
                ('rcx', c_uint64),
                ('rax', c_uint64),
                ('r8', c_uint64),
                ('r9', c_uint64),
                ('r10', c_uint64),
                ('r11', c_uint64),
                ('r12', c_uint64),
                ('r13', c_uint64),
                ('r14', c_uint64),
                ('r15', c_uint64),
                ('rflags', c_uint64),
                ('rip', c_uint64)]

class SIMD_AMD64(Structure):
    _fields_ = [('ymm0', c_uint64*4),
                ('ymm1', c_uint64*4),
                ('ymm2', c_uint64*4),
                ('ymm3', c_uint64*4),
                ('ymm4', c_uint64*4),
                ('ymm5', c_uint64*4),
                ('ymm6', c_uint64*4),
                ('ymm7', c_uint64*4),
                ('ymm8', c_uint64*4),
                ('ymm9', c_uint64*4),
                ('ymm10', c_uint64*4),
                ('ymm11', c_uint64*4),
                ('ymm12', c_uint64*4),
                ('ymm13', c_uint64*4),
                ('ymm14', c_uint64*4),
                ('ymm15', c_uint64*4)]

class FXSAVE_AREA(Structure):
    _fields_ = [('fcw', c_uint16),
                ('fsw', c_uint16),
                ('ftw', c_uint8),
                ('reserved_1', c_uint8),
                ('fop', c_uint16),
                ('fpu_ip', c_uint32),
                ('fpu_cs', c_uint16),
                ('reserved_2', c_uint16),
                ('fpu_dp', c_uint32),
                ('fpu_ds', c_uint16),
                ('reserved_3', c_uint16),
                ('mxcsr', c_uint32),
                ('mxcsr_mask', c_uint32),
                ('st_mm', c_uint64*2*8),
                ('xmm', c_uint64*2*16),
                ('padding', c_uint8*96)]


class RegFileAMD64(Structure):
    _fields_ = [('gpr', GPR_AMD64), ('simd', SIMD_AMD64), ('fxsave', FXSAVE_AREA)]



ARCH_INFO = {0:None, 1:None, 2:None, 3:(RegFileAMD64, "AMD64")}

class Metadata(Structure):
    _fields_ = [('arch', c_uint32), ('version', c_uint32)]

'''
typedef struct insn_ref {
	uint64_t pc;
} insn_ref_t;
'''
class InsnRef(Structure):
    _fields_ = [('pc', c_uint64)]

'''
typedef struct bytes_map {
	uint64_t pc;
	uint32_t size;
	uint8_t rawbytes[16];
} bytes_map_t ;
'''
class BytesMap(Structure):
    _fields_ = [('pc', c_uint64), ('size', c_uint32), ('rawbytes', c_uint8*16)]

'''
typedef struct {
	uint32_t length;	/* how many refs are there*/
} memref_t;
'''
class MemRef(Structure):
    _fields_ = [('length', c_uint32)]

'''
typedef struct {
	uint64_t addr;		/* memory address */
	uint64_t value;		/* memory value */
	uint32_t size;		/* how many bits are vaild in value */
	uint32_t status; 	/* 0 for Read, 1 for write */
} memfile_t;
'''
class MemFile(Structure):
    _fields_ = [('addr', c_uint64), ('value', c_uint64), ('size', c_uint32), ('status', c_uint32)]


class TraceInsn(object):
    def __init__(self):
        self.addr = None
        self.rawbytes = None
        self.num_mem = None
        self.mem = []
        self.regfile = None
        pass

class MemInfo(object):
    def __init__(self):
        pass

class PyPeekaboo(object):
    def __init__(self, trace_path):
        # ensure that path points to a directory...
        assert(os.path.isdir(trace_path))
        # ensure that the basic structure is correct
        insn_trace_path = os.path.join(trace_path, 'insn.trace')
        insn_bytemap_path = os.path.join(trace_path, 'insn.bytemap')
        regfile_path = os.path.join(trace_path, 'regfile')
        memfile_path = os.path.join(trace_path, 'memfile')
        memrefs_path = os.path.join(trace_path, 'memrefs')
        metafile_path = os.path.join(trace_path, 'metafile')
        assert(os.path.isfile(insn_trace_path))
        assert(os.path.isfile(insn_bytemap_path))
        assert(os.path.isfile(regfile_path))
        assert(os.path.isfile(memfile_path))
        assert(os.path.isfile(memrefs_path))
        assert(os.path.isfile(metafile_path))

        # open up the files
        self.insn_trace = open(insn_trace_path, 'rb')
        self.insn_bytemap = open(insn_bytemap_path, 'rb')
        self.regfile = open(regfile_path, 'rb')
        self.memfile = open(memfile_path, 'rb')
        self.memrefs = open(memrefs_path, 'rb')
        self.metafile = open(metafile_path, 'rb')

        # parse metafile
        metadata = read_struct(self.metafile, Metadata)
        self.regfile_struct, self.arch_str = ARCH_INFO[metadata.arch]

        self.memrefs_offsets = self.load_memrefs_offsets(trace_path)
        self.num_insn = os.path.getsize(insn_trace_path) / sizeof(InsnRef)

        # parse the bytemaps
        self.bytesmap = {}
        bytesmap_entry = BytesMap()
        while self.insn_bytemap.readinto(bytesmap_entry) == sizeof(bytesmap_entry):
            self.bytesmap[bytesmap_entry.pc] = [x for x in bytesmap_entry.rawbytes][:bytesmap_entry.size]

    def load_memrefs_offsets(self, trace_path):
        memrefs_offsets_path = os.path.join(trace_path, 'memrefs_offsets')
        if not os.path.isfile(memrefs_offsets_path):
            # memfile offsets for each insn does not exist, create them
            # generate the memfile offsets
            print("{} does not contain the cached offsets to memfile, generating...".format(trace_path))
            with open(memrefs_offsets_path, 'wb') as offset_file:
                cur_offset = 0
                memfile_offsets = []
                memref_entry = MemRef()
                while self.memrefs.readinto(memref_entry) == sizeof(memref_entry):
                    if memref_entry.length:
                        offset_file.write(struct.pack('<Q', cur_offset))
                        cur_offset += sizeof(MemFile) * memref_entry.length
                    else:
                        # 63rd bit tell us if its valid or not, 0 is valid, 1 is not
                        offset_file.write(struct.pack('<Q', 2**63))
        return open(memrefs_offsets_path, 'rb')

    def get_insn(self, insn_id):

        # get the offset of the instruction into the different files.
        insn_trace_foffset = insn_id * sizeof(InsnRef)
        memrefs_foffset = insn_id * sizeof(MemRef)
        regfile_foffset = insn_id * sizeof(self.regfile_struct)
        memfile_index_foffset = insn_id * 8

        my_insn = TraceInsn()

        self.insn_trace.seek(insn_trace_foffset)
        my_insn.addr = read_struct(self.insn_trace, InsnRef).pc
        my_insn.rawbytes = self.bytesmap[my_insn.addr]

        self.memrefs.seek(memrefs_foffset)
        my_insn.num_mem = read_struct(self.memrefs, MemRef).length

        my_insn.mem = []
        if my_insn.num_mem:
            self.memrefs_offsets.seek(memfile_index_foffset)
            for _ in range(my_insn.num_mem):
                buf = self.memrefs_offsets.read(8)
                memref_offset = struct.unpack('<Q', buf)[0]
                self.memfile.seek(memref_offset)
                my_insn.mem.append(read_struct(self.memfile, MemFile))

        self.regfile.seek(regfile_foffset)
        my_insn.regfile = read_struct(self.regfile, self.regfile_struct)
        return my_insn

    
    def pp(self):
        insn_ref = InsnRef()
        while self.insn_trace.readinto(insn_ref) == sizeof(InsnRef):
            rawbytes = self.bytesmap[insn_ref.pc]
            print("{}\t: {}".format(hex(insn_ref.pc), [hex(x) for x in rawbytes]))

