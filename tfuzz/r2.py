import r2pipe
from intervaltree import Interval, IntervalTree
import argparse
import capstone
import archinfo
import re
from contextlib import contextmanager

class Radare2(object):

    def __init__(self, program, flags=None):
        self.program = program

        # if flags == None:
        #     flags = ['-w']

        # if '-w' not in flags:
        #     flags.append('-w')

        if flags != None and isinstance(flags, list):
            self.r2 = r2pipe.open(self.program, flags=flags)
        else:
            self.r2 = r2pipe.open(self.program)
        # self.r2.cmd("aa")

        i_json = self.r2.cmdj('ij')
        self.os = i_json['bin']['os']
        self.arch = i_json['bin']['arch']
        self.bits  = i_json['bin']['bits']
        self.pic  = i_json['bin']['pic']


        if self.arch == 'x86':
            if self.bits == '64':
                self.archinfo = archinfo.ArchAMD64
            else:
                self.archinfo = archinfo.ArchX86
        else:
            self.archinfo = None

        if self.archinfo != None:
            self.md = capstone.Cs(self.archinfo.cs_arch, self.archinfo.cs_mode)
        else:
            self.md = None

    def __getitem__(self, key):
        self.r2.cmd('s ' + hex(key))
        ret = self.r2.cmd('p8 1')
        try:
            ret = int(ret, base=16)
        except ValueError:
            ret = None

        return ret

    def __setitem__(self, key, val):
        val = val & 0xFF
        val = "{0:0x}".format(val)
        self.r2.cmd('s ' + hex(key))
        self.r2.cmd('wx ' + val)

    def get_bytes_n(self, addr, n):
        '''
        This function returns an array of `n` bytes
        '''
        self.r2.cmd('s ' + hex(addr))

        return self.r2.cmdj('pcj ' + str(n))

    def get_cjump_addr(self, blk_addr):
        code_byte_array = self.get_bytes_n(blk_addr, 1024)
        code_char_array = [chr(b) for b in code_byte_array]
        code_str = ''.join(code_char_array)
        gen = self.md.disasm(code_str, blk_addr)

        for i in gen:
            if i.mnemonic.startswith('j') and i.mnemonic != 'jmp':
                # print("Found a jump instruction at %s(%d): %s"%(hex(i.address), i.size,
                #                                                i.mnemonic + ' ' + i.op_str))
                return i.address

        print("Conditional jump instruction not found")
        return 0

    def negate_cjmp(self, cjump_inst_addr):
        '''
        Only X86/X86_64 are supported now
        '''

        if self.md == None:
            raise NotImplementedError

        # http://unixwiz.net/techtips/x86-jumps.html
        x86_jmp_pairs ={
            'jo':'jno',
            'js': 'jns',
            'je': 'jne',
            'jz': 'jnz',
            'jb': 'jnb',
            'jae': 'jnae',
            'jc': 'jnc',
            'ja': 'jna',
            'jbe': 'jnbe',
            'jl': 'jnl',
            'jge': 'jnge',
            'jg': 'jng',
            'jle': 'jnle',
            'jp': 'jnp',
            'jpe': 'jpo',
            'jcxz': 'jecxz'
        }

        # add the original map
        x86_jmp_map = x86_jmp_pairs.copy()

        # add the reverse map
        for ji in x86_jmp_pairs.keys():
            x86_jmp_map[x86_jmp_pairs[ji]] = ji

        code_byte_array = self.get_bytes_n(cjump_inst_addr, 1024)
        code_char_array = [chr(b) for b in code_byte_array]
        code_str = ''.join(code_char_array)
        gen = self.md.disasm(code_str, cjump_inst_addr)

        i = gen.next()

        # we use this heuristic to determine it is a jump instruction
        if i.mnemonic not in x86_jmp_map:
            print("It is not a conditional jump instruction at @%s:%s" %
                  (hex(cjump_inst_addr), i.mnemonic + ' ' + i.op_str))
            return

        self.r2.cmd('s ' + str(i.address))

        # then negate the conditional jump instruction
        self.r2.cmd('wa ' + x86_jmp_map[i.mnemonic] + ' ' + i.op_str)
        return i.address

    def close(self):
        try:
            self.r2.quit()
        except:
            pass

    def __del__(self):
        self.close()


@contextmanager
def closing_r2(r2):
    try:
        yield r2
    finally:
        r2.close()

