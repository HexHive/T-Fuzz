import logging
import os
import stat
import re
import shutil
import pickle
import threading
import time
import itertools
import stat
import ConfigParser
# from graphviz import Digraph

import angr
import fuzzer
import tracer

from . import r2
from . import cov

logger = logging.getLogger("tfuzz.tprogram")

class TProgram(object):

    def __init__(self, program_path, c_instr_addrs=None, c_block_addrs=None):
        assert os.path.exists(program_path), "%s does not exist" % program_path
        self.program_path = program_path
        program_name = os.path.basename(program_path)
        self.program_name = program_name
        self.program_dir = os.path.dirname(self.program_path)

        self.config_file = self.program_path + '.meta'
        self.config_section_name = 'tmeta'
        self.config = ConfigParser.RawConfigParser()
        self.__parent = None

        self.__init_seed_from_parenet = []
        self.__c_all_instr_addrs = [] if c_instr_addrs \
                                   is None else c_instr_addrs
        self.__c_all_block_addrs = [] if c_block_addrs \
                                   is None else c_block_addrs

        self.__c_block_addr = None
        self.__c_instr_addr = None
        self.inputs_from_fuzzing_parent = None

        if os.path.exists(self.config_file):
            self.config.read(self.config_file)
            self.__c_all_block_addrs = eval(self.config.get(self.config_section_name, 'c_all_block_addrs'))
            self.__c_all_instr_addrs = eval(self.config.get(self.config_section_name, 'c_all_instr_addrs'))
            self.__c_block_addr = eval(self.config.get(self.config_section_name, 'c_block_addr'))
            self.__c_instr_addr = eval(self.config.get(self.config_section_name, 'c_instr_addr'))
            self.inputs_from_fuzzing_parent = eval(self.config.get(self.config_section_name, 'inputs_from_fuzzing_parent'))

    def is_cgc(self):
        '''
        QUICK HACK by checking the magic values
        '''
        ret = False
        with open(self.program_path, 'r') as f:
            f4 = f.read(4)
            if f4[1:] == "CGC":
                ret = True
        return ret

    @property
    def c_block_addr(self):
        return self.__c_block_addr

    @c_block_addr.setter
    def c_block_addr(self, addr):
        self.__c_block_addr = addr

    @property
    def c_instr_addr(self):
        return self.__c_instr_addr

    @c_instr_addr.setter
    def c_instr_addr(self, addr):
        self.__c_instr_addr = addr

    @property
    def c_all_instr_addrs(self):
        return self.__c_all_instr_addrs

    @c_all_instr_addrs.setter
    def c_all_instr_addrs(self, c_addrs):
        self.__c_all_instr_addrs = c_addrs

    @property
    def c_all_block_addrs(self):
        return self.__c_all_block_addrs

    @c_all_block_addrs.setter
    def c_all_block_addrs(self, c_addrs):
        self.__c_all_block_addrs = c_addrs

    @property
    def parent(self):
        return self.__parent

    @parent.setter
    def parent(self, p):
        self.__parent = p

    def __str__(self):
        return "<" + self.program_path + ">"

    def __repr__(self):
        return self.__str__()

    def __del__(self):
        self.write_metadata()

    def write_metadata(self):
        if self.config == None:
            return

        try:
            self.config.add_section(self.config_section_name)
        except:
            pass

        self.config.set(self.config_section_name, 'c_all_block_addrs', self.__c_all_block_addrs)
        self.config.set(self.config_section_name, 'c_all_instr_addrs', self.__c_all_instr_addrs)
        self.config.set(self.config_section_name, 'c_block_addr', self.__c_block_addr)
        self.config.set(self.config_section_name, 'c_instr_addr', self.__c_instr_addr)
        self.config.set(self.config_section_name, 'inputs_from_fuzzing_parent', self.inputs_from_fuzzing_parent)

        with open(self.config_file, 'w') as f:
            self.config.write(f)

