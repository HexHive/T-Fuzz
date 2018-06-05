import sys
import os
import re
import logging

import r2pipe
from intervaltree import Interval, IntervalTree

import angr

logger = logging.getLogger("tfuzz.ncc")

class FuncBasedFilter(object):

    def __init__(self, program, include_funcs=None, exclude_funcs=None):
        self.map = IntervalTree()
        self.funcs = set()
        self.include_funcs = set(include_funcs) if \
                             include_funcs != None else set() 
        self.exclude_funcs = set([
            "__libc_csu_fini",
            "__afl_manual_init",
            "__x86.get_pc_thunk.bx",
            "atexit",
            "__afl_persistent_loop",
            "__sanitizer_cov_trace_pc_guard",
            "__afl_auto_init",
            "__libc_csu_init",
            "__sanitizer_cov_trace_pc_guard_init",
            "fadvise",
            "fdadvise",
            "_crcx",
            "_crcx_docrc",
            "longjmp",
            "setjmp",
            "random",
            "_terminate",
            "deallocate",
            "_start",
            "transmit",
            "fdwait",
            "receive",
            "allocate"
        ])

        if exclude_funcs != None:
            self.exclude_funcs.update(exclude_funcs)
        
        self._build_addr_map(program)

    def _build_addr_map(self, program):
        r2 = r2pipe.open(program)
        symbols = r2.cmdj('isj')

        for s in symbols:
            if s['type'] != 'FUNC':
                continue

            if s['size'] == 0:
                continue

            if s['name'].startswith('imp'):
                continue

            if s['name'] in self.exclude_funcs:
                continue
            
            if s['name'] not in self.include_funcs:
                self.include_funcs.add(s['name'])

            self.map[s['vaddr']: s['vaddr'] + s['size']] = s['name']
            self.funcs.add(s['name'])

        r2.quit()

    def _in_which_function(self, key):
        if len(self.map[key]) == 0:
            return None
        return list(self.map[key])[0].data

    def filter(self, from_addr, to_addr):
        from_func = self._in_which_function(from_addr)
        to_func = self._in_which_function(to_addr)
        return from_func == to_func and from_func in self.include_funcs

class NCCDetector(object):

    def __init__(self, program_path, filters=None):
        self.program_path = program_path
        self.project = angr.Project(program_path, auto_load_libs=False)
        self.cfg = self.project.analyses.CFG()
        self.filters = [] if filters == None else filters

    def add_filter(self, filter):
        self.filters.append(filter)

    def detect_nccs(self, acc_cov):
        # TODO: optimize this algorithm
        for e in self.cfg.graph.edges():
            from_node, to_node = e
            if (from_node.addr, to_node.addr) in acc_cov.edges() or \
               from_node.addr not in acc_cov.nodes() or \
               to_node.addr in acc_cov.nodes():
                continue
            fout = False
            for f in self.filters:
                # if any of the filters returns false, we should discard it
                if not f.filter(from_node.addr, to_node.addr):
                    logger.info("(%s, %s) filtered out" % \
                                (hex(from_node.addr), hex(to_node.addr)))
                    fout = True
                    break
            if fout:
                continue
            yield (from_node.addr, to_node.addr)
