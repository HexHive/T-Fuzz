import os
import sys
import threading
import logging
import shutil
import time

logger = logging.getLogger("tfuzz.tfuzz_sys")

from .cov import AccCov
from .ncc import NCCDetector
from .ncc import FuncBasedFilter
from .r2 import Radare2
from .cov import DynamicTrace
from .tfuzz_fuzzer import Fuzzer
from .tprogram import TProgram
from .utils import create_dict

class TFuzzSys():

    def __init__(self, binary_path, workdir, afl_count=1, target_opts=None,
                 seed_files=None, rand_seed=False, check_interval=30,
                 input_placeholder='@@', afl_opts=None):

        assert os.path.exists(binary_path), "% does not exist" % binary_path

        self.origin_binary_path = binary_path
        self.origin_binary_name = os.path.basename(binary_path)
        self.workdir = os.path.abspath(workdir)
        self.afl_count = afl_count
        self.target_opts = target_opts
        self.check_interval = check_interval
        self.afl_opts = afl_opts if afl_opts is not None else []
        self.input_placeholder = input_placeholder
        self.seed_files = seed_files
        self.rand_seed = rand_seed

        # TODO: Add resuming feature
        if os.path.exists(workdir):
            print("%s already exist" % (workdir))
            raise Exception()

        # preparing seeds
        self.init_seed_files = []
        self.init_seed_dir = os.path.join(self.workdir, 'init_seeds')
        self.__prepare_init_seeds()
            
        self.__queue = []

        # Preparing the first TProgram
        original_tprogram_dir = os.path.join(self.workdir,
                                             self.origin_binary_name + '_tfuzz')
        original_tprogram_path = os.path.join(original_tprogram_dir,
                                              self.origin_binary_name + '_tfuzz')

        os.makedirs(original_tprogram_dir)
        shutil.copyfile(binary_path, original_tprogram_path)
        os.chmod(original_tprogram_path, 0777)

        self.dict_file = os.path.join(self.workdir,
                                      self.origin_binary_name + '.dict')
        create_dict(self.origin_binary_path, self.dict_file)
        if '-x' not in self.afl_opts:
            self.afl_opts = ['-x', self.dict_file] + self.afl_opts

        self.original_tprogram = TProgram(original_tprogram_path)
        self.__queue.append(self.original_tprogram)

        self.__current_fuzzer = None

        self.__stop = False

        ff = FuncBasedFilter(self.origin_binary_path, include_funcs=['main'])
        self.nccdetector = NCCDetector(self.origin_binary_path, filters=[ff])

    def __prepare_init_seeds(self):
        try:
            os.makedirs(self.init_seed_dir)
        except:
            pass

        if self.seed_files != None and len(self.seed_files) != 0:
            for sf in self.seed_files:
                shutil.copy(sf, self.init_seed_dir)
                self.init_seed_files.append(os.path.join(self.init_seed_dir, os.path.basename(sf)))
            return

        # no seed files are provided
        gen_init_seed_file = os.path.join(self.init_seed_dir, 'seed-0')

        with open(gen_init_seed_file, 'w') as f:
            if self.rand_seed:
                f.write(os.urandom(32))
            else:
                f.write("fuzz")

        self.init_seed_files.append(gen_init_seed_file)

    def __choose_program(self):
        if len(self.__queue) == 0:
            return None

        return self.__queue.pop(0)

    def __queue_empty(self):
        return len(self.__queue) == 0

    def __add_to_queue(self, tprogram):
        self.__queue.append(tprogram)

    def __prepare_fuzzing_workdir(self, tprogram):
        tprogram_fuzzing_workdir = os.path.join(self.workdir, 'fuzzing_' + tprogram.program_name)
        if not os.path.exists(tprogram_fuzzing_workdir):
            os.makedirs(tprogram_fuzzing_workdir)

        return tprogram_fuzzing_workdir

    def __clean_tprogram(self, tprogram):
        dname = os.path.dirname(tprogram.program_path)
        try:
            shutil.rmtree(dname)
        except:
            pass

    def __fuzz_one_program(self):

        fuzzing_workdir = self.__prepare_fuzzing_workdir(self.fuzzing_program)

        if self.fuzzing_program == self.original_tprogram:
            init_seeds = self.init_seed_files
        else:
            init_seeds = self.fuzzing_program.inputs_from_fuzzing_parent
    
        self.__current_fuzzer = Fuzzer(self.fuzzing_program, init_seeds,
                                       fuzzing_workdir, target_opts=self.target_opts,
                                       input_placeholder=self.input_placeholder,
                                       afl_opts=self.afl_opts)

        self.__current_fuzzer.start()

        time.sleep(2)
        
        if self.__current_fuzzer.failed_to_start():
            self.__current_fuzzer.stat['status'] = "failed to start"
            return False

        return True

    
    def run(self):

        while not self.__stop:

            program = self.__choose_program()
            if program == None:
                logger.warn("No program left")
                sys.exit()

            self.fuzzing_program = program
            if not self.__fuzz_one_program():
                logger.warn("%s failed to start, \
                skip, but there still might be some \
                crashes in crashing seeds", self.fuzzing_program)
                continue

            logger.debug("Fuzzing %s started", (self.fuzzing_program.program_name))
            while not self.__current_fuzzer.is_stuck():
                time.sleep(self.check_interval)


            logger.debug("Fuzzer got stuck")
            crash_seeds = len(self.__current_fuzzer.crash_seeds())
            crash_found = len(self.__current_fuzzer.crashes_found())
            if crash_seeds > 0 or crash_found > 0:
                logger.debug("Crashes found while fuzzing %s", self.fuzzing_program.program_name)

            self.__current_fuzzer.stat['crash_found'] = crash_found
            self.__current_fuzzer.stat['crash_seeds'] = crash_seeds
            self.__current_fuzzer.stop()
            self.__current_fuzzer.write_stat()

            acc_cov = AccCov()
            generated_inputs = self.__current_fuzzer.generated_inputs()
            for i in generated_inputs:
                t = DynamicTrace(self.fuzzing_program.program_path, i,
                                 target_opts=self.target_opts,
                                 input_placeholder=self.input_placeholder)

                acc_cov.add_trace(t)

            i = 0
            for from_addr, to_addr in self.nccdetector.detect_nccs(acc_cov):
                if from_addr in self.fuzzing_program.c_all_block_addrs:
                    continue

                transformed_program_name = self.fuzzing_program.program_name + '_' + str(i)
                transformed_program_dir = os.path.join(self.workdir, transformed_program_name)
                transformed_program_path = os.path.join(transformed_program_dir, transformed_program_name)
                try:
                    os.makedirs(transformed_program_dir)
                except:
                    pass

                shutil.copyfile(self.fuzzing_program.program_path, transformed_program_path)
                os.chmod(transformed_program_path, 0777)
                transformed_tprogram = TProgram(transformed_program_path)

                transformed_tprogram.c_all_instr_addrs = self.fuzzing_program.c_all_instr_addrs[:]
                transformed_tprogram.c_all_block_addrs = self.fuzzing_program.c_all_block_addrs[:]

                transformed_tprogram.c_block_addr = from_addr
                transformed_tprogram.c_all_block_addrs.append(from_addr)

                # TODO: guard this code with context manager
                radare2 = Radare2(transformed_program_path, flags=['-w'])
                c_addr = radare2.get_cjump_addr(from_addr)
                if c_addr == 0:
                    self.__clean_tprogram(transformed_tprogram)
                    continue

                radare2.negate_cjmp(c_addr)

                radare2.close()

                transformed_tprogram.c_all_instr_addrs.append(c_addr)
                transformed_tprogram.c_instr_addr = c_addr
                transformed_tprogram.inputs_from_fuzzing_parent = generated_inputs
                transformed_tprogram.write_metadata()

                self.__add_to_queue(transformed_tprogram)
                i = i + 1

            logger.debug("Fuzzing %s done", self.fuzzing_program.program_name)

    def stop(self):
        self.__stop = True
