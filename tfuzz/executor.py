import subprocess32
import os

import logging

logger = logging.getLogger("tfuzz.executor")

class Executor(object):

    def __init__(self, program, target_opts=None, timeout=10, record_stdout=False):
        '''
        The class to run a target program natively.

        :ivar program:        the path to the program to run
        :ivar target_opts:    optional, a list variable containing all the options 
                              passed to the program (excuding the program, e.g., 
                              to run `ls -al`, target_opts should be ['-al'])
        :ivar timeout:        an integer specifying the maximum time to 
                              run the target program in second
        :ivar record_stdout:  bool, whether to record the stdout or not, if true,
                              the output will be saved in `stdout` field
        '''

        self.program = os.path.abspath(program)

        args = [self.program]
        if target_opts != None:
            args = args + target_opts

        self.args = args
        self.crash = False
        self.timeout = timeout
        self.tmout = False
        self.timeout = timeout
        self.record_stdout = record_stdout

        self._run()

    def _run(self):
        try:
            if self.record_stdout:
                self.stdout = subprocess32.check_output(self.args, timeout=self.timeout)
            else:
                subprocess32.check_output(self.args, timeout=self.timeout)
        except subprocess32.TimeoutExpired:
            self.tmout = True
        except subprocess32.CalledProcessError:
            self.crash = True
