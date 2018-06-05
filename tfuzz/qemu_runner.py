import os
import time
import shutil
import signal
import socket
import logging
import resource
import tempfile
import re
import subprocess32
from contextlib import contextmanager

from .r2 import Radare2

l = logging.getLogger("tfuzz.qemu_runner")

try:
    import shellphish_qemu
except ImportError:
    raise ImportError("Unable to import shellphish_qemu, \
    which is required by QEMURunner. Please install it\
    before proceeding.")

class RunnerEnvironmentError(Exception):
    pass

def binary_type(binary):
    with file(binary) as f:
        f4 = f.read(4)
        if f4[1:] == "CGC":
            return "cgc"
        elif f4[1:] == "ELF":
            return "elf"

        return "Other"

class QEMURunner(object):

    def __init__(self, binary=None,
                 input=None,
                 record_trace=True,
                 record_stdout=False,
                 record_magic=True,
                 max_size = None,
                 seed=None,
                 memory_limit="8G",
                 bitflip=False,
                 report_bad_args=False,
                 argv=None,
                 trace_log_limit=2**30,
                 trace_timeout=10):

        self.binary = os.path.abspath(binary)
        self.tmout = False
        self._record_magic = record_magic
        self._record_trace = record_trace
        self.input = input

        if isinstance(seed, (int, long)):
            seed = str(seed)
        self._seed = seed
        self._memory_limit = memory_limit
        self._bitflip = bitflip
        self._report_bad_args = report_bad_args
        self.argv = argv
        self.crash_mode=False
        self.crash_addr = None

        # validate seed
        if self._seed is not None:
            try:
                iseed = int(self._seed)
                if iseed > 4294967295 or iseed < 0:
                    raise ValueError
            except ValueError:
                raise ValueError("The passed seed is either not an integer \
                or is not between 0 and UINT_MAX")

        self.input_max_size = max_size or len(input) if input is not None else None
        self.trace_log_limit = trace_log_limit
        self.trace_timeout = trace_timeout

        self._trace_source_path = None

        self._setup()

        if record_stdout:
            tmp = tempfile.mktemp(prefix="stdout_" + os.path.basename(binary))
            # will set crash_mode correctly
            self._run(stdout_file=tmp)
            with open(tmp, "rb") as f:
                self.stdout = f.read()
            os.remove(tmp)
        else:
            # will set crash_mode correctly
            self._run()

    def _setup(self):
        if not os.access(self.binary, os.X_OK):
            if os.path.isfile(self.binary):
                error_msg = "\"%s\" binary is not executable" % self.binary
                l.error(error_msg)
                raise RunnerEnvironmentError(error_msg)
            else:
                error_msg = "\"%s\" binary does not exist" % self.binary
                l.error(error_msg)
                raise RunnerEnvironmentError(error_msg)

        # try to find the install base
        self._check_qemu_install()

    def _check_qemu_install(self):
        """
        Check the install location of QEMU.
        """
        btype = binary_type(self.binary)
        if btype == "cgc":
            tname = "cgc-tracer"
        elif btype == "elf":
            self._record_magic = False
            r2 = Radare2(self.binary)
            if r2.arch == "x86" and r2.bits == 64:
                tname = "linux-x86_64"
            elif r2.arch == "x86" and r2.bits == 32:
                tname = "linux-i386"
            else:
                raise RunnerEnvironmentError("Binary type not supported")
        else:
            raise RunnerEnvironmentError("Binary type not supported")

        self._trace_source_path = shellphish_qemu.qemu_path(tname)
        if not os.access(self._trace_source_path, os.X_OK):
            if os.path.isfile(self._trace_source_path):
                error_msg = "%s is not executable" % self.trace_source
                l.error(error_msg)
                raise RunnerEnvironmentError(error_msg)
            else:
                error_msg = "\"%s\" does not exist" % self._trace_source_path
                l.error(error_msg)
                raise RunnerEnvironmentError(error_msg)

    def __get_rlimit_func(self):
        def set_fsize():
            # here we limit the logsize
            resource.setrlimit(resource.RLIMIT_FSIZE,
                               (self.trace_log_limit, self.trace_log_limit))
        return set_fsize

    def _run(self, stdout_file=None):

        # import ipdb; ipdb.set_trace()

        logname = tempfile.mktemp(dir="/dev/shm/", prefix="tracer-log-")

        args = [self._trace_source_path]
        if self._seed is not None:
            args.append("-seed")
            args.append(str(self._seed))

        # If the binary is CGC we'll also take this opportunity to read in the
        # magic page.
        if self._record_magic:
            mname = tempfile.mktemp(dir="/dev/shm/", prefix="tracer-magic-")
            args += ["-magicdump", mname]

        if self._record_trace:
            args += ["-d", "exec", "-D", logname]
        else:
            args += ["-enable_double_empty_exiting"]

        # Memory limit option is only available in shellphish-qemu-cgc-*
        if 'cgc' in self._trace_source_path:
            args += ["-m", self._memory_limit]

        args += self.argv or [self.binary]

        if self._bitflip:
            args = [args[0]] + ["-bitflip"] + args[1:]

        with open('/dev/null', 'wb') as devnull:
            stdout_f = devnull
            if stdout_file is not None:
                stdout_f = open(stdout_file, 'wb')

            p = None
            try:
                # we assume qemu with always exit and won't block
                if type(self.input) == str:
                    l.debug("Tracing as raw input")
                    l.debug(" ".join(args))
                    p = subprocess32.Popen(args, stdin=subprocess32.PIPE,
                                           stdout=stdout_f, stderr=devnull,
                                           preexec_fn=self.__get_rlimit_func())

                    _, _ = p.communicate(self.input, timeout=self.trace_timeout)
                else:
                    l.debug("Tracing as pov file")
                    in_s, out_s = socket.socketpair()
                    p = subprocess32.Popen(args, stdin=in_s, stdout=stdout_f,
                                           stderr=devnull,
                                           preexec_fn=self.__get_rlimit_func())

                    for write in self.input.writes:
                        out_s.send(write)
                        time.sleep(.01)

                ret = p.wait(timeout=self.trace_timeout)

                # did a crash occur?
                if ret < 0:
                    if abs(ret) == signal.SIGSEGV or abs(ret) == signal.SIGILL:
                        l.info("Input caused a crash (signal %d) \
                        during dynamic tracing", abs(ret))
                        l.debug(repr(self.input))
                        l.debug("Crash mode is set")
                        self.crash_mode = True

            except subprocess32.TimeoutExpired:
                if p != None:
                    p.terminate()
                    self.tmout = True

            self.returncode = p.returncode

            if stdout_file is not None:
                stdout_f.close()

        if self._record_trace:
            try:
                trace = open(logname).read()
                addrs = []
                self.trace = addrs

                # Find where qemu loaded the binary. Primarily for PIE
                qemu_base_addr = int(trace.split("start_code")[1].split("\n")[0], 16)
                self.base_addr = qemu_base_addr

                prog = re.compile(r'Trace (.*) \[(?P<addr>.*)\].*')
                for t in trace.split('\n'):
                    m = prog.match(t)
                    if m != None:
                        addr_str = m.group('addr')
                        addrs.append(int(addr_str, base=16))
                    else:
                        continue

                # grab the faulting address
                if self.crash_mode:
                    self.crash_addr = int(trace.split('\n')[-2].split('[')[1].split(']')[0], 16)

                l.debug("Trace consists of %d basic blocks", len(self.trace))
            except IndexError:
                l.warning("""One trace is found to be malformated,
                it is possible that the log file size exceeds the 1G limit,
                meaning that there might be infinite loops in the target program""")
            finally:
                os.remove(logname)

        if self._record_magic:
            try:
                self.magic = open(mname).read()
                a_mesg = "Magic content read from QEMU improper size, \
                should be a page in length"
                assert len(self.magic) == 0x1000, a_mesg
            except IOError:
                pass
            finally:
                try:
                    os.remove(mname)
                except OSError:
                    pass
