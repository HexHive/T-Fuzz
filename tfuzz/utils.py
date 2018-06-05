import os
import sys
import subprocess

from fuzzer import Fuzzer as __angr_Fuzzer

def create_dict(binary, dict_filename):
    create_dict_script = os.path.join(__angr_Fuzzer._get_base(),
                                      "bin", "create_dict.py")
    args = [sys.executable, create_dict_script, binary]

    with open(dict_filename, 'wb') as df:
        p = subprocess.Popen(args, stdout=df)
        retcode = p.wait()

    return retcode == 0 and os.path.getsize(dict_filename)

def replace_input_placeholder(target_opts, input_file,
                              input_placeholder='@@'):
    if target_opts == None:
        return None

    if input_file == None or input_placeholder == None:
        raise ValueError("input_file and input_placeholder could not be None")

    if not isinstance(input_placeholder, str) or \
       not isinstance(input_file, str) :
        raise ValueError("input_file and input_placeholder must be of str type")
    
    return [input_file if e == input_placeholder else e for e in target_opts]
