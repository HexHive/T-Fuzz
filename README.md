# T-Fuzz

T-Fuzz consists of 2 components:
- Fuzzing tool (TFuzz): a fuzzing tool based on program transformation
- Crash Analyzer (CrashAnalyzer): a tool that verifies whether crashes found transformed
  programs are true bugs in the original program or not (coming soon).


# OS support

The current version is tested only on Ubuntu-16.04, while trying to run the code,
please use our tested OS.

# Prerequisite

T-Fuzz system is built on several opensource tools.
- [angr](https://github.com/angr/angr)
- [shellphish fuzzer](https://github.com/shellphish/fuzzer)
- [angr tracer](https://github.com/angr/tracer)
- [radare2](https://github.com/radare/radare2) and its python
  wrapper [r2pipe](https://github.com/radare/radare2-r2pipe)

## Installing radare2

```
$ git clone https://github.com/radare/radare2.git
$ cd radare2
$ ./sys/install.sh
```

## Installing python libraries

### installing some dependent libraries

> Note: to use `apt-get build-dep`, you need to uncomment the deb-src lines in your apt source
> file (/etc/apt/sources.list) and run apt-get update.

```
$ sudo apt-get install build-essential gcc-multilib libtool automake autoconf bison debootstrap debian-archive-keyring
$ sudo apt-get build-dep qemu-system
$ sudo apt-get install libacl1-dev
```


### installing pip and setting up virtualenv &  wrapper

```
$ sudo apt-get install python-pip python-virtualenv
$ pip install virtualenvwrapper
```

Add the following lines to your shell rc file (`~/.bashrc` or `~/.zshrc`).

```
export WORKON_HOME=$HOME/.virtual_envs
source /usr/local/bin/virtualenvwrapper.sh
```

### Creating a python virtual environment

```
$ mkvirtualenv tfuzz-env
```

### Installing dependent libraries

This command will install all the dependent python libraries for you.

```
$ workon tfuzz-env
$ pip install -r req.txt
```

# Fuzzing target programs with T-Fuzz

```
$ ./TFuzz  --program  <path_to_target_program> --work_dir <work_dir> --target_opts <target_opts>
```

Where
- <path_to_target_program>: the path to the target program to fuzz
- <work_dir>: the directory to save the results
- <target_opts>: the options to pass to the target program, like AFL, use `@@` as
  		 placeholder for files to mutate.


## Examples

1. Fuzzing base64 with T-Fuzz

```
$ ./TFuzz  --program  target_programs/base64  --work_dir workdir_base64 --target_opts "-d @@"
```

2. Fuzzing uniq with T-Fuzz

```
$ ./TFuzz  --program  target_programs/uniq  --work_dir workdir_uniq --target_opts "@@"
```

3. Fuzzing md5sum with T-Fuzz

```
$ ./TFuzz  --program  target_programs/md5sum  --work_dir workdir_md5sum --target_opts "-c @@"
```

4. Fuzzing who with T-Fuzz

```
$ ./TFuzz  --program  target_programs/who  --work_dir workdir_who --target_opts "@@"
```

# Using CrashAnalyzer to verify crashes

T-Fuzz CrashAnalyzer has been put in a docker image, however,
it is still not working in all binaries we tested, we are still investigating
it the cause.

Here is how:

Run the following command to run our docker image

```
$ [sudo] docker pull tfuzz/tfuzz-test
$ [sudo] docker run  --security-opt seccomp:unconfined -it tfuzz/tfuzz-test  /usr/bin/zsh 
```

In the container:

There are 3 directories:
- `release`: contains code the built lava binaries
- `results`: contains some results we found in lava-m dataset 
- `radare2`: it is a program used by T-Fuzz.


Currently, `T-Fuzz` may not work, because the tracer crashes accidentally.
And the CrashAnalyzer can not work on all results.
But some cases can be recovered.

For example:


To verify bugs in base64, first goto `release` and checkout ca_base64:

```
$ cd release
$ git checkout ca_base64
```

Then we use a transformed program to recover the crash in the original program:

1. Choose a transformed program and run it on the input found by a fuzzer:

```
$ cd ~
$./results/ca_base64/554/base64_tfuzz_28/base64_tfuzz_28 -d ./results/ca_base64/554/crashing_inputs_from/results_saved_0_from 
[1]    131 segmentation fault (core dumped)  ./results/ca_base64/554/base64_tfuzz_28/base64_tfuzz_28 -d
```


2. Recover an input from this transformed program and crashing input

```
$ ./release/CrashAnalyzer  --tprogram ./results/ca_base64/554/base64_tfuzz_28/base64_tfuzz_28 --target_opts "-d @@" --crash_input ./results/ca_base64/554/crashing_inputs_from/results_saved_0_from --result_dir base64_result --save_to recover
WARNING | 2018-12-04 04:28:22,350 | angr.analyses.disassembly_utils | Your verison of capstone does not support MIPS instruction groups.
Trying /root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from
WARNING | 2018-12-04 04:28:23,228 | angr.project | Address is already hooked, during hook(0x9021cd0, <SimProcedure ReturnUnconstrained>). Re-hooking.
WARNING | 2018-12-04 04:28:23,228 | angr.project | Address is already hooked, during hook(0x90dd000, <SimProcedure ReturnUnconstrained>). Re-hooking.
WARNING | 2018-12-04 04:28:23,229 | angr.simos.linux | Tracer has been heavily tested only for CGC. If you find it buggy for Linux binaries, we are sorry!
Adding <Bool Or(((file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_0_0_8 >= 65) && (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_0_0_8 <= 90)), ((file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_0_0_8 >= 97) && (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_0_0_8 <= 122)), ((file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_0_0_8 >= 48) && (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_0_0_8 <= 57)), (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_0_0_8 == 43), (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_0_0_8 == 47))>
Adding <Bool Or(((file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_1_1_8 >= 65) && (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_1_1_8 <= 90)), ((file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_1_1_8 >= 97) && (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_1_1_8 <= 122)), ((file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_1_1_8 >= 48) && (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_1_1_8 <= 57)), (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_1_1_8 == 43), (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_1_1_8 == 47))>
Adding <Bool Or(((file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_2_2_8 >= 65) && (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_2_2_8 <= 90)), ((file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_2_2_8 >= 97) && (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_2_2_8 <= 122)), ((file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_2_2_8 >= 48) && (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_2_2_8 <= 57)), (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_2_2_8 == 43), (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_2_2_8 == 47))>
Adding <Bool Or(((file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_3_3_8 >= 65) && (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_3_3_8 <= 90)), ((file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_3_3_8 >= 97) && (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_3_3_8 <= 122)), ((file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_3_3_8 >= 48) && (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_3_3_8 <= 57)), (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_3_3_8 == 43), (file_/root/results/ca_base64/554/crashing_inputs_from/results_saved_0_from_9_3_3_8 == 47))>
results saved to /root/base64_result/recover_0
```

Then `/root/base64_result/recover_0` is generated, we can use it to trigger a crash in the original program.

3. verify the input by running the generated  input on the original program

```
$ ./results/base64 -d base64_result/recover_0 
Successfully triggered bug 554, crashing now!
Successfully triggered bug 554, crashing now!
Successfully triggered bug 554, crashing now!
[1]    177 segmentation fault (core dumped)  ./results/base64 -d base64_result/recover_0
```