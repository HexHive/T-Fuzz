# T-Fuzz

T-Fuzz consists of 2 components:
- Fuzzing tool (TFuzz): a fuzzing tool based on program transformation
- Crash Analyzer (CrashAnalyzer): a tool that verifies whether crashes found transformed
  programs are true bugs in the original program or not (coming soon).

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

### Creating a virtual environment

```
$ mkvirtualenv tfuzz-env
```

### Installing dependent libraries

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

Coming soon!
