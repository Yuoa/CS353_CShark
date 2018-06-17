# CShark
This is project of assignment 6 of POSTECH CSED353 network class on 2018 spring semester.

## About building project

### Requirements
- libpcap
- CMake 2.5 or higher
- Make
- g++ with C(++) Standard 11

### How to build
If you are first downloaded this project and now trying to build, type as below.
```bash
$ cmake .
$ make
```
Else if you are not first to build the repository, just type `make`.
```bash
$ make
```
If you moved base directory, remove caches and retry.
```bash
$ rm -rf CMakeFiles
$ rm -rf CMakeCache.txt
$ cmake .
$ make
```

## About executing the program
```shell
$ ./CShark
```

## License
MIT License.
