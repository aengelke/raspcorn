# raspcorn: Assembler testing sandbox

- Run user-specified assembly programs in a unicorn emulator and verify result, calling convention, and instruction count
- Future work: emulate custom syscall ABI (e.g. for malloc, free, etc.), easy support for memory in test cases, complete handling of calling convention
- Dependencies: unicorn, pyelftools, bubblewrap

