
import os
import random
import struct

from elftools.elf.elffile import ELFFile
from elftools.elf.constants import P_FLAGS
from unicorn import Uc, UcError
from unicorn.unicorn_const import *
from unicorn.x86_const import *
from unicorn.arm64_const import *

class InvalidBinaryException(Exception):
    pass

class EmulationException(Exception):
    pass

class Emulator(object):
    EXIT_ADDR = 0xfffffffffffef000

    def __init__(self, binary, signature, max_code_size=65536,
            stack_size=0x1000):
        self._state_insn_count = 0
        self._state_first_fault = None

        self._insn_count_hook = None
        self._max_code_size = max_code_size
        self._signature = signature
        self._process_elf_binary(binary)

        # Verify that the entry address is indeed sane and mapped.
        elf_end = self._elf_vaddr + len(self._elf_data)
        print("[.] ELF range %#x-%#x"%(self._elf_vaddr, elf_end))
        if not self._elf_vaddr <= self._elf_entry < elf_end:
            raise InvalidBinaryException("entry outside binary")

        self._uc = self._create_uc()

        self._uc.hook_add(UC_HOOK_MEM_INVALID, self._hook_segfault)

        elf_map_start = self._elf_vaddr & ~0xfff
        elf_map_end = (elf_end + 0xfff) & ~0xfff

        print("[.] Uc mapping ELF from %#x-%#x"%(elf_map_start, elf_map_end))
        self._uc.mem_map(
            elf_map_start, elf_map_end - elf_map_start,
            UC_PROT_READ | UC_PROT_EXEC
        )
        self._uc.mem_write(self._elf_vaddr, self._elf_data)

        self._stack = 0x7fffff00000 # TODO: Randomize!!
        self._stack_size = (stack_size + 0xfff) & ~0xfff
        print("[.] Uc mapping stack from %#x+%#x"%(self._stack, stack_size))
        self._uc.mem_map(
            self._stack, self._stack_size, UC_PROT_READ | UC_PROT_WRITE
        )

        self._uc.mem_map(self.EXIT_ADDR, 0x1000, UC_PROT_READ | UC_PROT_EXEC)

        self._base_context = self._uc.context_save()

    def enable_insn_count(self):
        if self._insn_count_hook is not None: return
        self._insn_count_hook = self._uc.hook_add(UC_HOOK_CODE, self._hook_code)
    def disable_insn_count(self):
        if self._insn_count_hook is None: return
        self._uc.hook_del(self._insn_count_hook)
        self._insn_count_hook = None
    def _hook_code(self, _, address, size, data):
        self._state_insn_count += 1

    def _hook_segfault(self, _, access, address, size, value, data):
        if self._state_first_fault:
            # Should never happen...
            print("[!] Double-fault!")
            return False

        if access in (UC_MEM_FETCH_UNMAPPED, UC_MEM_FETCH_PROT):
            self._state_first_fault = "instruction fetch from invalid or " \
                "non-executable address %#x" % address
        elif access in (UC_MEM_READ_UNMAPPED, UC_MEM_WRITE_UNMAPPED):
            self._state_first_fault = "read/write from unmapped address"
        else:
            self._state_first_fault = "read/write from address " \
                "non-readable/writable address %#x" % address
        print("[-] Invalid memory access", (access, address, size, value, data))
        return False

    def _process_elf_binary(self, binary):
        self._elf_vaddr = None
        self._elf_data = None
        self._elf_entry = None

        with open(binary, "rb") as f:
            elffile = ELFFile(f)

            print("[.] ELF entry is at", hex(elffile["e_entry"]))
            self._elf_entry = elffile["e_entry"]

            print("[.] ELF type is", elffile["e_type"])
            if elffile["e_type"] != "ET_EXEC":
                raise InvalidBinaryException("ELF type %r"%elffile["e_type"])

            print("[.] ELF has machine", elffile["e_machine"])
            if not self._check_elf_machine(elffile):
                raise InvalidBinaryException("wrong architecture")

            for segment in elffile.iter_segments():
                self._process_segment(segment)

        if not self._elf_data:
            raise InvalidBinaryException("binary is empty")

    def _process_segment(self, segment):
        print("[.] ELF segment: %s V=%#x FSZ=%#x MSZ=%#x flags=%d"%(
            segment["p_type"], segment["p_vaddr"], segment["p_filesz"],
            segment["p_memsz"], segment["p_flags"]
        ))
        if segment["p_type"] == "PT_LOAD":
            if segment["p_flags"] & P_FLAGS.PF_W:
                raise InvalidBinaryException("writable segment")
            if self._elf_data:
                raise InvalidBinaryException("too many load segments")
            if not segment["p_flags"] & P_FLAGS.PF_X:
                raise InvalidBinaryException("no executable segment")
            if segment["p_filesz"] != segment["p_memsz"]:
                raise InvalidBinaryException("zero-filled segment")
            if segment["p_filesz"] > self._max_code_size:
                raise InvalidBinaryException("code size %d > %d (maximum)"%(
                    segment["p_filesz"], self._max_code_size)
                )

            # Try to read segment data
            segment_data = segment.data()
            print("[.] Read %d bytes of code/data"%len(segment_data))
            if len(segment_data) != segment["p_filesz"]:
                raise InvalidBinaryException("corrupt binary")

            self._elf_data = segment_data
            self._elf_vaddr = segment["p_vaddr"]
        elif segment["p_type"] == "PT_NULL":
            pass
        elif segment["p_type"] == "PT_GNU_STACK":
            pass
        else:
            raise InvalidBinaryException("invalid segment %r"%segment["p_type"])

    def _check_elf_machine(self, elffile):
        return False

class AMD64Emulator(Emulator):
    REGS_GP = (
        UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RBX, UC_X86_REG_RDX,
        UC_X86_REG_RSP, UC_X86_REG_RBP, UC_X86_REG_RSI, UC_X86_REG_RDI,
        UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
        UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
    )
    REGS_GP_ARG = (
        UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX,
        UC_X86_REG_R8, UC_X86_REG_R9,
    )
    REGS_GP_CALL_SAVE = (
        UC_X86_REG_RBX, UC_X86_REG_RSP, UC_X86_REG_RBP,
        UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
    )

    @staticmethod
    def _name_reg(reg):
        return {
            UC_X86_REG_RAX: "rax", UC_X86_REG_RCX: "rcx", UC_X86_REG_RBX: "rbx",
            UC_X86_REG_RDX: "rdx", UC_X86_REG_RSP: "rsp", UC_X86_REG_RBP: "rbp",
            UC_X86_REG_RSI: "rsi", UC_X86_REG_RDI: "rdi", UC_X86_REG_R8: "r8",
            UC_X86_REG_R9: "r9", UC_X86_REG_R10: "r10", UC_X86_REG_R11: "r11",
            UC_X86_REG_R12: "r12", UC_X86_REG_R13: "r13", UC_X86_REG_R14: "r14",
            UC_X86_REG_R15: "r15",
        }[reg]

    def _create_uc(self):
        return Uc(UC_ARCH_X86, UC_MODE_64)

    def _check_elf_machine(self, elffile):
        return elffile["e_machine"] == "EM_X86_64"

    def run(self, *args):
        # Restore known plain context to prevent information to be leaked across
        # subsequent runs. This only restores registers, but not memory.
        self._uc.context_restore(self._base_context)

        gp_reg_vals = {reg: random.randint(0, 2**64-1) for reg in self.REGS_GP}
        for reg, value in gp_reg_vals.items():
            self._uc.reg_write(reg, value)
        for reg in range(UC_X86_REG_XMM0, UC_X86_REG_XMM0+16):
            self._uc.reg_write(reg, random.randint(0, 2**128-1))

        # TODO: Properly handle signature!
        if len(args) > len(self.REGS_GP_ARG): assert False
        for reg, arg in zip(self.REGS_GP_ARG, args):
            self._uc.reg_write(reg, arg)

        stack = struct.pack("<Q", self.EXIT_ADDR)
        stack_ptr = self._stack + self._stack_size - len(stack)
        self._uc.reg_write(UC_X86_REG_RSP, stack_ptr)
        gp_reg_vals[UC_X86_REG_RSP] = stack_ptr + 8

        # Initialize stack with random garbage.
        stack = os.urandom(self._stack_size - len(stack)) + stack
        self._uc.mem_write(self._stack, stack)

        try:
            self._state_insn_count = 0
            self._state_first_fault = None
            self._uc.emu_start(self._elf_entry, self.EXIT_ADDR)

            pc = self._uc.reg_read(UC_X86_REG_RIP)
            if pc != self.EXIT_ADDR:
                print("[!] Program didn't terminate at exit addr", hex(pc))
                self._state_first_fault = "abnormal program exit"
        except UcError as e:
            pc = self._uc.reg_read(UC_X86_REG_RIP)
            print("[-] Emulation error:", e, "at", hex(pc))
            if not self._state_first_fault:
                if e.errno == UC_ERR_INSN_INVALID:
                    self._state_first_fault = "invalid instruction at %#x"%pc
                elif e.errno == UC_ERR_EXCEPTION:
                    # We have no hook for CPU exceptions installed.
                    self._state_first_fault = "CPU exception at %#x"%pc
                elif e.errno in (UC_ERR_READ_UNMAPPED, UC_ERR_WRITE_UNMAPPED,
                        UC_ERR_FETCH_UNMAPPED, UC_ERR_WRITE_PROT,
                        UC_ERR_READ_PROT, UC_ERR_FETCH_PROT):
                    # Should never happen, but who knows.
                    print("[!] Memory access error without fault!")
                    self._state_first_fault = "memory access error"
                else:
                    self._state_first_fault = "internal error"

        if self._state_first_fault:
            print("[.] Reported fault:", self._state_first_fault)
            raise EmulationException(self._state_first_fault)

        result = self._uc.reg_read(UC_X86_REG_RAX)

        # Check ABI/callee-save registers
        abi_violations = []
        for reg in self.REGS_GP_CALL_SAVE:
            value = self._uc.reg_read(reg)
            if value != gp_reg_vals[reg]:
                print("[-] Program clobbered reg %s (was %#x, is %#x)" % (
                    self._name_reg(reg), gp_reg_vals[reg], value
                ))
                abi_violations.append("clobbered %s"%self._name_reg(reg))

        print("[.] Insn count:", self._state_insn_count)

        return result, abi_violations, self._state_insn_count
