
import os
import pkg_resources
import resource
import subprocess
import tempfile

from .emulator import AMD64Emulator, EmulationException

SUPPORTED_ARCHITECTURES = {
    "amd64": {
        "as": ["/bin/as", "--64", "--fatal-warnings"],
        "ld": [
            "/bin/ld",
            "--fatal-warnings", # fail if entry point doesn't exist
            "-static",
            "--no-dynamic-linker",
            "-z", "defs",
            "-z", "noexecstack",
        ],
        "emulator": AMD64Emulator,
    }
}

class TestFailureException(Exception):
    def __init__(self, msg, data=None):
        super().__init__(msg)
        self.data = data

class TestCase(object):
    def __init__(self, emulator, insn_count=None):
        self._emulator = emulator
        self._fault = None
        self._fail = None
        self._insn_count_max = insn_count
        if insn_count is None:
            self._emulator.disable_insn_count()
        else:
            self._emulator.enable_insn_count()
        self._memranges = []
        self._result = None
        self._abi_violations = None
        self._insn_count = -1
    # def alloc_mem(self, size):
    # def write_mem(self, addr, data):
    def call(self, *args):
        try:
            result, abi_violations, insn_count = self._emulator.run(*args)
            self._result = result
            self._abi_violations = abi_violations
            self._insn_count = insn_count
        except EmulationException as e:
            self._fault = str(e)
        return self
    # def mem_eq(self, addr, size, value):
    def result_s64_eq(self, val):
        if self._fault or self._fail: return
        if self._result != val&0xffffffffffffffff:
            self._fail = "wrong result, expected %#x != %#x"%(val, self._result)

    def __repr__(self):
        return "TestCase<fault:%r,fail:%r,insns:%d/%d,abi:%r>" % (
            self._fault, self._fail, self._insn_count, self._insn_count_max,
            self._abi_violations,
        )

class Tester(object):
    # These are just default values which can be overridden by the real tester.
    FILE_SOURCE = "user.s"
    FILE_BINARY = "user.bin"
    MAX_FILE_SIZE = 0x100000 # 1 MiB
    MAX_TEXT_SIZE = 0x10000 # 64 kiB
    MAX_STACK_SIZE = 0x1000 # 4 kiB
    AS_FLAGS = []
    LD_FLAGS = []
    LIBCALLS = []

    def __init__(self, code, arch):
        if arch not in SUPPORTED_ARCHITECTURES:
            raise Exception("unsupported arch %r"%arch)
        self._arch_data = SUPPORTED_ARCHITECTURES[arch]

        self._set_rlimits()

        # TODO: Process allowed library calls. For now, allow none.
        self._tmpdir = tempfile.TemporaryDirectory()
        with open(os.path.join(self.basedir, self.FILE_SOURCE), "w") as f:
            f.write(code)
        self._compile(arch, self.FILE_BINARY, self.FILE_SOURCE)

        try:
            self._emulator = self._arch_data["emulator"](
                binary=os.path.join(self.basedir, self.FILE_BINARY),
                signature=self.SIGNATURE,
                max_code_size=self.MAX_TEXT_SIZE,
                stack_size=self.MAX_STACK_SIZE,
            )
        except InvalidBinaryException as e:
            raise TestFailureException("invalid binary: %s"%e)

        self._cases = []

    def case(self, **kwargs):
        case = TestCase(self._emulator, **kwargs)
        self._cases.append(case)
        return case

    def _set_rlimits(self):
        try:
            fsize_cur = resource.getrlimit(resource.RLIMIT_FSIZE)
            if fsize_cur[0] == resource.RLIM_INFINITY:
                fsize_new = self.MAX_FILE_SIZE
            else:
                fsize_new = min(fsize_cur[0], self.MAX_FILE_SIZE)
            print("[.] Setting rlimit FSIZE from", fsize_cur, "to", fsize_new)
            resource.setrlimit(resource.RLIMIT_FSIZE, (fsize_new, fsize_new))

            core_new = 0
            print("[.] Setting rlimit CORE to", core_new)
            resource.setrlimit(resource.RLIMIT_CORE, (core_new, core_new))
        except resource.error as e:
            print("[-] Unable to set rlimits", e)
            raise e

    def _compile(self, arch, dest, *sources):
        print("[.] Compiling", *sources, "for", arch)
        if not sources:
            raise Exception("compilation requires at least one source")
        objfile = dest + ".o"
        self._compiler_run_sandbox(
            self._arch_data["as"] + self.AS_FLAGS,
            objfile, sources,
        )
        self._compiler_run_sandbox(
            self._arch_data["ld"] + self.LD_FLAGS + ["-e", self.ENTRY_FUNCTION],
            dest, [objfile],
        )
        print("[+] Successfully compiled to", dest)

    def _compiler_run_sandbox(self, binary, dest, sources):
        sandboxdir = pkg_resources.resource_filename("raspcorn", "compiler-sandbox")
        bwrap_args = [
            "/usr/bin/bwrap",
            "--unshare-all",
            "--new-session",
            "--die-with-parent",
            "--cap-drop", "ALL",
            "--tmpfs", "/tmp",
            "--ro-bind", os.path.join(sandboxdir, "lib64"), "/lib64",
            "--ro-bind", os.path.join(sandboxdir, "bin"), "/bin",
            "--bind", self.basedir, "/data",
            "--chdir", "/data",
        ]
        compiler_args = binary + ["-o", dest] + list(sources)
        try:
            subprocess.run(
                bwrap_args + compiler_args,
                capture_output=True,
                check=True,
                universal_newlines=True,
            )
        except subprocess.CalledProcessError as e:
            print("[-] Compilation failed (%d) on"%e.returncode, compiler_args)
            print("[.] Output:", repr(e.stderr))
            raise TestFailureException(
                "Compilation failed with code %d" % e.returncode,
                "Command: %s\n%s"%(" ".join(compiler_args), e.stderr)
            )

    @property
    def basedir(self):
        return self._tmpdir.name

    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc_value, exc_tb):
        self._tmpdir.cleanup()
