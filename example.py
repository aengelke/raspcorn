
from raspcorn.base import Tester, TestFailureException


sample_program = """
.global increment
.intel_syntax noprefix
increment:
    lea rax, [rdi+1]
    ret
"""

class SampleTester(Tester):
    ENTRY_FUNCTION = "increment"
    SIGNATURE = ("i64", "i64")

    def test(self):
        self.case(insn_count=2).call(4).result_s64_eq(5)
        self.case(insn_count=2).call(0).result_s64_eq(1)
        self.case(insn_count=2).call(-1).result_s64_eq(0)
        self.case(insn_count=2).call(-2).result_s64_eq(-1)
        self.case(insn_count=2).call(0x12345678abcdef90).result_s64_eq(0x12345678abcdef91)
        self.case(insn_count=2).call(0x7fffffffffffffff).result_s64_eq(0x8000000000000000)

if __name__ == "__main__":
    try:
        with SampleTester(sample_program, "amd64") as tester:
            print(tester.test())
            print(tester._cases)
    except TestFailureException as e:
        print("Test failed:", e)
        print(e.data)
    else:
        print("ok")

    # Lib calls clobber all scratch regs
    # TBD: how to emulate malloc failures?
    # TBD: detection of compiler-generated code and plagiarism

    pass

