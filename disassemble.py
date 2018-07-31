import sys
from symevm import util

code = util.hex_to_bytes(sys.stdin.read().rstrip())
for line in util.disassemble(code, 0, len(code) - 1, pc_hex=True):
    print(line)


