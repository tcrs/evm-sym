import sys
from symevm import util
from ethereum import utils

code = utils.parse_as_bin(sys.stdin.read().rstrip())
for line in util.disassemble(code, 0, len(code) - 1, pc_hex=True):
    print(line)


