import z3
import collections

Instr = collections.namedtuple('Instr', 'name pop push base_gas extra_gas')
Instr.__new__.__defaults__ = (None,)

# Derived from pyethereum's opcode.py
def get_opcodes(metropolis=True):
    Gexpbyte = 50
    Gcopy = 3
    Glogdata = 8
    Gsha3word = 6
    Gsset = 20000
    Gsreset = 5000

    def words_ceil(n):
        # ceil(n / 32)
        return (n + 31) >> 5

    def copy_gas(sz):
        return words_ceil(sz) * Gcopy

    def log_gas(state, _, sz, *topics):
        return sz * Glogdata

    def sstore_gas(state, addr, word):
        cur_val = z3.Select(state.storage, addr)
        return z3.If(z3.And(cur_val == 0, word != 0), z3.BitVecVal(Gsset, 256), z3.BitVecVal(Gsreset, 256))

    ops = {
        0x00: Instr('STOP', 0, 0, 0),
        0x01: Instr('ADD', 2, 1, 3),
        0x02: Instr('MUL', 2, 1, 5),
        0x03: Instr('SUB', 2, 1, 3),
        0x04: Instr('DIV', 2, 1, 5),
        0x05: Instr('SDIV', 2, 1, 5),
        0x06: Instr('MOD', 2, 1, 5),
        0x07: Instr('SMOD', 2, 1, 5),
        0x08: Instr('ADDMOD', 3, 1, 8),
        0x09: Instr('MULMOD', 3, 1, 8),
        # Note: currently only actually support concrete arguments to EXP
        0x0a: Instr('EXP', 2, 1, 10, lambda state, b, e: \
            z3.If(e == 0, z3.BitVecVal(0, 256), z3.BitVecVal(Gexpbyte * ((e.as_long().bit_length() // 8) + 1), 256))),
        0x0b: Instr('SIGNEXTEND', 2, 1, 5),
        0x10: Instr('LT', 2, 1, 3),
        0x11: Instr('GT', 2, 1, 3),
        0x12: Instr('SLT', 2, 1, 3),
        0x13: Instr('SGT', 2, 1, 3),
        0x14: Instr('EQ', 2, 1, 3),
        0x15: Instr('ISZERO', 1, 1, 3),
        0x16: Instr('AND', 2, 1, 3),
        0x17: Instr('OR', 2, 1, 3),
        0x18: Instr('XOR', 2, 1, 3),
        0x19: Instr('NOT', 1, 1, 3),
        0x1a: Instr('BYTE', 2, 1, 3),
        0x20: Instr('SHA3', 2, 1, 30, lambda state, _, sz: words_ceil(sz) * Gsha3word),
        0x30: Instr('ADDRESS', 0, 1, 2),
        0x31: Instr('BALANCE', 1, 1, 400 if metropolis else 20),
        0x32: Instr('ORIGIN', 0, 1, 2),
        0x33: Instr('CALLER', 0, 1, 2),
        0x34: Instr('CALLVALUE', 0, 1, 2),
        0x35: Instr('CALLDATALOAD', 1, 1, 3),
        0x36: Instr('CALLDATASIZE', 0, 1, 2),
        0x37: Instr('CALLDATACOPY', 3, 0, 3, lambda state, x, y, sz: copy_gas(sz)),
        0x38: Instr('CODESIZE', 0, 1, 2),
        0x39: Instr('CODECOPY', 3, 0, 3, lambda state, x, y, sz: copy_gas(sz)),
        0x3a: Instr('GASPRICE', 0, 1, 2),
        0x3b: Instr('EXTCODESIZE', 1, 1, 700 if metropolis else 20),
        0x3c: Instr('EXTCODECOPY', 4, 0, 700 if metropolis else 20, lambda state, x, y, z, sz: copy_gas(sz)),
        0x3d: Instr('RETURNDATASIZE', 0, 1, 2),
        0x3e: Instr('RETURNDATACOPY', 3, 0, 3),
        0x40: Instr('BLOCKHASH', 1, 1, 20),
        0x41: Instr('COINBASE', 0, 1, 2),
        0x42: Instr('TIMESTAMP', 0, 1, 2),
        0x43: Instr('NUMBER', 0, 1, 2),
        0x44: Instr('DIFFICULTY', 0, 1, 2),
        0x45: Instr('GASLIMIT', 0, 1, 2),
        0x50: Instr('POP', 1, 0, 2),
        0x51: Instr('MLOAD', 1, 1, 3),
        0x52: Instr('MSTORE', 2, 0, 3),
        0x53: Instr('MSTORE8', 2, 0, 3),
        0x54: Instr('SLOAD', 1, 1, 200 if metropolis else 50),
        0x55: Instr('SSTORE', 2, 0, 0, sstore_gas),
        0x56: Instr('JUMP', 1, 0, 8),
        0x57: Instr('JUMPI', 2, 0, 10),
        0x58: Instr('PC', 0, 1, 2),
        0x59: Instr('MSIZE', 0, 1, 2),
        0x5a: Instr('GAS', 0, 1, 2),
        0x5b: Instr('JUMPDEST', 0, 0, 1),
        0xa0: Instr('LOG0', 2, 0, 375, log_gas),
        0xa1: Instr('LOG1', 3, 0, 750, log_gas),
        0xa2: Instr('LOG2', 4, 0, 1125, log_gas),
        0xa3: Instr('LOG3', 5, 0, 1500, log_gas),
        0xa4: Instr('LOG4', 6, 0, 1875, log_gas),
        0xf0: Instr('CREATE', 3, 1, 32000),
        # TODO call gas calculation. Seems quite complicated?
        0xf1: Instr('CALL', 7, 1, 700 if metropolis else 40),
        0xf2: Instr('CALLCODE', 7, 1, 700 if metropolis else 40),
        0xf3: Instr('RETURN', 2, 0, 0),
        0xf4: Instr('DELEGATECALL', 6, 1, 700 if metropolis else 40),
        0xfa: Instr('STATICCALL', 6, 1, 40),
        0xfd: Instr('REVERT', 2, 0, 0),
        # TODO should cost more if sending to an account which must be created
        0xff: Instr('SELFDESTRUCT', 1, 0, 5000 if metropolis else 0),
    }
    ops.update({0x5f + i: Instr('PUSH' + str(i), 0, 1, 3)
        for i in range(1,33)})
    ops.update({0x7f + i: Instr('DUP' + str(i), i, i + 1, 3)
        for i in range(1, 17)})
    ops.update({0x8f + i: Instr('SWAP' + str(i), i + 1, i + 1, 3)
        for i in range(1, 17)})

    return ops

opcodes = get_opcodes(True)
