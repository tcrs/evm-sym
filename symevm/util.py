from ethereum import opcodes, utils

def oplen(op):
    if op >= 0x60 and op <= 0x7F:
        # PUSHn instructions are 1 + n long
        return 2 + op - 0x60
    else:
        return 1

def disassemble(code, start_pc, max_pc, pc_hex=False):
    assert start_pc <= max_pc
    pc = start_pc
    while pc <= max_pc:
        op = code[pc]
        try:
            name, *_ = opcodes.opcodes[op]
        except KeyError:
            name = 'INVALID(' + hex(op) + ')'
        if name.startswith('PUSH'):
            npush = op - 0x60 + 1
            # TODO supposed to get zeros if some bytes >= len(inp)
            yield hex(utils.big_endian_to_int(code[pc+1:pc+npush+1]))
        else:
            if pc_hex:
                yield hex(pc) + ':' + name
            else:
                yield str(pc) + ':' + name
        pc += oplen(op)
