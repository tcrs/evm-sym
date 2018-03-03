from . import vm_isa

def hex_to_bytes(text):
    if text.startswith('0x'):
        text = text[2:]
    return bytes.fromhex(text)

def oplen(op):
    if op >= 0x60 and op <= 0x7F:
        # PUSHn instructions are 1 + n long
        return 2 + op - 0x60
    else:
        return 1

def pushval(code, off):
    op = code[off]
    if op >= 0x60 and op <= 0x7f:
        npush = op - 0x60 + 1
        bv = code[off + 1:off + npush + 1]
        if len(bv) != npush:
            bv += b'\0' * (npush - len(bv))
        return int.from_bytes(bv, byteorder='big')

def disassemble(code, start_pc, max_pc, pc_hex=False, show_pc=True):
    for pc, instr in disassemble_core(code, start_pc, max_pc):
        pc_str = ''
        if show_pc:
            if pc_hex:
                pc_str = hex(pc) + ': '
            else:
                pc_str = str(pc) + ': '
        yield pc_str + instr

def disassemble_core(code, start_pc, max_pc):
    assert start_pc <= max_pc
    pc = start_pc
    while pc <= max_pc:
        op = code[pc]
        try:
            instr = vm_isa.opcodes[op]
            name = instr.name
        except KeyError:
            name = 'INVALID(' + hex(op) + ')'
        if name.startswith('PUSH'):
            npush = op - 0x60 + 1
            # TODO supposed to get zeros if some bytes >= len(inp)
            yield pc, name + ' ' + hex(int.from_bytes(code[pc+1:pc+npush+1], byteorder='big'))
        else:
            yield pc, name
        pc += oplen(op)
