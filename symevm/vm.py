import z3
import copy
import collections
from . import util, mem, vm_isa

MemorySort = z3.ArraySort(z3.BitVecSort(256), z3.BitVecSort(8))
StorageSort = z3.ArraySort(z3.BitVecSort(256), z3.BitVecSort(256))

MemoryEmpty = z3.K(z3.BitVecSort(256), z3.BitVecVal(0, 8))
StorageEmpty = z3.K(z3.BitVecSort(256), z3.BitVecVal(0, 256))

sha3 = z3.Function('sha3', MemorySort, z3.BitVecSort(256))

MemRange = collections.namedtuple('MemRange', 'mem offset size')

ReturnInfo = collections.namedtuple('ReturnInfo', 'call_node new_pc retdata_start retdata_sz retresult')
CallInfo = collections.namedtuple('CallInfo', 'calldata gas value')

class CFGNode:
    def __init__(self, global_state, transaction, parent=None, predicates=[], pc=0):
        self.start_pc = pc
        self.pc = pc
        self.transaction = transaction
        self.jumpdests = set()
        # TODO Avoid copying this around every time - only copy on write
        self.global_state = copy.copy(global_state)
        if parent is None:
            self.code = None
            self.stack = []
            self.callstack = []
            self.memory = mem.Memory()
            self.storage = None
            self.balance = None
            self.gas = None
            self.callinfo = None
            self.addr = None
        else:
            # These members will represent the state at the end of the current
            # block.
            self.code = parent.code
            self.stack = copy.copy(parent.stack)
            self.callstack = parent.callstack
            self.memory = copy.copy(parent.memory)
            self.storage = parent.storage
            self.balance = parent.balance
            self.gas = parent.gas
            self.callinfo = parent.callinfo
            self.addr = parent.addr
            self.caller = parent.caller
        self.predicates = predicates
        self.parent = parent
        self.successors = []
        # Why the block finished here
        self.end_type = None
        self.end_info = None

    def get_contract_state(self, addr):
        if addr not in self.global_state:
            self.global_state[addr] = self.transaction.initial_contract_state(addr)
        return self.global_state[addr]

    def make_child_branch(self, new_pc, preds):
        n = CFGNode(self.global_state, self.transaction, parent=self, pc=new_pc, predicates = preds)
        self.successors.append(n)
        return n

    def make_child_call(self, addr, code_addr, caller, callinfo, retinfo):
        n = CFGNode(self.global_state, self.transaction);
        # Put current storage for current contract into global state so that it
        # is correctly picked up for re-entrant calls
        n.global_state[self.addr] = n.global_state[self.addr]._replace(storage=self.storage, balance=self.balance - callinfo.value)
        n.parent = self
        code_s = self.get_contract_state(code_addr)
        n.code = code_s.code
        child_s = self.get_contract_state(addr)
        n.storage = child_s.storage
        n.balance = child_s.balance + callinfo.value
        n.callstack = self.callstack + [retinfo]
        n.gas = callinfo.gas
        n.callinfo = callinfo
        n.addr = addr
        n.caller = caller
        self.successors.append(n)
        return n

    def make_child_return(self, retdata_off, retdata_sz):
        self.retdata_off, self.retdata_sz = retdata_off, retdata_sz
        #print(z3.simplify(self.memory))
        if self.callstack:
            retinfo = self.callstack[-1]
            n = CFGNode(self.global_state, self.transaction, parent=retinfo.call_node, pc=retinfo.new_pc)
            n.global_state[self.addr] = n.global_state[self.addr]._replace(storage=self.storage, balance=self.balance)
            n.storage = n.global_state[n.addr].storage
            n.balance = n.global_state[n.addr].balance
            n.parent = self
            n.predicates.append(retinfo.retresult == 1)
            n.memory.overlay(self.memory, retinfo.retdata_start, retdata_off,
                z3.If(retdata_sz < retinfo.retdata_sz, retdata_sz, retinfo.retdata_sz))
            n.retdata = MemRange(self.memory, retinfo.retdata_start, retinfo.retdata_sz)
            self.successors.append(n)
            return n

    def make_child_revert(self, retdata_off, retdata_sz):
        self.retdata_off, self.retdata_sz = retdata_off, retdata_sz
        if self.callstack:
            retinfo = self.callstack[-1]
            # Note: rollback global state to before CALL
            n = CFGNode(retinfo.call_node.global_state, self.transaction, parent=retinfo.call_node, pc=retinfo.new_pc)
            n.storage = n.global_state[n.addr].storage
            n.balance = n.global_state[n.addr].balance
            n.parent = self
            # Note: return 0
            n.predicates.append(retinfo.retresult == 0)
            n.memory.overlay(self.memory, retinfo.retdata_start, retdata_off,
                z3.If(retdata_sz < retinfo.retdata_sz, retdata_sz, retinfo.retdata_sz))
            n.retdata = MemRange(self.memory, retinfo.retdata_start, retinfo.retdata_end)
            self.successors.append(n)
            return n

    def __str__(self):
        return 'CFGNode({}:{}, end_type={})'.format(self.start_pc, self.pc, self.end_type)

def is_concrete(v):
    return z3.is_bv_value(v)

def as_concrete(v):
    return z3.simplify(v).as_long()

def get_byte(v, bi):
    lo = (31 - bi) * 8
    # z3 Extract bounds are inclusive
    return z3.Extract(lo + 7, lo, v)

def _bool_to_01(bv):
    return z3.If(bv, z3.BitVecVal(1, 256), z3.BitVecVal(0, 256))

def run_block(s, solver, log_trace=False):
    def end_trace(reason, *args):
        s.end_type = reason
        s.end_info = args
        pass

    while True:
        op = s.code[s.pc]
        try:
            instr = vm_isa.opcodes[op]
        except KeyError:
            end_trace('invalid')
            return

        if log_trace:
            print('{:04}: {}'.format(s.pc, instr.name))
            print('> ' + ';; '.join(str(z3.simplify(x)) for x in s.stack))
            #print('> {} | {} | {}'.format(stack, mem, store))

        try:
            instr_args = [s.stack.pop() for i in range(instr.pop)]
        except IndexError:
            end_trace('stack underflow')
            return

        def reducestack(fn):
            s.stack.append(fn(*instr_args))

        oplen = 1

        s.gas = s.gas - instr.base_gas
        if instr.extra_gas is not None:
            s.gas = s.gas - instr.extra_gas(s, *instr_args)
        s.gas = z3.simplify(s.gas)

        if op >= 0x80 and op <= 0x8f: # DUPn
            # instr_args[0] = old top of stack
            for v in reversed(instr_args):
                s.stack.append(v)
            s.stack.append(instr_args[-1])
        elif op >= 0x90 and op <= 0x9f: #SWAPn
            # Old top of stack pushed first
            s.stack.append(instr_args[0])
            # Then the middle section (in original order)
            for v in reversed(instr_args[1:-1]):
                s.stack.append(v)
            # Then bottom value on top
            s.stack.append(instr_args[-1])
        elif op >= 0x60 and op <= 0x7f: #PUSHn
            npush = op - 0x60 + 1
            s.stack.append(z3.BitVecVal(util.pushval(s.code, s.pc), 256))
            oplen += npush
        elif instr.name == 'ADD':
            reducestack(lambda x, y: x + y)
        elif instr.name == 'MUL':
            reducestack(lambda x, y: x * y)
        elif instr.name == 'SUB':
            reducestack(lambda x, y: x - y)
        elif instr.name == 'DIV':
            reducestack(lambda x, y: z3.If(y == 0, z3.BitVecVal(0, 256), z3.UDiv(x, y)))
        elif instr.name == 'SDIV':
            reducestack(lambda x, y: z3.If(y == 0,
                z3.BitVecVal(0, 256), z3.If(x == -2**255 and y == -1,
                    z3.BitVecVal(-2**255, 256), x / y)))
        elif instr.name == 'MOD':
            reducestack(lambda x, y: z3.If(y == 0, z3.BitVecVal(0, 256), z3.URem(x, y)))
        elif instr.name == 'SMOD':
            reducestack(lambda x, y: z3.If(y == 0, z3.BitVecVal(0, 256), z3.SRem(x, y)))
        elif instr.name == 'ADDMOD':
            reducestack(lambda x, y, z: z3.If(z == 0, z3.BitVecVal(0, 256),
                z3.Extract(255, 0, z3.URem(z3.ZeroExt(1, x) + z3.ZeroExt(1, y), z3.ZeroExt(1, z)))))
        elif instr.name == 'MULMOD':
            reducestack(lambda x, y, z: z3.If(z == 0, z3.BitVecVal(0, 256),
                z3.Extract(255, 0, z3.URem(z3.ZeroExt(256, x) * z3.ZeroExt(256, y), z3.ZeroExt(256, z)))))
        elif instr.name == 'EXP':
            # TODO z3 currently doesn't seem to provide __pow__ on BitVecs?
            reducestack(lambda x, y: z3.BitVecVal(pow(x.as_long(), y.as_long(), 1 << 256), 256))
        elif instr.name == 'LT':
            reducestack(lambda x, y: _bool_to_01(z3.ULT(x, y)))
        elif instr.name == 'GT':
            reducestack(lambda x, y: _bool_to_01(z3.UGT(x, y)))
        elif instr.name == 'SLT':
            reducestack(lambda x, y: _bool_to_01(x < y))
        elif instr.name == 'SGT':
            reducestack(lambda x, y: _bool_to_01(x > y))
        elif instr.name == 'EQ':
            reducestack(lambda x, y: _bool_to_01(x == y))
        elif instr.name == 'ISZERO':
            reducestack(lambda x: _bool_to_01(x == 0))
        elif instr.name == 'AND':
            reducestack(lambda x, y: x & y)
        elif instr.name == 'OR':
            reducestack(lambda x, y: x | y)
        elif instr.name == 'XOR':
            reducestack(lambda x, y: x ^ y)
        elif instr.name == 'NOT':
            reducestack(lambda x: ~x)
        elif instr.name == 'BYTE':
            idx, val = instr_args
            bidx = as_concrete(idx)
            if bidx <= 31:
                s.stack.append(z3.ZeroExt(248, get_byte(val, bidx)))
            else:
                s.stack.append(z3.BitVecVal(0, 256))
        elif instr.name == 'SIGNEXTEND':
            idx, val = instr_args
            bidx = as_concrete(idx)
            if bidx <= 31:
                nbits = 8 * (bidx + 1)
                to_extend = z3.Extract(nbits - 1, 0, val)
                s.stack.append(z3.SignExt(256 - nbits, to_extend))
            else:
                s.stack.append(val)
        elif instr.name == 'CODESIZE':
            s.stack.append(z3.BitVecVal(s.code.size(), 256))
        elif instr.name == 'SHA3':
            start, sz = instr_args
            v = MemoryEmpty
            n = as_concrete(sz)
            for i in range(n):
                v = z3.Store(v, i, s.memory.select(start + i))
            s.stack.append(sha3(v))
            # TODO when n == 0 or all values are concrete, simplify!
            #start, sz = as_concrete(start), as_concrete(sz)
            #stack.append(ethereum.utils.sha3_256([as_concrete(
        elif instr.name in {'GASPRICE', 'COINBASE', 'TIMESTAMP', 'NUMBER', 'DIFFICULTY', 'GASLIMIT', 'ORIGIN'}:
            reducestack(getattr(s.transaction, instr.name.lower()))
        elif instr.name in {'BALANCE', 'BLOCKHASH', 'EXTCODESIZE'}:
            reducestack(lambda x: (getattr(s.transaction, instr.name.lower())())(x))
        elif instr.name == 'ADDRESS':
            s.stack.append(s.addr)
        elif instr.name == 'CALLVALUE':
            s.stack.append(s.callinfo.value)
        elif instr.name == 'CALLDATASIZE':
            s.stack.append(s.callinfo.calldata.size)
        elif instr.name == 'CALLER':
            s.stack.append(s.caller)
        elif instr.name == 'CODECOPY':
            # TODO handle non-concrete size
            start_mem, start_code, sz = instr_args
            start_code = as_concrete(start_code)
            for i in range(as_concrete(sz)):
                s.memory.store(start_mem + i, s.code[start_code + i])
        elif instr.name == 'CALLDATACOPY':
            src, dest, sz = instr_args
            cd_mem, cd_off, cd_sz = s.callinfo.calldata
            # TODO cache this limited calldata memory object - this is so that
            # out of range calldata reads correctly return 0s
            limited_cdmem = mem.Memory()
            limited_cdmem.overlay(cd_mem, 0, cd_off, cd_sz)
            s.memory.overlay(limited_cdmem, dest, cd_off + src, sz)
        elif instr.name == 'CALLDATALOAD':
            addr, = instr_args
            cd_mem, cd_off, cd_sz, *_ = s.callinfo.calldata
            s.stack.append(z3.simplify(z3.Concat(
                *[z3.If(addr + i < cd_sz, cd_mem.select(cd_off + addr + i), 0) for i in range(32)])))
        elif instr.name == 'RETURNDATASIZE':
            if hasattr(s, retdata):
                s.stack.append(s.retdata.size)
            else:
                s.stack.append(z3.BitVecVal(0, 256))
        elif instr.name == 'RETURNDATACOPY':
            src, dest, sz = instr_args
            # TODO non-concrete length, retdata overflow (should terminate)
            if hasattr(s, retdata):
                for i in range(sz.as_long()):
                    s.memory.store(dest + i, z3.Select(s.retdata.mem, s.retdata.offset + src + i))
        elif instr.name == 'POP':
            pass
        elif instr.name == 'MLOAD':
            addr, = instr_args
            s.stack.append(z3.simplify(z3.Concat(*[s.memory.select(addr + i) for i in range(32)])))
        elif instr.name == 'MSTORE':
            dst, word = instr_args
            for i in range(32):
                s.memory.store(dst + i, get_byte(word, i))
        elif instr.name == 'MSTORE8':
            dst, word = instr_args
            s.memory.store(dst, get_byte(word, 31))
        elif instr.name == 'SLOAD':
            addr, = instr_args
            s.stack.append(z3.simplify(z3.Select(s.storage, addr)))
        elif instr.name == 'SSTORE':
            addr, word = instr_args
            s.storage = z3.Store(s.storage, addr, word)
        elif instr.name == 'PC':
            s.stack.append(z3.BitVecVal(s.pc, 256))
        elif instr.name == 'GAS':
            # TODO actually track gas usage?
            s.stack.append(z3.BitVec('{}:GAS'.format(s.pc), 256))
        elif instr.name in 'STOP':
            end_trace('stop')
            return
        elif instr.name == 'RETURN':
            ret_start, ret_size = instr_args
            s.make_child_return(ret_start, ret_size)
            return
        elif instr.name == 'REVERT':
            ret_start, ret_size = instr_args
            s.make_child_revert(ret_start, ret_size)
            return
        elif instr.name in {'CALL', 'CALLCODE', 'DELEGATECALL'}:
            if instr.name in {'CALL', 'CALLCODE'}:
                gas, addr, value, in_off, in_sz, out_off, out_sz = instr_args
                caller = s.addr
            elif instr.name == 'DELEGATECALL':
                gas, addr, in_off, in_sz, out_off, out_sz = instr_args
                value = s.callinfo.value
                caller = s.caller
            else:
                assert False, instr.name
            addr = z3.simplify(addr)
            if instr.name == 'CALL':
                call_addr = addr
                code_addr = addr
            else:
                call_addr = z3.BitVecVal(s.addr, 256)
                code_addr = addr

            callres = z3.BitVec('{}:{}({})'.format(s.pc, instr.name, z3.simplify(call_addr)), 256)
            s.stack.append(callres)
            if is_concrete(call_addr):
                s.make_child_call(addr = call_addr.as_long(), code_addr=code_addr.as_long(), caller=caller,
                    retinfo=ReturnInfo(s, s.pc + 1, out_off, out_sz, callres),
                    callinfo=CallInfo(MemRange(s.memory, in_off, in_sz), z3.BV2Int(gas), value))
                return
            else:
                end_trace('call', call_addr, value, gas)
                s.make_child_branch(new_pc = s.pc + 1, preds = [s.gas > 0, z3.Or(callres == 1, callres == 0)])
                return
        elif instr.name == 'CREATE':
            value, in_off, in_sz = instr_args
            res = z3.BitVec('{}:CREATE({})'.format(s.pc, value), 256)
            s.stack.append(res)
            end_trace('create', value)
            s.make_child_branch(new_pc = s.pc + 1, preds = [s.gas > 0, z3.Or(res == 0, res == 1)])
            return
        elif instr.name == 'SELFDESTRUCT':
            to_addr = instr_args
            end_trace('suicide', to_addr)
            # No successors
            return
        elif instr.name == 'JUMPI':
            end_trace(None)
            loc, cond = instr_args

            fallthrough_pc = None

            solver.push()
            solver.add(cond == 0)
            fallthrough_state = None
            if solver.check() == z3.sat:
                # Also might not take the jump
                fallthrough_pc = s.pc + 1
            solver.pop()

            solver.push()
            solver.add(cond != 0)
            if solver.check() == z3.sat:
                # OK, can take the jump
                if is_concrete(loc):
                    loc_conc = loc.as_long()
                    if loc_conc == fallthrough_pc:
                        # Fuse fallthrough and jump if to same location
                        fallthrough_pc = None
                        s.make_child_branch(new_pc = loc_conc, preds = [s.gas > 0])
                    else:
                        s.make_child_branch(new_pc = loc_conc, preds = [s.gas > 0, cond != 0])
                else:
                    for dest in s.code.all_jumpdests():
                        solver.push()
                        solver.add(loc == dest)
                        if solver.check() == z3.sat:
                            if dest == fallthrough_pc:
                                fallthrough_pc = None
                                s.make_child_branch(new_pc = dest, preds = [s.gas > 0, loc == dest])
                            else:
                                s.make_child_branch(new_pc = dest, preds = [s.gas > 0, cond != 0, loc == dest])
                        solver.pop()
            solver.pop()
            if fallthrough_pc is not None:
                s.make_child_branch(new_pc = fallthrough_pc, preds = [s.gas > 0, cond == 0])
            return
        elif instr.name == 'JUMP':
            end_trace(None)
            (loc,) = instr_args
            if is_concrete(loc):
                s.make_child_branch(new_pc = loc.as_long(), preds=[s.gas > 0])
            else:
                successors = []
                for dest in s.code.all_jumpdests():
                    solver.push()
                    solver.add(loc == dest)
                    if solver.check() == z3.sat:
                        s.make_child_branch(new_pc = dest, preds=[s.gas > 0, loc == dest])
                    solver.pop()
            # No fallthrough
            return
        elif instr.name == 'JUMPDEST':
            s.jumpdests.add(s.pc)
        elif instr.name in {'LOG0', 'LOG1', 'LOG2', 'LOG3', 'LOG4'}:
            pass
        else:
            raise NotImplementedError(instr.name)

        if log_trace:
            print('< ' + ';; '.join(str(z3.simplify(x)) for x in s.stack))
        s.pc += oplen
