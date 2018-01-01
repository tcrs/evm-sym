import z3
import copy
import collections
from . import util
from ethereum import opcodes, utils

MemorySort = z3.ArraySort(z3.BitVecSort(256), z3.BitVecSort(8))
StorageSort = z3.ArraySort(z3.BitVecSort(256), z3.BitVecSort(256))

MemoryEmpty = z3.K(z3.BitVecSort(256), z3.BitVecVal(0, 8))
StorageEmpty = z3.K(z3.BitVecSort(256), z3.BitVecVal(0, 256))

sha3 = z3.Function('sha3', MemorySort, z3.BitVecSort(256))

ContractState = collections.namedtuple('ContractState', 'code storage')

ReturnInfo = collections.namedtuple('ReturnInfo', 'call_node new_pc retdata_start retdata_sz retresult')
CallInfo = collections.namedtuple('CallInfo', 'calldata_mem calldata_off calldata_sz gas value')

class CFGNode:
    def __init__(self, global_state, transaction, parent=None, predicates=[], pc=0):
        self.start_pc = pc
        self.pc = pc
        self.transaction = transaction
        # TODO Avoid copying this around every time - only copy on write
        self.global_state = copy.copy(global_state)
        if parent is None:
            self.code = None
            self.stack = []
            self.callstack = []
            self.memory = MemoryEmpty
            self.storage = None
            self.gas = None
            self.callinfo = None
            self.addr = None
        else:
            # These members will represent the state at the end of the current
            # block.
            self.code = parent.code
            self.stack = copy.copy(parent.stack)
            self.callstack = copy.copy(parent.callstack)
            self.memory = parent.memory
            self.storage = parent.storage
            self.gas = parent.gas
            self.callinfo = parent.callinfo
            self.addr = parent.addr
        self.predicates = predicates
        self.parent = parent
        self.successors = []
        # Why the block finished here
        self.end_type = None
        self.end_info = None

    def make_child_branch(self, new_pc, preds):
        n = CFGNode(self.global_state, self.transaction, parent=self, pc=new_pc, predicates = preds)
        self.successors.append(n)
        return n

    def make_child_call(self, addr, callinfo, retinfo):
        #print(z3.simplify(self.memory))
        n = CFGNode(self.global_state, self.transaction);
        # Put current storage for current contract into global state so that it
        # is correctly picked up for re-entrant calls
        n.global_state[self.addr] = n.global_state[self.addr]._replace(storage=self.storage)
        n.parent = self
        info = n.global_state[addr]
        n.code = info.code
        n.storage = info.storage
        n.callstack = self.callstack + [retinfo]
        n.gas = callinfo.gas
        n.callinfo = callinfo
        n.addr = addr
        self.successors.append(n)
        return n

    def make_child_return(self, retdata_off, retdata_sz):
        self.retdata_off, self.retdata_sz = retdata_off, retdata_sz
        #print(z3.simplify(self.memory))
        if self.callstack:
            retinfo = self.callstack[-1]
            n = CFGNode(self.global_state, self.transaction, parent=retinfo.call_node, pc=retinfo.new_pc)
            n.global_state[self.addr] = n.global_state[self.addr]._replace(storage = self.storage)
            n.storage = n.global_state[n.addr].storage
            n.parent = self
            n.predicates.append(retinfo.retresult == 1)
            # TODO handle non-concrete sizes?
            for i in range(min(retdata_sz.as_long(), retinfo.retdata_sz.as_long())):
                n.memory = z3.Store(n.memory, retinfo.retdata_start + i, z3.Select(self.memory, retdata_off + i))
            self.successors.append(n)
            return n

    def __str__(self):
        return 'CFGNode({}:{}, end_type={})'.format(self.start_pc, self.pc, self.end_type)

def cfg_to_dot(code, root, root_env=None, check_env=None, solver=None):
    def recprint(t, blockname):
        colour = 'black'
        if solver is not None:
            solver.push()
            solver.add(*[root_env.substitute(check_env, x) for x in t.predicates])
            if solver.check() == z3.sat:
                colour = 'green'
            else:
                colour = 'red'

        #print('subgraph x{:x} {{'.format(t.addr))
        #print('label="0x{:x}";'.format(t.addr))
        print('{}[color={},label="0x{:x}\n{}"];'.format(blockname, colour, t.addr, '\\n'.join(util.disassemble(t.code, t.start_pc, t.pc))))
        #print('}')
        if hasattr(t, 'retdata_off'):
            retlabel = ', '.join(str(z3.simplify(z3.Select(t.memory, t.retdata_off + i)))
                for i in range(t.retdata_sz.as_long()))
        else:
            retlabel = None
        for i, succ in enumerate(t.successors):
            sname = blockname + '_' + str(i)
            recprint(succ, sname)
            label = str(z3.simplify(z3.And(succ.predicates)))
            if retlabel is not None:
                label = label + '\nRETURN => ' + retlabel

            print('{} -> {} [label="{}"];'.format(blockname, sname, label))
        if not t.successors and retlabel is not None:
            print('{}_exit[color=black,label="X"];'.format(blockname));
            print('{} -> {}_exit [label="RETURN => {}"];'.format(blockname, blockname, retlabel))
        if solver is not None:
            solver.pop()

    print('digraph {')
    print('node [shape=box];')
    recprint(root, 'root')
    print('}')

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
    def getargs(n):
        return [s.stack.pop() for i in range(n)]

    def end_trace(reason, *args):
        s.end_type = reason
        s.end_info = args
        pass

    while True:
        op = s.code[s.pc]
        try:
            name, ins, outs, gas = opcodes.opcodes[op]
        except KeyError:
            end_trace('invalid')
            return

        if log_trace:
            print('{:04}: {}'.format(s.pc, name))
            print('> {}'.format([z3.simplify(x) for x in s.stack]))
            #print('> {} | {} | {}'.format(stack, mem, store))

        def reducestack(fn):
            s.stack.append(fn(*getargs(ins)))

        oplen = 1

        # TODO Proper gas accounting!
        # Some instructions have variable gas costs
        # pyethereum gas field we're using here is not the latest mainnet values
        s.gas = s.gas - gas

        ## Execute instruction
        # TODO
        #  - Check that the semantics of z3 math ops match EVM spec exactly
        #  (especially for MOD/SMOD)...
        # - teach z3 things like SHA3(a) == SHA3(b) iff a == b

        if op >= 0x80 and op <= 0x8f: # DUPn
            n = op - 0x80
            s.stack.append(s.stack[-(n + 1)])
        elif op >= 0x90 and op <= 0x9f: #SWAPn
            n = op - 0x90 + 1
            temp = s.stack[-(n + 1)]
            s.stack[-(n + 1)] = s.stack[-1]
            s.stack[-1] = temp
        elif op >= 0x60 and op <= 0x7f: #PUSHn
            npush = op - 0x60 + 1
            # TODO supposed to get zeros if some bytes >= len(inp)
            val = utils.big_endian_to_int(s.code[s.pc + 1:s.pc + npush + 1])
            s.stack.append(z3.BitVecVal(val, 256))
            oplen += npush
        elif name == 'ADD':
            reducestack(lambda x, y: x + y)
        elif name == 'MUL':
            reducestack(lambda x, y: x * y)
        elif name == 'SUB':
            reducestack(lambda x, y: x - y)
        elif name == 'DIV':
            reducestack(lambda x, y: z3.If(y == 0, z3.BitVecVal(0, 256), z3.UDiv(x, y)))
        elif name == 'SDIV':
            reducestack(lambda x, y: z3.If(y == 0,
                z3.BitVecVal(0, 256), z3.If(x == -2**255 and y == -1,
                    z3.BitVecVal(-2*255, 256), x / y)))
        elif name == 'MOD':
            reducestack(lambda x, y: z3.If(y == 0, z3.BitVecVal(0, 256), z3.URem(x, y)))
        elif name == 'SMOD':
            # TODO args[1] == 0
            reducestack(lambda x, y: z3.If(y == 0, z3.BitVecVal(0, 256), z3.SRem(x, y)))
        elif name == 'ADDMOD':
            # TODO intermediate add not modulo 256 (need wider types)
            reducestack(lambda x, y, z: z3.If(z == 0, z3.BitVecVal(0, 256), z3.URem(x + y, z)))
        elif name == 'MULMOD':
            # TODO intermediate mul not modulo 256 (need wider types)
            reducestack(lambda x, y, z: z3.If(z == 0, z3.BitVecVal(0, 256), z3.URem(x + y, z)))
        elif name == 'EXP':
            # TODO z3 currently doesn't seem to provide __pow__ on BitVecs?
            reducestack(lambda x, y: z3.BitVecVal(x.as_long() ** y.as_long(), 256))
        elif name == 'SIGNEXTEND':
            NotImplemented
        elif name == 'LT':
            reducestack(lambda x, y: _bool_to_01(z3.ULT(x, y)))
        elif name == 'GT':
            reducestack(lambda x, y: _bool_to_01(z3.UGT(x, y)))
        elif name == 'SLT':
            reducestack(lambda x, y: _bool_to_01(x < y))
        elif name == 'SGT':
            reducestack(lambda x, y: _bool_to_01(x > y))
        elif name == 'EQ':
            reducestack(lambda x, y: _bool_to_01(x == y))
        elif name == 'ISZERO':
            reducestack(lambda x: _bool_to_01(x == 0))
        elif name == 'AND':
            reducestack(lambda x, y: x & y)
        elif name == 'OR':
            reducestack(lambda x, y: x | y)
        elif name == 'XOR':
            reducestack(lambda x, y: x ^ y)
        elif name == 'NOT':
            reducestack(lambda x: ~x)
        elif name == 'BYTE':
            # TODO z3.Extract could be used, need to branch on byte index though.
            NotImplemented
        elif name == 'CODESIZE':
            s.stack.append(z3.BitVecVal(s.code.size(), 256))
        elif name == 'SHA3':
            start, sz = getargs(ins)
            v = MemoryEmpty
            n = as_concrete(sz)
            for i in range(n):
                v = z3.Store(v, i, z3.Select(s.memory, start + i))
            s.stack.append(sha3(v))
            # TODO when n == 0 or all values are concrete, simplify!
            #start, sz = as_concrete(start), as_concrete(sz)
            #stack.append(utils.sha3_256([as_concrete(
        elif name in {'GASPRICE', 'COINBASE', 'TIMESTAMP', 'NUMBER', 'DIFFICULTY', 'GASLIMIT'}:
            reducestack(getattr(s.transaction, name.lower()))
        elif name in {'BALANCE', 'BLOCKHASH', 'EXTCODESIZE'}:
            reducestack(lambda x: (getattr(s.transaction, name.lower())())(x))
        elif name == 'ADDRESS':
            s.stack.append(s.addr)
        elif name == 'CALLVALUE':
            s.stack.append(s.callinfo.value)
        elif name == 'CALLDATASIZE':
            s.stack.append(s.callinfo.calldata_sz)
        elif name == 'CALLER':
            NotImplemented
        elif name == 'ORIGIN':
            NotImplemented
        elif name == 'CODECOPY':
            start_mem, start_code, sz = getargs(ins)
            start_code = as_concrete(start_code)
            for i in range(as_concrete(sz)):
                s.memory = z3.Store(s.memory, start_mem + i, s.code[start_code + i])
        elif name == 'CALLDATACOPY':
            src, dest, sz = getargs(ins)
            cd_mem, cd_off, cd_sz = s.callinfo
            for i in range(sz.as_long()):
                # TOOD: out of range == 0?
                cd_val = z3.If(src + i < cd_sz, z3.Select(cd_mem, cd_off + src + i), 0)
                s.memory = z3.Store(s.memory, dest + i, cd_val)
        elif name == 'CALLDATALOAD':
            args = getargs(ins)
            cd_mem, cd_off, cd_sz, *_ = s.callinfo
            s.stack.append(z3.simplify(z3.Concat(
                *[z3.If(args[0] + i < cd_sz, z3.Select(cd_mem, cd_off + args[0] + i), 0) for i in range(32)])))
        elif name == 'POP':
            getargs(ins)
            pass
        elif name == 'MLOAD':
            args = getargs(ins)
            s.stack.append(z3.simplify(z3.Concat(*[z3.Select(s.memory, args[0] + i) for i in range(32)])))
        elif name == 'MSTORE':
            args = getargs(ins)
            for i in range(32):
                s.memory = z3.Store(s.memory, args[0] + i, get_byte(args[1], i))
        elif name == 'MSTORE8':
            args = getargs(ins)
            s.memory = z3.Store(s.memory, args[0], get_byte(args[1], 31))
        elif name == 'SLOAD':
            args = getargs(ins)
            s.stack.append(z3.simplify(z3.Select(s.storage, args[0])))
        elif name == 'SSTORE':
            args = getargs(ins)
            s.storage = z3.Store(s.storage, args[0], args[1])
        elif name == 'PC':
            s.stack.append(z3.BitVecVal(s.pc, 256))
        elif name == 'GAS':
            # TODO actually track gas usage?
            s.stack.append(z3.BitVec('{}:GAS'.format(s.pc), 256))
        elif name in 'STOP':
            end_trace('stop')
            return []
        elif name == 'RETURN':
            ret_start, ret_size = getargs(ins)
            s.make_child_return(ret_start, ret_size);
            return
        elif name == 'CALL':
            gas, call_addr, value, in_off, in_sz, out_off, out_sz = getargs(ins)
            callres = z3.BitVec(name, 256)
            s.stack.append(callres)
            if is_concrete(call_addr):
                s.make_child_call(addr = call_addr.as_long(),
                    retinfo=ReturnInfo(s, s.pc + 1, out_off, out_sz, callres),
                    callinfo=CallInfo(s.memory, in_off, in_sz, gas, value))
                return
            else:
                end_trace('call', call_addr, value, gas)
                name = '{}:CALL({})'.format(s.pc, z3.simplify(call_addr))
                s.make_child_branch(new_pc = s.pc + 1, preds = [s.gas > 0, z3.Or(callres == 1, callres == 0)])
                return

        #elif name == 'CALLCODE':
        #    raise NotImplementedError()
        #elif name == 'DELEGATECALL':
        #    raise NotImplementedError()
        elif name == 'CREATE':
            value, in_off, in_sz = getargs(ins)
            name = '{}:CREATE({})'.format(s.pc, value)
            res = z3.BitVec(name, 256)
            s.stack.append(res)
            end_trace('create', value)
            s.make_child_branch(new_pc = s.pc + 1, preds = [s.gas > 0, z3.Or(res == 0, res == 1)])
            return
        elif name == 'SUICIDE':
            to_addr = getargs(ins)
            end_trace('suicide', to_addr)
            # No successors
            return []
        elif name == 'JUMPI':
            end_trace(None)
            loc, cond = getargs(ins)

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
        elif name == 'JUMP':
            end_trace(None)
            (loc,) = getargs(ins)
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
        elif name == 'JUMPDEST':
            pass
        elif name in {'LOG0', 'LOG1', 'LOG2', 'LOG3', 'LOG4'}:
            getargs(ins)
            pass
        else:
            raise NotImplementedError(name)

        if log_trace:
            print('< {}'.format([z3.simplify(x) for x in s.stack]))
        s.pc += oplen

def get_cfg(global_state, transaction, print_trace=True):
    def rectrace(node, solver):
        run_block(node, solver, log_trace=print_trace)

        if print_trace:
            for succ in node.successors:
                print('{} => {}'.format(z3.simplify(z3.And(*succ.predicates)), succ.start_pc))
            if len(node.successors) == 0:
                print('------------------ END OF THIS TRACE ------------')

        for succ in node.successors:
            solver.push()
            solver.add(*succ.predicates)
            rectrace(succ, solver)
            solver.pop()
        return node

    contract_state = global_state[transaction.address()]

    root = CFGNode(global_state, transaction)
    root.code = contract_state.code
    root.storage = contract_state.storage
    root.gas = transaction.initial_gas()
    root.callinfo = CallInfo(transaction.calldata(), 0, transaction.calldatasize(),
        transaction.initial_gas(), transaction.callvalue())
    root.addr = transaction.address()

    return rectrace(root, z3.Solver())
