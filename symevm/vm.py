import z3
import copy
import collections
from . import util
from ethereum import opcodes, utils

MemorySort = z3.ArraySort(z3.BitVecSort(256), z3.BitVecSort(8))
StorageSort = z3.ArraySort(z3.BitVecSort(256), z3.BitVecSort(256))

MemoryEmpty = z3.K(z3.BitVecSort(256), z3.BitVecVal(0, 8))
StorageEmpty = z3.K(z3.BitVecSort(256), z3.BitVecVal(0, 256))

class CFGNode:
    def __init__(self, parent=None, predicates=[], pc=0):
        self.start_pc = pc
        self.pc = pc
        if parent is None:
            self.code = None
            self.stack = []
            self.memory = MemoryEmpty
            self.gas = None
        else:
            # These members will represent the state at the end of the current
            # block.
            self.code = parent.code
            self.stack = copy.copy(parent.stack)
            self.memory = parent.memory
            self.storage = parent.storage
            self.gas = parent.gas
        self.predicates = predicates
        self.parent = parent
        self.successors = []
        # Why the block finished here
        self.end_type = None
        self.end_info = None

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

        print('{}[color={},label="{}"];'.format(blockname, colour, '\\n'.join(util.disassemble(code, t.start_pc, t.pc))))
        for i, succ in enumerate(t.successors):
            sname = blockname + '_' + str(i)
            recprint(succ, sname)
            print('{} -> {} [label="{}"];'.format(blockname, sname, z3.simplify(z3.And(succ.predicates))))
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

def run_block(env, s, solver, log_trace=False):
    def getargs(n):
        return [s.stack.pop() for i in range(n)]

    def end_trace(reason, *args):
        s.end_type = reason
        s.end_info = args
        pass

    def make_succ(new_pc, preds):
        return (preds, new_pc)

    while True:
        op = s.code[s.pc]
        try:
            name, ins, outs, gas = opcodes.opcodes[op]
        except KeyError:
            end_trace('invalid')
            return []

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
            raise NotImplementedError(name)
            #start, sz = as_concrete(start), as_concrete(sz)
            #stack.append(utils.sha3_256([as_concrete(
        elif name in {'CALLER', 'ADDRESS', 'ORIGIN', 'CALLVALUE', 'CALLDATASIZE', 'GASPRICE', 'COINBASE', 'TIMESTAMP', 'NUMBER', 'DIFFICULTY', 'GASLIMIT'}:
            reducestack(getattr(env, name.lower()))
        elif name in {'BALANCE', 'BLOCKHASH', 'EXTCODESIZE'}:
            reducestack(lambda x: (getattr(env, name.lower())())(x))
        elif name == 'CODECOPY':
            start_mem, start_code, sz = getargs(ins)
            start_code = as_concrete(start_code)
            for i in range(as_concrete(sz)):
                s.memory = z3.Store(s.memory, start_mem + i, s.code[start_code + i])
        elif name == 'CALLDATACOPY':
            src, dest, sz = getargs(ins)
            for i in range(sz.as_long()):
                s.memory = z3.Store(s.memory, dest + i, z3.Select(env.calldata(), src + i))
        elif name == 'CALLDATALOAD':
            args = getargs(ins)
            s.stack.append(z3.simplify(z3.Concat(*[z3.Select(env.calldata(), args[0] + i) for i in range(32)])))
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
            # TODO ACTUALLY HANDLE THIS PROPERLY!!
            end_trace('return')
            return []
        #elif name == 'RETURN':
        #    ret_start, ret_size = getargs(ins)
        #    ret_info = s.callstack.pop()
        #    size = min(ret_size, ret_info.out_size)
        #    off = start.as_long()
        #    ret_state = ret_info.state
        #    for i in range(size.as_long()):
        #        ret_state.memory = z3,Store(ret_state.memory, ret_info.out_off + i,
        #            z3.Select(memory, off + i))
        #    raise NotImplementedError()
        elif name == 'CALL':
            successors = []
            # TODO pass value through to calls
            gas, call_addr, value, in_off, in_sz, out_off, out_sz = getargs(ins)
            if is_concrete(call_addr):
                raise NotImplementedError('concrete call')
            else:
                end_trace('call', call_addr, value, gas)
                name = '{}:CALL({})'.format(s.pc, z3.simplify(call_addr))
                callres = z3.BitVec(name, 256)
                s.stack.append(callres)
                return [make_succ(s.pc + 1, [z3.Or(callres == 1, callres == 0)])]

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
            return [make_succ(s.pc + 1, [z3.Or(res == 0, res == 1)])]
        elif name == 'SUICIDE':
            to_addr = getargs(ins)
            end_trace('suicide', to_addr)
            # No successors
            return []
        elif name == 'JUMPI':
            end_trace(None)
            loc, cond = getargs(ins)

            successors = []

            solver.push()
            solver.add(cond == 0)
            fallthrough_state = None
            if solver.check() == z3.sat:
                # Also might not take the jump
                fallthrough_state = make_succ(s.pc + 1, [cond == 0])
                successors.append(fallthrough_state)
            solver.pop()

            solver.push()
            solver.add(cond != 0)
            if solver.check() == z3.sat:
                # OK, can take the jump
                if is_concrete(loc):
                    if fallthrough_state and loc == fallthrough_state[1]:
                        fallthrough_state[0][-1] = z3.Or(cond == 0, cond != 1)
                    else:
                        successors.append(make_succ(loc.as_long(), [cond != 0]))
                else:
                    for dest in s.code.all_jumpdests():
                        solver.push()
                        solver.add(loc == dest)
                        if solver.check() == z3.sat:
                            successors.append(make_succ(dest, [cond != 0, loc == dest]))
                        solver.pop()
            solver.pop()
            return successors
        elif name == 'JUMP':
            end_trace(None)
            (loc,) = getargs(ins)
            if is_concrete(loc):
                return [make_succ(loc.as_long(), [])]
            else:
                successors = []
                for dest in s.code.all_jumpdests():
                    solver.push()
                    solver.add(loc == dest)
                    if solver.check() == z3.sat:
                        successors.append(make_succ(dest, [loc == dest]))
                    solver.pop()
                # No fallthrough
                return successors
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

def get_cfg(code, env, print_trace=False):
    def rectrace(node, solver):
        successors = run_block(env, node, solver, log_trace=print_trace)

        if print_trace:
            for preds, nextpc in successors:
                print('{} => {}'.format(z3.simplify(z3.And(*preds)), nextpc))
            if len(successors) == 0 and print_trace:
                print('------------------ END OF THIS TRACE ------------')

        if successors:
            for preds, nextpc in successors:
                child = CFGNode(parent=node, pc=nextpc, predicates=preds + [node.gas > 0])
                node.successors.append(child)

                solver.push()
                solver.add(*preds)
                rectrace(child, solver)
                solver.pop()
        return node

    root = CFGNode(pc=0)
    root.code = code
    root.storage = env.initial_storage()
    root.gas = env.initial_gas()

    return rectrace(root, z3.Solver())
