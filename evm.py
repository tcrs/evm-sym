import z3
import sys
import copy
import argparse
import collections
from ethereum import opcodes, utils
import symevm.vm, symevm.util
import assemble

MemorySort = z3.ArraySort(z3.BitVecSort(256), z3.BitVecSort(8))
StorageSort = z3.ArraySort(z3.BitVecSort(256), z3.BitVecSort(256))

MemoryEmpty = z3.K(z3.BitVecSort(256), z3.BitVecVal(0, 8))
StorageEmpty = z3.K(z3.BitVecSort(256), z3.BitVecVal(0, 256))

def memory_any():
    return z3.Const('memory', MemorySort)

def storage_any():
    return z3.Const('storage', StorageSort)

def cached(fn):
    def wrapper(self, *args):
        if fn.__name__ not in self._cache:
            self._cache[fn.__name__] = fn(self, *args)
        return self._cache[fn.__name__]
    return wrapper

# Global State:
#   address -> (code, storage)
#
# Transaction State:
#   block num, gas price, etc...
#
# Call State:
#   address, calldata/size, callstack depth
#
# CFG Node:
#   updated global state (storage)
#   stack, memory, gas, pc

class StateCache:
    def __init__(self, **kwargs):
        self._cache = {}
        for name, val in kwargs.items():
            assert hasattr(self, name), name
            self._cache[name] = val

class TransactionState(StateCache):
    def __init__(self, name, address, **kwargs):
        StateCache.__init__(self, **kwargs)
        self.name = name
        self._address = address

    def address(self):
        return self._address

    @cached
    def gasprice(self):
        return z3.BitVec('GASPRICE<{}>'.format(self.name), 256)

    @cached
    def extcodesize(self):
        return z3.Function('EXTCODESIZE<{}>'.format(self.name), z3.BitVecSort(256), z3.BitVecSort(256))

    @cached
    def blockhash(self):
        return z3.Function('BLOCKHASH<{}>'.format(self.name), z3.BitVecSort(256), z3.BitVecSort(256))

    @cached
    def coinbase(self):
        return z3.BitVec('COINBASE<{}>'.format(self.name), 256)

    @cached
    def timestamp(self):
        return z3.BitVec('TIMESTAMP<{}>'.format(self.name), 256)

    @cached
    def number(self):
        return z3.BitVec('NUMBER<{}>'.format(self.name), 256)

    @cached
    def difficulty(self):
        return z3.BitVec('DIFFICULTY<{}>'.format(self.name), 256)

    @cached
    def gaslimit(self):
        return z3.BitVec('GASLIMIT<{}>'.format(self.name), 256)

    @cached
    def balance(self):
        return z3.Function('BALANCE<{}>'.format(self.name), z3.BitVecSort(256), z3.BitVecSort(256))

    @cached
    def initial_gas(self):
        return z3.Int('INITIALGAS<{}>'.format(self.name))

    @cached
    def initial_callstack_depth(self):
        return z3.BitVec('ICSDEPTH<{}>'.format(self.name), 256)

    @cached
    def caller(self):
        return z3.BitVec('CALLER<{}>'.format(self.name), 256)

    @cached
    def callvalue(self):
        return z3.BitVec('CALLVALUE<{}>'.format(self.name), 256)

    @cached
    def calldata(self):
        return z3.Const('CALLDATA<{}>'.format(self.name), MemorySort)

    @cached
    def calldatasize(self):
        return z3.BitVec('CALLDATASIZE<{}>'.format(self.name), 256)

class Environment(StateCache):
    def __init__(self, name, **kwargs):
        StateCache.__init__(self, **kwargs)
        self.name = name

    # Differs from z3.substitute in that it can substitute functions (which is
    # required as a few of the environment things are functions). Modified
    # version of python code from:
    # https://stackoverflow.com/questions/15236450/substituting-function-symbols-in-z3-formulas
    # also based somewhat on the z3 substitute implementation:
    # https://github.com/Z3Prover/z3/blob/master/src/ast/rewriter/expr_safe_replace.cpp
    def substitute(self, other, expr):
        cache = z3.AstMap(ctx=expr.ctx)

        fnsubs = []
        for k, v in self._cache.items():
            if z3.is_app(v) and v.num_args() > 0:
                fnsubs.append((v, getattr(other, k)()))
            else:
                cache[v] = getattr(other, k)()

        todo = [expr]
        while todo:
            n = todo[-1]
            if n in cache:
                todo.pop()
            elif z3.is_var(n):
                cache[n] = n
                todo.pop()
            elif z3.is_app(n):
                new_args = []
                for i in range(n.num_args()):
                    arg = n.arg(i)
                    if arg not in cache:
                        todo.append(arg)
                    else:
                        new_args.append(cache[arg])
                # Only actually do the substitution if all the arguments have
                # already been processed
                if len(new_args) == n.num_args():
                    todo.pop()
                    fn = n.decl()
                    for oldfn, newfn in fnsubs:
                        if z3.eq(fn, oldfn):
                            new_fn = z3.substitute_vars(newfn, *new_args)
                            break
                    else:
                        # TODO only if new_args != old_args
                        new_fn = fn(new_args)
                    cache[n] = new_fn
            else:
                assert z3.is_quantifier(n)
                # Not currently implemented as don't use quanitifers at the
                # moment
                raise NotImplementedError()
        return cache[expr]


    def get_substitutions(self, other):
        return [(v, getattr(other, k)()) for k, v in self._cache.items()]

    @cached
    def initial_storage(self):
        return z3.Const('ISTORAGE<{}>'.format(self.name), StorageSort)

    @cached
    def address(self):
        return z3.BitVec('ADDRESS<{}>'.format(self.name), 256)

    @cached
    def codesize(self):
        return z3.BitVec('CODESIZE<{}>'.format(self.name), 256)


class Code:
    def __init__(self, code):
        self._code = code
        self._jumpdests = []
        i = 0
        while i < len(code):
            if code[i] == 0x5b:
                self._jumpdests.append(i)
            i += symevm.util.oplen(code[i])

    def size(self):
        return len(self._code)

    def __getitem__(self, x):
        if isinstance(x, slice):
            return self._code[x]
        elif x >= len(self._code):
            return 0
        else:
            return self._code[x]

    def all_jumpdests(self):
        return self._jumpdests

def print_trace(t, prefix=''):
    print('{}{}{}:{}'.format(prefix, (t.end_type + ' ') if t.end_type is not None else '', t.pcs, t.predicates))
    for succ in t.successors:
        assert succ.parent is t
        print_trace(succ, prefix = (prefix + ' >'))

def filter_traces(t, fn):
    if fn(t):
        yield t
    for succ in t.successors:
        yield from filter_traces(succ, fn)

def is_reachable(solver, trace, trace_env, env):
    def all_preds(t):
        if t.parent is not None:
            return all_preds(t.parent) + t.predicates
        else:
            return t.predicates
    solver.add(*[trace_env.substitute(env, x) for x in all_preds(trace)])
    return (solver.check() == z3.sat)

def reachable(root, root_env, env, filterfn):
    def reach_rec(t, solver):
        solver.push()
        solver.add(*[root_env.substitute(env, x) for x in t.predicates])
        if solver.check() == z3.sat:
            if filterfn(t):
                yield t
            for succ in t.successors:
                yield from reach_rec(succ, solver)
        solver.pop()

    solver = z3.Solver()
    yield from reach_rec(root, solver)

def try_reach(targets, root, root_env, envstack):
    solver = z3.Solver()
    unreached_targets = []
    gadgets = []
    for target in targets:
        gadgets = list(reachable(root, root_env, envstack[-1], lambda t: t.end_type in {'call', 'stop'} and t.storage is not root_env.initial_storage()))
        solver.push()
        if is_reachable(solver, target, root_env, envstack[-1]):
            print(target)
            print(solver.assertions())
            print(solver.model())
            print()
        else:
            unreached_targets.append(target)
        solver.pop()

    for gadget in gadgets:
        if not unreached_targets:
            break

        params = {}
        if gadget.end_type == 'call':
            # TODO: other things!
            params = dict(origin = envstack[-1].origin())
        else:
            params = dict()
        print('| gadget: ' + str(gadget.storage))
        params['initial_storage'] = root_env.substitute(envstack[-1], gadget.storage)
        print('>> recursing with storage; ' + str(params['initial_storage']))
        gadget_env = Environment(str(len(envstack)), **params)
        # Note that unreached_targets is updated here so that targets which
        # were reached with a gadget will not also be attempted with another
        # gadget
        unreached_targets = try_reach(unreached_targets, root, root_env, envstack + [gadget_env])
    return unreached_targets

def add_args(parser):
    parser.add_argument('code', default='-', help='EVM code as a hex string')
    parser.add_argument('--cfg', action='store_true', help='Output full control-flow graph in graphviz format')
    parser.add_argument('--trace', action='store_true', help='Output verbose trace of execution')
    parser.add_argument('--caller', type=lambda x: int(x, 0), help='CALLER instruction return value')

def named_storage(name):
    #return z3.Const('Storage<{}>'.format(name), StorageSort)
    return StorageEmpty

contract1 = [
    '0 SLOAD',
    '@finish JUMPI',
    '1 0 SSTORE',
    '1 0 0 0 0 0x1235 77 CALL',
    '0 0 SSTORE',
    '=finish 1 0 RETURN']

contract2 = [
    '1 0 MSTORE8',
    '1 1 1 0 0 0x1234 75 CALL',
    '1 1 RETURN',
    ]

test_global_state = {
    #0x1234: symevm.vm.ContractState(Code(assemble.assemble(['0 0 0 0 0 0x1235 77 CALL 1 1 SSTORE STOP'])), named_storage('0x1234')),
    0x1234: symevm.vm.ContractState(Code(assemble.assemble(contract1)), named_storage('0x1234')),
    #0x1235: symevm.vm.ContractState(Code(assemble.assemble(['0 0 0 0 0 0x1234 75 CALL'])), named_storage('0x1235')),
    0x1235: symevm.vm.ContractState(Code(assemble.assemble(contract2)), named_storage('0x1235')),
}

def main(argv):
    p = argparse.ArgumentParser()
    add_args(p)
    args = p.parse_args(argv)

    if args.caller is None:
        print('Must specify caller')
        sys.exit(1)

    if args.code == '-':
        code = sys.stdin.read()
    else:
        code = open(args.code, 'r').read()
    code = Code(utils.parse_as_bin(code.rstrip()))

    global_state = test_global_state
   # {
   #     1234: symevm.vm.ContractState(code, z3.Const('Storage<1234>', StorageSort)),
   # }

    #base_env = Environment('base', address=0x1234)
    base_t = TransactionState('base', 0x1234)
    root = symevm.vm.get_cfg(global_state, base_t, print_trace=args.trace)
    if args.cfg:
        #poss_env = Environment('t', code, address=1234, caller=z3.BitVecVal(args.caller, 256), initial_storage=StorageEmpty)
        #symevm.vm.cfg_to_dot(code, root, base_env, poss_env, z3.Solver())
        symevm.vm.cfg_to_dot(code, root)
    else:
        interestingfn = lambda t: t.end_type in {'call', 'suicide', 'stop'}
        gadgetsfn = lambda t: t.end_type in {'call', 'stop'} and t.modified_storage is not None

        poss_env = Environment('t', code, caller=z3.BitVecVal(args.caller, 256))
        poss_reachable = list(reachable(root, base_env, poss_env, interestingfn))

        env0 = Environment('0', code, caller=z3.BitVecVal(args.caller, 256), initial_storage=StorageEmpty)

        unreachable = try_reach(poss_reachable, root, base_env, [env0])
        for node in unreachable:
            print('could not reach: {}'.format(node))

    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
