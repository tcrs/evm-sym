import z3
import sys
import copy
import argparse
import collections
from ethereum import opcodes, utils
import symevm.vm, symevm.util, symevm.bb, symevm.cfg, symevm.state, symevm.code
import assemble

MemorySort = z3.ArraySort(z3.BitVecSort(256), z3.BitVecSort(8))
StorageSort = z3.ArraySort(z3.BitVecSort(256), z3.BitVecSort(256))

MemoryEmpty = z3.K(z3.BitVecSort(256), z3.BitVecVal(0, 8))
StorageEmpty = z3.K(z3.BitVecSort(256), z3.BitVecVal(0, 256))

def memory_any():
    return z3.Const('memory', MemorySort)

def storage_any():
    return z3.Const('storage', StorageSort)

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
    #0x1234: symevm.vm.ContractState(symevm.code.Code(assemble.assemble(['0 0 0 0 0 0x1235 77 CALL 1 1 SSTORE STOP'])), named_storage('0x1234')),
    0x1234: symevm.state.ContractState(symevm.code.Code(assemble.assemble(contract1)), named_storage('0x1234')),
    #0x1235: symevm.vm.ContractState(symevm.code.Code(assemble.assemble(['0 0 0 0 0 0x1234 75 CALL'])), named_storage('0x1235')),
    0x1235: symevm.state.ContractState(symevm.code.Code(assemble.assemble(contract2)), named_storage('0x1235')),
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
    code = utils.parse_as_bin(code.rstrip())

    code = symevm.code.Code(code)

    #global_state = test_global_state
    global_state = {
        0x1234: symevm.state.ContractState(code),
        #0x1234: symevm.vm.ContractState(code, StorageEmpty),
    }

    # TODO
    # - HANDLE LOOPS!!! Probably helped by limiting max gas
    # - limit initial_gas <= block gas limit

    base_t = symevm.state.TransactionState('base', 0x1234, global_state, initial_storage_policy=symevm.state.storage_any_policy)
    root = symevm.cfg.get_cfg(code, base_t, print_trace=args.trace)
    if args.cfg:
        poss_state = symevm.state.TransactionState('t', 0x1234, global_state, caller=z3.BitVecVal(args.caller, 256),
            initial_storage_policy=symevm.state.storage_empty_policy,
            origin=z3.BitVecVal(args.caller, 256))
        #poss_env = Environment('t', code, address=1234, caller=z3.BitVecVal(args.caller, 256), initial_storage=StorageEmpty)
        symevm.cfg.to_dot(code, root, base_t, poss_state, z3.Solver())
        #symevm.cfg.to_dot(code, root)
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
