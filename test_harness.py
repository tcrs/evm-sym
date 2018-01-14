import sys
import json
import argparse
import z3
from ethereum import utils
import symevm.util, symevm.code, symevm.state, symevm.cfg, symevm.vm

def tests_from_files(filenames):
    for filename in filenames:
        with open(filename, 'r') as f:
            loaded = json.load(f)
        for name, test in loaded.items():
            yield '{}:{}'.format(filename, name), test

def dict_to_storage(items, base=symevm.state.StorageEmpty):
    s = base
    for k, v in items.items():
        s = z3.Store(s, z3.BitVecVal(int(k, 0), 256), z3.BitVecVal(int(v, 0), 256))
    return s

def get_cfg_leaves(leaves, node):
    if not node.successors:
        leaves.append(node)
    else:
        for s in node.successors:
            get_cfg_leaves(leaves, s)

def run_test(args, name, test):
    print(name)

    state = {}
    storages = {}
    for addr, info in test['pre'].items():
        addr = int(addr, 0)
        storages[addr] = dict_to_storage(info['storage'])
        state[addr] = symevm.vm.ContractState(symevm.code.Code(utils.parse_as_bin(info['code'])))

    code = symevm.code.Code(utils.parse_as_bin(test['exec']['code']))
    addr = int(test['exec']['address'], 0)

    ts = symevm.state.TransactionState('base', addr,
        initial_storage_policy=symevm.state.storage_specified_policy(storages, symevm.state.storage_empty_policy))
    root = symevm.cfg.get_cfg(state, ts, print_trace=args.trace, verbose_coverage=False)
    if args.cfg:
        symevm.cfg.to_dot(code, root)
    leaves = []
    get_cfg_leaves(leaves, root)
    assert len(leaves) == 1, leaves

    #print(leaves[0].storage)
    #print(leaves[0].global_state)

    if 'post' in test:
        for addr, info in test['post'].items():
            addr = int(addr, 0)
            if 'storage' in info:
                for k, v in info['storage'].items():
                    k = int(k, 0)
                    v = int(v, 0)
                    calculated = z3.simplify(z3.Select(leaves[0].storage, z3.BitVecVal(k, 256)))
                    if v != calculated.as_long():
                        print('FAIL: expected storage[{}][{}] == {}. Actual value: {}'.format(
                            addr, k, v, calculated))
    else:
        # TODO think should check there was an abort maybe?
        pass

def add_args(p):
    p.add_argument('tests', nargs='+', help='Test JSON files')
    p.add_argument('--cfg', action='store_true', help='Print CFG of test code')
    p.add_argument('--trace', action='store_true', help='Print detailed trace of instruction execution')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    add_args(parser)
    args = parser.parse_args()
    for name, test in tests_from_files(args.tests):
        run_test(args, name, test)
