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

def mem_from_str(text, base=symevm.state.MemoryEmpty):
    b = utils.parse_as_bin(text)
    m = base
    for i, v in enumerate(b):
        m = z3.Store(m, z3.BitVecVal(i, 256), z3.BitVecVal(v, 8))
    return m, len(b)

def get_state(items):
    state = {}
    for addr, info in items.items():
        unknown_keys = set(info.keys()) - {'balance', 'code', 'nonce', 'storage'}
        if unknown_keys:
            raise NotImplementedError('Unknown contract state keys ' + str(unknown_keys))
        balance = int(info['balance'], 0)
        nonce = int(info['nonce'], 0)
        storage = dict_to_storage(info['storage'])
        code = symevm.code.Code(utils.parse_as_bin(info['code']))
        state[addr] = symevm.state.ContractState(code=code, storage=storage, balance=balance, nonce=nonce)
    return state

def get_transaction_info(test):
    env_translate = dict(
        currentCoinbase='coinbase',
        currentDifficulty='difficulty',
        currentGasLimit='gaslimit',
        currentNumber='number',
        currentTimestamp='timestamp')
    tstate = {}
    for k, v in test['env'].items():
        tstate[env_translate[k]] = z3.BitVecVal(int(v, 0), 256)

    exec_translate = dict(
        gasPrice = 'gasprice',
        value = 'callvalue',
        caller = 'caller',
        gas = 'initial_gas')
    for k, v in test['exec'].items():
        if k in exec_translate:
            tstate[exec_translate[k]] = z3.BitVecVal(int(v, 0), 256)

    code = symevm.code.Code(utils.parse_as_bin(test['exec']['code']))
    tstate['calldata'], tstate['calldatasize'] = mem_from_str(test['exec']['data'])

    return code, tstate

def get_cfg_leaves(leaves, node):
    if not node.successors:
        leaves.append(node)
    else:
        for s in node.successors:
            get_cfg_leaves(leaves, s)

def run_test(args, name, test):
    print(name)

    global_state = get_state(test['pre'])
    addr = int(test['exec']['address'], 0)
    code, tstate = get_transaction_info(test)

    ts = symevm.state.TransactionState('base', addr, global_state, **tstate)
    root = symevm.cfg.get_cfg(code, ts, print_trace=args.trace, verbose_coverage=False)
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
