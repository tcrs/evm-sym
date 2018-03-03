import os
import sys
import json
import argparse
import z3
import symevm.util, symevm.code, symevm.state, symevm.cfg, symevm.vm, symevm.mem
import traceback

def all_json_files(directory):
    for top, _, files in os.walk(directory):
        for f in files:
            if f.endswith('.json'):
                yield os.path.join(top, f)

def tests_from_files(filenames):
    def test_files():
        for filename in filenames:
            if os.path.isdir(filename):
                yield from all_json_files(filename)
            else:
                yield filename

    for filename in test_files():
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
    b = symevm.util.hex_to_bytes(text)
    m = base
    for i, v in enumerate(b):
        m = z3.Store(m, z3.BitVecVal(i, 256), z3.BitVecVal(v, 8))
    return symevm.mem.Memory(base=m), len(b)

def get_state(items):
    state = {}
    for addr, info in items.items():
        unknown_keys = set(info.keys()) - {'balance', 'code', 'nonce', 'storage'}
        if unknown_keys:
            raise NotImplementedError('Unknown contract state keys ' + str(unknown_keys))
        balance = int(info['balance'], 0)
        nonce = int(info['nonce'], 0)
        storage = dict_to_storage(info['storage'])
        code = symevm.code.Code(info['code'])
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

    code = symevm.code.Code(test['exec']['code'])
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

    failed = False
    if 'post' in test:
        for addr, info in test['post'].items():
            addr = int(addr, 0)
            if 'storage' in info:
                for k, v in info['storage'].items():
                    k = int(k, 0)
                    v = int(v, 0)
                    calculated = z3.simplify(z3.Select(leaves[0].storage, z3.BitVecVal(k, 256)))
                    if v != calculated.as_long():
                        failed = True
                        print('FAIL: expected storage[{}][{}] == {}. Actual value: {}'.format(
                            addr, k, v, calculated))
    else:
        # TODO think should check there was an abort maybe?
        pass

    return not failed

def add_args(p):
    p.add_argument('tests', nargs='+', help='Test JSON files')
    p.add_argument('--cfg', action='store_true', help='Print CFG of test code')
    p.add_argument('--trace', action='store_true', help='Print detailed trace of instruction execution')
    p.add_argument('--continue', dest='cont', choices=('y', 'n'), default=None, help='Continue after test failure. Default y for multiple files on command line')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    add_args(parser)
    args = parser.parse_args()
    if args.cont is None:
        args.cont = 'y' if len(args.tests) > 1 else 'n'
    failed = []
    passed = []
    for name, test in tests_from_files(args.tests):
        try:
            if run_test(args, name, test):
                passed.append(name)
            else:
                failed.append(name)
                if args.cont == 'n':
                    sys.exit(1)
        except KeyboardInterrupt:
            sys.exit(1)
        except:
            failed.append(name)
            if args.cont == 'n':
                raise
            else:
                traceback.print_exc()
    print('Passed {}/{}'.format(len(passed), len(passed) + len(failed)))
    if failed:
        print('Failed tests:')
        for n in failed:
            print(n)
