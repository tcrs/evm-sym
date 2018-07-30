import symevm.state

def dict_to_storage(items, base=symevm.state.StorageEmpty):
    s = base
    for k, v in items.items():
        s = z3.Store(s, z3.BitVecVal(int(k, 0), 256), z3.BitVecVal(int(v, 0), 256))
    return s

def get_state(items):
    state = {}
    for addr, info in items.items():
        unknown_keys = set(info.keys()) - {'balance', 'code', 'nonce', 'storage'}
        if unknown_keys:
            raise NotImplementedError('Unknown contract state keys ' + str(unknown_keys))
        if 'balance' in info:
            balance = int(info['balance'], 0)
        else:
            balance = None
        if 'nonce' in info:
            nonce = int(info['nonce'], 0)
        else:
            nonce = None
        if 'storage' in info:
            storage = dict_to_storage(info['storage'])
        else:
            storage = None
        code = symevm.code.Code(info['code'])
        state[int(addr, 0)] = symevm.state.ContractState(code=code, storage=storage, balance=balance, nonce=nonce)
    return state
