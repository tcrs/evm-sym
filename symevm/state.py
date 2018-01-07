import z3

MemorySort = z3.ArraySort(z3.BitVecSort(256), z3.BitVecSort(8))

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
    def origin(self):
        return z3.BitVec('ORIGIN<{}>'.format(self.name), 256)

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
