import z3

MemorySort = z3.ArraySort(z3.BitVecSort(256), z3.BitVecSort(8))
StorageSort = z3.ArraySort(z3.BitVecSort(256), z3.BitVecSort(256))

MemoryEmpty = z3.K(z3.BitVecSort(256), z3.BitVecVal(0, 8))
StorageEmpty = z3.K(z3.BitVecSort(256), z3.BitVecVal(0, 256))

def cached(fn):
    def wrapper(self, *args):
        if fn.__name__ not in self._cache:
            self._cache[fn.__name__] = fn(self, *args)
        return self._cache[fn.__name__]
    return wrapper

def storage_empty_policy(name, addr):
    return StorageEmpty

def storage_any_policy(name, addr):
    return z3.Const('Storage<{}:{:x}>'.format(name, addr), StorageSort)

def storage_specified_policy(storages, sub_policy):
    def policy(name, addr):
        if addr in storages:
            return storages[addr]
        else:
            return sub_policy(name, addr)
    return policy

class TransactionState:
    def __init__(self, name, address, initial_storage_policy=storage_empty_policy, **kwargs):
        self._cache = {}
        for name, val in kwargs.items():
            assert hasattr(self, name), name
            self._cache[name] = val

        self.name = name
        self._address = address
        self._storage_policy = initial_storage_policy
        self._initial_storage = {}

    # Differs from z3.substitute in that it can substitute functions (which is
    # required as a few of the environment things are functions). Modified
    # version of python code from:
    # https://stackoverflow.com/questions/15236450/substituting-function-symbols-in-z3-formulas
    # also based somewhat on the z3 substitute implementation:
    # https://github.com/Z3Prover/z3/blob/master/src/ast/rewriter/expr_safe_replace.cpp
    def substitute(self, other, expr):
        cache = z3.AstMap(ctx=expr.ctx)

        for k, v in self._initial_storage.items():
            cache[v] = other.initial_storage(k)

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

    def initial_storage(self, addr):
        if addr not in self._initial_storage:
            self._initial_storage[addr] = self._storage_policy(self.name, addr)
        return self._initial_storage[addr]

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
