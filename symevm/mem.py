import z3
import copy
import collections
from . import state

class Memory:
    def __init__(self, base=state.MemoryEmpty, base_idx=None):
        self._mem = base
        self._idx = base_idx

    def select(self, idx):
        expr = z3.Select(self._mem, idx)
        if self._idx is not None:
            expr = z3.substitute(expr, (self._idx, idx))
        return expr

    def store(self, idx, val):
        self._mem = z3.Store(self._mem, idx, val)

    def overlay(self, chunk, base_off, chunk_off, length):
        slen = z3.simplify(length)
        if z3.is_bv_value(slen):
            for i in range(slen.as_long()):
                if isinstance(chunk, Memory):
                    sel = chunk.select(chunk_off + i)
                else:
                    sel = z3.Select(chunk, chunk_off + i)
                self._mem = z3.Store(self._mem, base_off + i, sel)
        else:
            if self._idx is None:
                self._idx = z3.BitVec('idx', 256)
            if isinstance(chunk, Memory):
                chunk_val = chunk.select(self._idx - base_off + chunk_off)
            else:
                chunk_val = z3.Select(chunk, self._idx - base_off + chunk_off)
            self._mem = z3.If(
                z3.And(self._idx >= base_off, self._idx < base_off + length),
                z3.Store(state.MemoryEmpty, self._idx, chunk_val),
                self._mem)

    def __copy__(self):
        if self._idx is None:
            return Memory(base=self._mem)
        else:
            ni = z3.BitVec('idx', 256)
            nm = z3.substitute(self._mem, (self._idx, ni))
            return Memory(base=nm, base_idx=ni)
