from . import util

class Code:
    def __init__(self, code):
        self._code = util.hex_to_bytes(code)
        self._jumpdests = self._find_jumpdests()

    def _find_jumpdests(self):
        jd = []
        i = 0
        while i < len(self._code):
            if self._code[i] == 0x5b:
                jd.append(i)
            i += util.oplen(self._code[i])
        return jd

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
