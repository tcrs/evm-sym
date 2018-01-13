from . import util

class Code:
    def __init__(self, code):
        self._code = code
        self._jumpdests = []
        i = 0
        while i < len(code):
            if code[i] == 0x5b:
                self._jumpdests.append(i)
            i += util.oplen(code[i])

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
