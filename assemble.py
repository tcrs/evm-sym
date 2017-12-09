import sys
import collections
from ethereum import opcodes, utils

def pushbytes(v):
    be = utils.int_to_big_endian(v)
    n = len(be)
    if n == 0:
        # PUSH1 0
        return [0x60, 0]
    else:
        return [0x60 + n - 1] + [x for x in be]

class Ref:
    __slots__ = ('label',)
    def __init__(self, label):
        self.label = label

class Label:
    __slots__ = ('name', 'size', 'refs', 'push')
    def __init__(self, name):
        self.name, self.refs, self.size, self.push = name, [], 2, []

class Assembler:
    def __init__(self, lines=[]):
        self.code = []
        self.labels = {}
        for line in lines:
            self.add_line(line)

    #  - Each line is whitespace split into words
    #  - numbers are translated into push of appropriate size
    #  - =<word> is a jump dest
    #  - @<word> is a reference to a jump dest
    def add_line(self, line):
        line = line.strip()
        for word in line.split(' '):
            try:
                v = int(word, 0)
                pb = pushbytes(v)
                self.code.extend(pb)
            except ValueError:
                if word[0] == '=':
                    self.code.append(self.labels.setdefault(word[1:], Label(word[1:])))
                elif word[0] == '@':
                    v = self.labels.setdefault(word[1:], Label(word[1:]))
                    ref = Ref(v)
                    v.refs.append(ref)
                    self.code.append(ref)
                else:
                    op = opcodes.reverse_opcodes[word.upper()]
                    self.code.append(op)

    def assemble(self):
        # Size all jump dest pushes (iterative)
        # Jump dest pushes are sized based on the length in bytes of the jump
        # destination address, which can change depending on the size of the pushes in
        # code before it, so may have to go round this loop a few times...
        while 1:
            loc = 0
            for b in self.code:
                if isinstance(b, Ref):
                    loc += b.label.size
                else:
                    if isinstance(b, Label):
                        b.push = pushbytes(loc)
                        if len(b.push) != b.size:
                            b.size = len(b.push)
                            # Retry with new size
                            break
                    loc += 1
            else:
                break

        for b in self.code:
            if isinstance(b, Label):
                # JUMPDEST
                yield 0x5b
            elif isinstance(b, Ref):
                yield from b.label.push
            else:
                yield b

def assemble(code):
    return bytes(Assembler(code).assemble())

if __name__ == '__main__':
    asm = Assembler()
    with open(sys.argv[1], 'r') as f:
        for line in f:
            asm.add_line(line)

    # Write code out as a single big hex string
    for b in asm.assemble():
        sys.stdout.write('{:02x}'.format(b))
