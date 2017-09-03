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
        self.name, self.refs, self.size, self.push = name, [], 2, b''

code = []
labels = {}

# Read asm input:
#  - Each line is whitespace split into words
#  - numbers are translated into push of appropriate size
#  - =<word> is a jump dest
#  - @<word> is a reference to a jump dest
with open(sys.argv[1], 'r') as f:
    for line in f:
        line = line.strip()
        for word in line.split(' '):
            try:
                v = int(word, 0)
                code.extend(pushbytes(v))
            except ValueError:
                if word[0] == '=':
                    code.append(labels.setdefault(word[1:], Label(word[1:])))
                elif word[0] == '@':
                    v = labels.setdefault(word[1:], Label(word[1:]))
                    ref = Ref(v)
                    v.refs.append(ref)
                    code.append(ref)
                else:
                    op = opcodes.reverse_opcodes[word.upper()]
                    code.append(op)

# Size all jump dest pushes (iterative)
# Jump dest pushes are sized based on the length in bytes of the jump
# destination address, which can change depending on the size of the pushes in
# code before it, so may have to go round this loop a few times...
while 1:
    loc = 0
    for b in code:
        if isinstance(b, Ref):
            loc += b.label.size
        else:
            if isinstance(b, Label):
                pb = pushbytes(loc)
                if len(pb) != b.size:
                    b.size = len(pb)
                    # Retry with new size
                    break
                else:
                    b.push = ''.join('{:02x}'.format(x) for x in pb)
            loc += 1
    else:
        break

# Write out code as a big hex string
for b in code:
    if isinstance(b, Label):
        # JUMPDEST
        sys.stdout.write('5b')
    elif isinstance(b, Ref):
        sys.stdout.write(b.label.push)
    else:
        sys.stdout.write('{:02x}'.format(b))
