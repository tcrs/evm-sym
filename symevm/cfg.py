import z3
import collections
from . import vm, util

def print_coverage(addr, cov):
    max_pc = max(e for _, e in cov.keys())
    rep = ['.'] * (max_pc + 1)
    for (start, end), v in cov.items():
        if v:
            c = str(v) if v <= 9 else '!'
            rep[start:end] = [c] * (end - start)
    print('0x{:x}: {}'.format(addr, ''.join(rep)))

def get_cfg(code, transaction, print_trace=True, verbose_coverage=True):
    coverage = {}
    def rectrace(node, solver, covered_jumpdests):
        try:
            vm.run_block(node, solver, log_trace=print_trace)
        except IndexError:
            node.end_type = 'stack error'
            node.end_info = []

        if verbose_coverage:
            coverage.setdefault(node.addr, collections.defaultdict(int))
            coverage[node.addr][(0, node.code.size())] = 0
            coverage[node.addr][(node.start_pc, node.pc)] += 1
            print()
            for addr, cov in coverage.items():
                print_coverage(addr, cov)
            print('ran 0x{:x}:0x{:x}'.format(node.start_pc, node.pc))

        if print_trace:
            for succ in node.successors:
                print('{} => {}'.format(z3.simplify(z3.And(*succ.predicates)), succ.start_pc))
            if len(node.successors) == 0:
                print('------------------ END OF THIS TRACE ------------')

        for succ in node.successors:
            if succ.start_pc in covered_jumpdests:
                print('Found back edge from {} -> {}, skipping for now'.format(node.start_pc, succ.start_pc))
            else:
                solver.push()
                solver.add(*succ.predicates)
                rectrace(succ, solver, covered_jumpdests | node.jumpdests)
                solver.pop()
        return node

    contract_state = transaction.initial_contract_state(transaction.address())

    root = vm.CFGNode({transaction.address(): contract_state}, transaction)
    # Note: allow executing code which is not from contract transaction.address()
    root.code = code
    root.storage = contract_state.storage
    root.balance = contract_state.balance
    root.gas = transaction.initial_gas()
    root.callinfo = vm.CallInfo(vm.MemRange(transaction.calldata(), 0, transaction.calldatasize()),
        transaction.initial_gas(), transaction.callvalue())
    root.addr = transaction.address()
    root.caller = transaction.origin()

    return rectrace(root, z3.Solver(), set())

def to_json(code, root):
    def recprint(elems, t, blockname):
        elems.append({'data': dict(id=blockname, content='\n'.join(util.disassemble(t.code, t.start_pc, t.pc)))})
        for i, succ in enumerate(t.successors):
            sname = blockname + '_' + str(i)
            recprint(elems, succ, sname)
            elems.append({'data': dict(source=blockname, target=sname, content=str(z3.simplify(z3.And(succ.predicates))))})
    e = []
    recprint(e, root, 'r')
    print(json.dumps(e, indent=2))

def to_dot(code, root, root_env=None, check_env=None, solver=None):
    def recprint(t, blockname):
        colour = 'black'
        if solver is not None:
            solver.push()
            solver.add(*[root_env.substitute(check_env, x) for x in t.predicates])
            if solver.check() == z3.sat:
                colour = 'green'
            else:
                colour = 'red'

        #print('subgraph x{:x} {{'.format(t.addr))
        #print('label="0x{:x}";'.format(t.addr))
        print('{}[color={},label="@@ 0x{:x} @@\n{}"];'.format(blockname, colour, t.addr, '\\n'.join(util.disassemble(t.code, t.start_pc, t.pc))))
        #print('}')
        if hasattr(t, 'retdata_off') and vm.is_concrete(t.retdata_sz):
            retlabel = ', '.join(str(z3.simplify(t.memory.select(t.retdata_off + i)))
                for i in range(t.retdata_sz.as_long()))
        else:
            retlabel = None
        for i, succ in enumerate(t.successors):
            sname = blockname + '_' + str(i)
            recprint(succ, sname)
            label = str(z3.simplify(z3.And(succ.predicates)))
            if retlabel is not None:
                label = label + '\nRETURN => ' + retlabel

            print('{} -> {} [label="{}"];'.format(blockname, sname, label))
        if not t.successors and retlabel is not None:
            print('{}_exit[color=black,label="X"];'.format(blockname));
            print('{} -> {}_exit [label="RETURN => {}"];'.format(blockname, blockname, retlabel))
        if solver is not None:
            solver.pop()

    print('digraph {')
    print('node [shape=box];')
    recprint(root, 'root')
    print('}')
