# Ethereum Virtual Machine static analysis tool

Very much work-in-progress!

`evm.py` is a rather hacky driver for the `symevm` library, which can output a
control flow graph (CFG) in either JSON or dot format. There is also some basic
support for attempting to find sequences of contract calls which will reach
nodes in the CFG satisfying some critera. This is the start of automatic
fault-finding, but it not complete in any way yet.

The input is a JSON file encoding the relevant initial state of the Ethereum
system for analysis. See `examples/parity-wallet.json` for an example; the
`entry` attribute specifies the contract address to start analysis from.
`contracts` is a mapping from contract address to its state.

## Experimental UI

There is a HTTP REST server:

	python3 server.py

then open `web/ui.html` in a browser

	chromium web/ui.html

Click on a contract address in the top left to see its disassembly and an
interactive control-flow graph on the right.

Currently the only way to change which contracts are loaded is by changing
`new_session` in `server.py` to load a different json file...

# Tools

## Ethereum tests

	git checkout https://github.com/ethereum/tests.git
	python3 test_harness.py tests/VMTests/vmArithmeticTest/*.json

Currently the test harness is WIP - it won't be properly testing the results of
all types of test are actually correct! The artithmetic tests are pretty well
checked at the moment. Running other tests are useful to at least check the
execution engine doesn't crash.

## Assembler & Disassembler

`assemble.py` will assemble to EVM bytecode from a simple assembly format. Lines
are split on whitespace, numbers are assembled to PUSH bytecodes of minimum size
for the number, =name declares a named jump destination, @name resolves to a
PUSH of the address of the named jump destination. Everything else must be a
bytecode name. E.g.

	1 31 0 CALLDATACOPY
	0 MLOAD
	DUP1 SLOAD
	@a JUMPI
	DUP1 SSTORE
	STOP
	=a
	STOP

`disassemble.py` will output a more basic assembly listing from an input EVM
bytecode string.

Note that currently the output of `dissasemble.py` cannot be assembled by
`assembly.py`...

## Infura

`infura.py` provides a very simple command line interface for [infura][infura].
e.g.

	./infura.py code 0x459F7854776ED005B6Ec63a88F834fDAB0B6993e

will output the code for the given contract address.

# Install

Install z3 (not available through pip) -- use a virtualenv

	virtualenv -p python3 env
	source env/bin/activate

Following their instructions for python (check these are still current):

	git clone https://github.com/Z3Prover/z3.git
	cd z3
	python scripts/mk_make.py --python
	cd build
	make
	make install

To use the [infura][infura] APIs:

	pip install requests

[infura]: https://infura.io/

# TODO

 - Accurate Gas model, with trace end on out-of-gas
   - Model memory gas cost (track max index of touched memory words)
   - Model call gas cost
   - Call and selfdestruct gas cost depends on whether target contract exists
 - Model refund counter
 - Loop handling, can handle loops by tracing but this is currently disabled as
   the tracer can get stuck in an infinite loop quite easily. This would
   probably practical to re-enable when the Gas model is implemented properly,
   as looping traces will terminate eventually with out-of-gas.
 - Better support for the etherum tests
 - Express to Z3 that we want to assume sha(a) == sha(b) iff a == b
 - More efficient Memory model. Z3 does not support an extended array theory
   which includes copies ([see here][ext-arry]). These are required for
   CALLDATACOPY (and probably RETURNDATACOPY) with non-concrete size arguments.
   I have seen this in contracts which forward call data to another contract
   (via a delegate call), copying CALLDATASIZE bytes into memory and passing
   that on through the call. I have implemented something relatively simple in
   `mem.py`, but it turns out to be very slow to solve :(.

[ext-array]: http://smt2012.loria.fr/paper1.pdf
