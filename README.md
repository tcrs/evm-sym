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

## Ethereum tests

	git checkout https://github.com/ethereum/tests.git
	python3 test_harness.py tests/VMTests/vmArithmeticTest/*.json

Currently the test harness is WIP - it won't be properly testing the results of
all types of test are actually correct! The artithmetic tests are pretty well
checked at the moment. Running other tests are useful to at least check the
execution engine doesn't crash.

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
