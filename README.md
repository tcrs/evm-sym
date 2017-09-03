# Install

Install required packages (use a python virtualenv):

	virtualenv -p python3 env
	source env/bin/activate
	pip install -r requirements.txt

Install z3 (not available through pip)

	git clone https://github.com/Z3Prover/z3.git

Following their instructions for python (check these are still current) whilst
the virtualenv is active

	cd z3
	python scripts/mk_make.py --python
	cd build
	make
	make install
