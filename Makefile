# ucpqc - Unicorn emulation framework for PQC firmware
#
#   make setup                     create .venv and install dependencies
#   make firmware                  build the default schemes from pqm4
#   make firmware SCHEME=<path>    build one scheme, e.g.
#                                  SCHEME=crypto_kem/ml-kem-768/m4fspeed
#   make test                      run the test suite
#   make demo                      roundtrip + profile of ML-DSA-44

PQM4    ?= ../pqm4
VENV    ?= .venv
PY      := $(VENV)/bin/python
TESTS   ?= test
PLATFORM?= mps2-an386

# Schemes built by `make firmware` with no SCHEME= given.  Add to this list to
# keep more targets around; nothing else in the framework needs changing.
SCHEMES ?= \
	crypto_sign/ml-dsa-44/m4f \
	crypto_sign/ml-dsa-65/m4f \
	crypto_kem/ml-kem-768/m4fspeed \
	mupq/pqclean/crypto_sign/ml-dsa-44/clean

DEFAULT_ELF := firmware/ml-dsa-44_m4f_test.elf

.PHONY: all setup firmware test demo schemes clean distclean

all: setup firmware

$(PY):
	python3 -m venv $(VENV)
	$(PY) -m pip install --quiet --upgrade pip
	$(PY) -m pip install --quiet -r requirements.txt

setup: $(PY)
	@$(PY) -c "import unicorn, capstone, elftools; \
		print('unicorn', unicorn.__version__, '/ capstone', capstone.__version__)"

firmware: setup
ifdef SCHEME
	$(PY) -m ucpqc build $(SCHEME) --pqm4 $(PQM4) --platform $(PLATFORM) --tests $(TESTS)
else
	@for scheme in $(SCHEMES); do \
		$(PY) -m ucpqc build $$scheme --pqm4 $(PQM4) --platform $(PLATFORM) --tests $(TESTS) || exit 1; \
	done
endif

schemes: setup
	@$(PY) -m ucpqc schemes $(PATTERN) --pqm4 $(PQM4)

test: setup
	$(PY) tests/run_tests.py

demo: setup
	$(PY) -m ucpqc roundtrip $(DEFAULT_ELF)
	@echo
	$(PY) -m ucpqc profile $(DEFAULT_ELF) --op sign --top 10

clean:
	rm -rf firmware/*.elf firmware/*.json
	find . -name __pycache__ -type d -exec rm -rf {} +

distclean: clean
	rm -rf $(VENV)
