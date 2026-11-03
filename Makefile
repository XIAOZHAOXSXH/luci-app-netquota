PYTHON ?= python
.PHONY: all build test
all: build
build:
	$(PYTHON) tools/build_ipk.py
test:
	$(PYTHON) -m unittest discover -s tests -p "test_*.py"
