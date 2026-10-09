.PHONY: help test-py test-sol test lint vectors clean
help:
	@echo "make test-py   - Python unit tests (stdlib only, no installs)"
	@echo "make test-sol  - Foundry tests (needs: foundryup; forge install foundry-rs/forge-std)"
	@echo "make vectors   - print Merkle vectors used by Solidity tests"
	@echo "make test      - everything"

test-py:
	python3 -m unittest discover -s tests -t . -v

test-sol:
	cd contracts && forge test -vv

test: test-py test-sol

vectors:
	python3 tools/gen_vectors.py

clean:
	rm -rf contracts/out contracts/cache
