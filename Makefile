.PHONY: test lint help build sdist wheel clean install-sudo uninstall-sudo

help:
	@echo "Targets:"
	@echo "  make test   - run the test suite"
	@echo "  make build  - build source and wheel distributions"
	@echo "  make clean  - remove build artifacts"
	@echo "  make install-sudo   - install sudo-compatible wrappers"
	@echo "  make uninstall-sudo - remove sudo-compatible wrappers"

test:
	PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests -q

build:
	python -m build

sdist:
	python -m build --sdist

wheel:
	python -m build --wheel

clean:
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache

install-sudo:
	sudo bash scripts/install-sudo-wrapper.sh

uninstall-sudo:
	sudo bash scripts/uninstall-sudo-wrapper.sh
