.PHONY: install dev test test-fast test-perf lint format coverage build docker clean help

PYTHON ?= python
IMAGE ?= kuberoast
TAG ?= latest

help:
	@echo "Available targets:"
	@echo "  install    Install package (production)"
	@echo "  dev        Install package with dev dependencies"
	@echo "  test       Run all pytest tests"
	@echo "  test-fast  Run pytest excluding performance tests"
	@echo "  test-perf  Run only performance regression tests"
	@echo "  coverage   Run pytest with coverage"
	@echo "  lint       Run ruff lint checks"
	@echo "  format     Auto-format code with ruff"
	@echo "  build      Build wheel + sdist into dist/"
	@echo "  docker     Build Docker image ($(IMAGE):$(TAG))"
	@echo "  clean      Remove build artifacts"

install:
	$(PYTHON) -m pip install .

dev:
	$(PYTHON) -m pip install -e ".[dev]"

test:
	$(PYTHON) -m pytest -v

test-fast:
	$(PYTHON) -m pytest -v -m "not performance"

test-perf:
	$(PYTHON) -m pytest -v -m performance

coverage:
	$(PYTHON) -m pytest --cov=kuberoast --cov-report=term-missing --cov-report=html

lint:
	$(PYTHON) -m ruff check kuberoast tests
	$(PYTHON) -m ruff format --check kuberoast tests

format:
	$(PYTHON) -m ruff format kuberoast tests
	$(PYTHON) -m ruff check --fix kuberoast tests

build:
	$(PYTHON) -m pip install --upgrade build
	$(PYTHON) -m build

docker:
	docker build -t $(IMAGE):$(TAG) .

clean:
	rm -rf build dist *.egg-info .pytest_cache .coverage htmlcov coverage.xml
	find . -type d -name __pycache__ -exec rm -rf {} +
