.DEFAULT_GOAL := help

.PHONY: help lint format typecheck test check

help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "  lint       ruff check src tests"
	@echo "  format     ruff format src tests"
	@echo "  typecheck  mypy src"
	@echo "  test       pytest"
	@echo "  check      lint + typecheck + test"

lint:
	uv run ruff check src tests

format:
	uv run ruff format src tests

typecheck:
	uv run mypy src

test:
	uv run pytest

check: lint typecheck test
