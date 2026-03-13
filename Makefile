.DEFAULT_GOAL := help

.PHONY: help lint format typecheck test build check

help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "  lint       ruff check src tests"
	@echo "  format     ruff format src tests"
	@echo "  typecheck  mypy src"
	@echo "  test       pytest"
	@echo "  build      uv build"
	@echo "  check      format -> lint -> typecheck -> test -> build"

lint:
	scripts/run lint

format:
	scripts/run format

typecheck:
	scripts/run typecheck

test:
	scripts/run test

build:
	scripts/run build

check:
	scripts/run all
