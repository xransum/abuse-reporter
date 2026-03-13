.DEFAULT_GOAL := help

.PHONY: help pre-commit lint format typecheck test build check

help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "  pre-commit  pre-commit run --all-files (lint + format + file checks)"
	@echo "  lint        ruff check src tests"
	@echo "  format      ruff format src tests"
	@echo "  typecheck   mypy src"
	@echo "  test        pytest"
	@echo "  build       uv build"
	@echo "  check       pre-commit -> typecheck -> test -> build"

pre-commit:
	scripts/run pre-commit

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
