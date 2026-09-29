.DEFAULT_GOAL := help
VENV := .venv
PY   := $(VENV)/bin/python
DEV_DB  := postgresql+psycopg://advisory_hub:advisory_hub_dev@localhost:5432/advisory_hub
TEST_DB := postgresql+psycopg://advisory_hub:advisory_hub_dev@localhost:5432/advisory_hub_test

export DATABASE_URL      ?= $(DEV_DB)
export TEST_DATABASE_URL ?= $(TEST_DB)
export SECRET_KEY        ?= local-development-secret-key-not-for-production

help:  ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

venv:  ## Create the virtualenv and install dependencies
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install -q --upgrade pip
	$(VENV)/bin/pip install -e ".[dev]"

up:  ## Start postgres + redis
	docker compose up -d postgres redis

down:  ## Stop all services
	docker compose down

migrate:  ## Apply migrations to the dev database
	$(VENV)/bin/alembic upgrade head

testdb:  ## (Re)create the test database
	docker compose exec -T postgres psql -U advisory_hub -d postgres \
	  -c "DROP DATABASE IF EXISTS advisory_hub_test;" >/dev/null
	docker compose exec -T postgres psql -U advisory_hub -d postgres \
	  -c "CREATE DATABASE advisory_hub_test;" >/dev/null
	@echo "test database ready"

test:  ## Run the test suite
	$(PY) -m pytest

lint:  ## ruff check + format check
	$(VENV)/bin/ruff check advisory_hub tests migrations
	$(VENV)/bin/ruff format --check advisory_hub tests migrations

fmt:  ## Auto-fix and format
	$(VENV)/bin/ruff check --fix advisory_hub tests migrations
	$(VENV)/bin/ruff format advisory_hub tests migrations

types:  ## mypy strict
	$(VENV)/bin/mypy advisory_hub

check: lint types test  ## Everything CI runs

serve:  ## Run the app locally with reload
	$(VENV)/bin/uvicorn advisory_hub.main:app --reload --port 8000

images:  ## Build both images locally under the names compose expects
	docker build -f docker/Dockerfile       -t $${IMAGE_NAMESPACE:-localhost}/advisory-hub:$${IMAGE_TAG:-latest} .
	docker build -f docker/nginx/Dockerfile -t $${IMAGE_NAMESPACE:-localhost}/advisory-hub-proxy:$${IMAGE_TAG:-latest} .

admin:  ## Create an administrator account
	$(PY) -m advisory_hub.cli create-admin

.PHONY: help venv up down migrate testdb test lint fmt types check serve images admin
