.PHONY: install dev test lint run docker clean

install:
	pip install -r requirements.txt && pip install -e .

dev:
	pip install -e ".[dev]"

test:
	pytest -q

lint:
	ruff check osintx tests

run:
	osintx serve --reload

docker:
	docker compose up --build

clean:
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache
