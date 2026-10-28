.PHONY: install run verify test docker docker-down clean

install:
	./kali_install.sh

run:
	./run_web.sh

verify:
	./verify.sh

test:
	.venv/bin/python -m pytest -q tests/

docker:
	docker compose up -d --build

docker-down:
	docker compose down

clean:
	rm -rf .venv __pycache__ osintx/web/__pycache__ .pytest_cache
	find . -name '*.pyc' -delete
