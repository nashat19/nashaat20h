# nashaat20h
Generated and deployed with APEXGODLY Coder

## Run locally

Requires Python 3.10 or later.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
osintx serve --reload
```

Open the web UI at <http://127.0.0.1:8000>. To configure optional API keys and settings, copy `env.example` to `.env` and edit it.

## Run with Docker

Docker Compose reads environment variables from `.env`, so create it before starting:

```bash
cp env.example .env
docker compose up --build
```

Open the web UI at <http://127.0.0.1:8000>. Stop the service with `Ctrl+C`.

## Development

Run the test suite and lint checks with:

```bash
pytest -q
ruff check osintx tests
```
