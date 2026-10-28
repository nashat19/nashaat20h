FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    OSINTX_HOST=0.0.0.0 \
    OSINTX_PORT=8000

WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends whois dnsutils curl \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements-web.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r requirements-web.txt

COPY . .

RUN useradd -m -u 10001 osintx && chown -R osintx:osintx /app
USER osintx

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD curl -fsS http://127.0.0.1:8000/api/health || exit 1

CMD ["python", "-m", "uvicorn", "osintx.web.app:app", "--host", "0.0.0.0", "--port", "8000"]
