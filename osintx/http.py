"""Resilient async HTTP client with retries, backoff and rate limiting."""

from __future__ import annotations

import asyncio
import random
from typing import Any

import httpx

from osintx.config import Config
from osintx.ratelimit import TokenBucket

RETRY_STATUS = {408, 425, 429, 500, 502, 503, 504}

class HttpError(RuntimeError):
    pass

class HttpClient:
    def __init__(self, config: Config) -> None:
        self.config = config
        self._bucket = TokenBucket(config.global_rate, burst=max(4, int(config.global_rate)))
        timeout = httpx.Timeout(config.timeout, connect=config.connect_timeout)
        limits = httpx.Limits(
            max_connections=config.concurrency * 2,
            max_keepalive_connections=config.concurrency,
        )
        self._client = httpx.AsyncClient(
            timeout=timeout,
            limits=limits,
            follow_redirects=config.follow_redirects,
            verify=config.verify_tls,
            proxy=config.proxy or None,
            headers={"User-Agent": random.choice(config.user_agents)},
        )

    async def __aenter__(self) -> "HttpClient":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    # ------------------------------------------------------------------
    def _headers(self, extra: dict[str, str] | None) -> dict[str, str]:
        headers = {"User-Agent": random.choice(self.config.user_agents)}
        if extra:
            headers.update(extra)
        return headers

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        json: Any = None,
        data: Any = None,
        auth: tuple[str, str] | None = None,
        allow_status: tuple[int, ...] = (),
    ) -> httpx.Response:
        if self.config.offline:
            raise HttpError("offline mode")

        last_error: Exception | None = None
        for attempt in range(self.config.retries + 1):
            await self._bucket.acquire()
            try:
                response = await self._client.request(
                    method,
                    url,
                    headers=self._headers(headers),
                    params=params,
                    json=json,
                    data=data,
                    auth=auth,
                )
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_error = exc
            else:
                if response.status_code in allow_status:
                    return response
                if response.status_code not in RETRY_STATUS:
                    return response
                last_error = HttpError(f"HTTP {response.status_code} for {url}")
                retry_after = response.headers.get("Retry-After")
                if retry_after and retry_after.isdigit():
                    await asyncio.sleep(min(float(retry_after), 30.0))
            if attempt < self.config.retries:
                delay = self.config.backoff_base * (2 ** attempt)
                await asyncio.sleep(delay + random.uniform(0, delay / 2))
        raise HttpError(str(last_error) if last_error else "request failed")

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def get_json(self, url: str, **kwargs: Any) -> Any:
        response = await self.get(url, **kwargs)
        try:
            return response.json()
        except ValueError as exc:
            raise HttpError(f"invalid JSON from {url}") from exc
