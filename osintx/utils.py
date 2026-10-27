"""Helpers: target detection, masking, hashing, formatting."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Iterable, Iterator, TypeVar

from osintx.models import Target, TargetType

T = TypeVar("T")

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
PHONE_RE = re.compile(r"^\+?[0-9][0-9\s\-().]{5,18}$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
USERNAME_RE = re.compile(r"^[A-Za-z0-9._\-]{2,40}$")

def detect_type(value: str) -> TargetType:
    value = value.strip()
    if not value:
        return TargetType.UNKNOWN
    if EMAIL_RE.match(value):
        return TargetType.EMAIL
    try:
        ipaddress.ip_address(value)
        return TargetType.IP
    except ValueError:
        pass
    if value.startswith("+") or (PHONE_RE.match(value) and not DOMAIN_RE.match(value)):
        digits = re.sub(r"\D", "", value)
        if 7 <= len(digits) <= 15:
            return TargetType.PHONE
    if DOMAIN_RE.match(value) and "." in value:
        return TargetType.DOMAIN
    if USERNAME_RE.match(value):
        return TargetType.USERNAME
    return TargetType.UNKNOWN

def make_target(value: str, forced: str | None = None) -> Target:
    value = value.strip()
    if forced and forced != "auto":
        return Target(value=value, type=TargetType(forced))
    return Target(value=value, type=detect_type(value))

def normalize_phone(value: str, default_region: str = "IQ") -> str:
    digits = re.sub(r"[^\d+]", "", value)
    if digits.startswith("00"):
        digits = "+" + digits[2:]
    if not digits.startswith("+"):
        digits = "+" + digits
    return digits

def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def md5(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()

def mask(value: str, keep: int = 3) -> str:
    if len(value) <= keep * 2:
        return value
    return f"{value[:keep]}{'*' * (len(value) - keep * 2)}{value[-keep:]}"

def chunked(items: Iterable[T], size: int) -> Iterator[list[T]]:
    bucket: list[T] = []
    for item in items:
        bucket.append(item)
        if len(bucket) >= size:
            yield bucket
            bucket = []
    if bucket:
        yield bucket

def dedupe(items: Iterable[T], key=lambda x: x) -> list[T]:
    seen: set = set()
    out: list[T] = []
    for item in items:
        marker = key(item)
        if marker in seen:
            continue
        seen.add(marker)
        out.append(item)
    return out

def human_seconds(seconds: float) -> str:
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, rest = divmod(seconds, 60)
    return f"{int(minutes)}m{rest:.0f}s"

def truncate(text: str, limit: int = 160) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"
