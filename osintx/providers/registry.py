"""Auto-discovery of provider plugins."""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from typing import Iterable

from osintx.providers import base

PACKAGE = "osintx.providers"

def _walk(package_name: str) -> Iterable[str]:
    package = importlib.import_module(package_name)
    for info in pkgutil.walk_packages(package.__path__, prefix=f"{package_name}."):
        if info.ispkg:
            continue
        if info.name.rsplit(".", 1)[-1] in {"base", "registry"}:
            continue
        yield info.name

def discover() -> dict[str, type[base.BaseProvider]]:
    """Return {provider_name: class} for every concrete provider."""
    found: dict[str, type[base.BaseProvider]] = {}
    for module_name in _walk(PACKAGE):
        try:
            module = importlib.import_module(module_name)
        except Exception:  # pragma: no cover
            continue
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if not issubclass(obj, base.BaseProvider) or obj is base.BaseProvider:
                continue
            if inspect.isabstract(obj):
                continue
            meta = getattr(obj, "meta", None)
            if meta is None:
                continue
            found[meta.name] = obj
    return found

def build(names: list[str] | None = None, categories: list[str] | None = None) -> list[base.BaseProvider]:
    registry = discover()
    instances: list[base.BaseProvider] = []
    for name, cls in sorted(registry.items()):
        meta = cls.meta
        if names and name not in names:
            continue
        if categories and meta.category not in categories:
            continue
        if not meta.enabled_by_default and not names:
            continue
        instances.append(cls())
    return instances
