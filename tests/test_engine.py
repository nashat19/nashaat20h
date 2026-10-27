import asyncio

import pytest

from osintx.config import Config
from osintx.engine import Engine
from osintx.models import Finding, Severity, Target, TargetType
from osintx.providers.base import BaseProvider, ProviderMeta
from osintx.storage import Storage

class DummyProvider(BaseProvider):
    meta = ProviderMeta(
        name="dummy",
        category="test",
        description="dummy",
        targets=("email",),
        timeout=5.0,
    )

    async def run(self, target):
        return [
            Finding(
                provider=self.name,
                category="test",
                title="hit",
                severity=Severity.LOW,
                data={"t": target.value},
            )
        ]

class FailingProvider(BaseProvider):
    meta = ProviderMeta(
        name="failing",
        category="test",
        description="fails",
        targets=("email",),
        timeout=5.0,
    )

    async def run(self, target):
        raise RuntimeError("boom")

@pytest.fixture()
def config(tmp_path):
    return Config(data_dir=tmp_path)

def test_engine_collects_findings(config):
    storage = Storage(config.db_path)
    engine = Engine(config, storage, [DummyProvider()])
    result = asyncio.run(engine.run(Target("a@b.co", TargetType.EMAIL)))
    assert len(result.findings) == 1
    assert result.findings[0].title == "hit"

def test_engine_survives_failure(config):
    storage = Storage(config.db_path)
    engine = Engine(config, storage, [FailingProvider()])
    result = asyncio.run(engine.run(Target("a@b.co", TargetType.EMAIL)))
    assert result.findings == []
    assert result.outcomes[0].ok is False
