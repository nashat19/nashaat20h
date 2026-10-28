from .enrich.correlate import Correlator
from .enrich import auto as auto_enrich

class Engine:
    async def scan(self, target, kind="auto", providers=None, on_result=None, progress=None):
        cor = Correlator(kind, target)
        seen = set()
        async for r in self._run_providers(target, kind, providers, progress):
            cor.ingest(r)
            if on_result: await on_result(r)
            # auto-enrich new nodes
            async for e in auto_enrich.expand(cor.graph, r, self.client):
                cor.ingest(e)
                if on_result: await on_result(e)
        # emit graph summary
        yield {"provider": "graph", "type": "graph", "value": json.dumps(cor.graph.to_dict())}
