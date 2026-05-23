from ucg.graph.ontology import EdgeType, NodeType
from ucg.graph.repository import InMemoryGraphRepository
from ucg.ingestion.models import EntityRef, IngestionEvent
from ucg.ingestion.service import IngestionService


def test_ingestion_upserts_nodes_and_context() -> None:
    repository = InMemoryGraphRepository()
    service = IngestionService(repository)
    result = service.ingest(
        IngestionEvent(
            source="agentic-soc",
            event_type="agent.action",
            actor=EntityRef(id="agent:triage", type=NodeType.AGENT, name="Triage Agent"),
            object=EntityRef(id="asset:payments", type=NodeType.ASSET, name="Payments API"),
            relationship=EdgeType.OBSERVED,
            attributes={"severity": "high"},
        )
    )

    context = repository.context("asset:payments", "default", depth=1)

    assert result.edge_id.startswith("edge:")
    assert {node.id for node in context.nodes} == {"agent:triage", "asset:payments"}
    assert len(context.edges) == 1
