from ucg.graph.models import GraphEdge, GraphNode, Provenance
from ucg.graph.repository import GraphRepository
from ucg.ingestion.models import IngestionEvent, IngestionResult


class IngestionService:
    def __init__(self, repository: GraphRepository) -> None:
        self.repository = repository

    def ingest(self, event: IngestionEvent) -> IngestionResult:
        actor = GraphNode(
            id=event.actor.id,
            type=event.actor.type,
            name=event.actor.name,
            tenant_id=event.tenant_id,
            attributes=event.actor.attributes,
            sources=[event.source],
        )
        obj = GraphNode(
            id=event.object.id,
            type=event.object.type,
            name=event.object.name,
            tenant_id=event.tenant_id,
            attributes=event.object.attributes,
            sources=[event.source],
        )
        self.repository.upsert_node(actor)
        self.repository.upsert_node(obj)

        edge = GraphEdge(
            id=GraphEdge.deterministic_id(
                tenant_id=event.tenant_id,
                edge_type=event.relationship,
                source_id=event.actor.id,
                target_id=event.object.id,
                source=event.source,
            ),
            type=event.relationship,
            source_id=event.actor.id,
            target_id=event.object.id,
            tenant_id=event.tenant_id,
            confidence=event.confidence,
            attributes={"event_type": event.event_type, **event.attributes},
            provenance=Provenance(source=event.source, source_record_id=event.source_record_id),
            observed_at=event.observed_at,
        )
        self.repository.upsert_edge(edge)
        return IngestionResult(
            node_ids=[actor.id, obj.id],
            edge_id=edge.id,
            tenant_id=event.tenant_id,
        )
