from datetime import UTC, datetime

from ucg.connectors.models import ConnectorHealth, ConnectorRegistration, ConnectorStatus


class ConnectorRegistry:
    def __init__(self) -> None:
        self._connectors: dict[tuple[str, str], ConnectorRegistration] = {}

    def register(self, connector: ConnectorRegistration) -> ConnectorRegistration:
        self._connectors[(connector.tenant_id, connector.id)] = connector
        return connector

    def list(self, tenant_id: str) -> list[ConnectorRegistration]:
        return [
            connector
            for (connector_tenant, _), connector in self._connectors.items()
            if connector_tenant == tenant_id
        ]

    def health(self, connector_id: str, tenant_id: str) -> ConnectorHealth | None:
        connector = self._connectors.get((tenant_id, connector_id))
        if connector is None:
            return None
        freshness = int((datetime.now(UTC) - connector.last_seen_at).total_seconds())
        return ConnectorHealth(
            connector_id=connector.id,
            status=connector.status,
            freshness_seconds=max(freshness, 0),
            coverage={
                "node_types": len(connector.supported_node_types),
                "edge_types": len(connector.supported_edge_types),
            },
        )

    def mark_error(self, connector_id: str, tenant_id: str) -> ConnectorRegistration | None:
        connector = self._connectors.get((tenant_id, connector_id))
        if connector is None:
            return None
        updated = connector.model_copy(update={"status": ConnectorStatus.ERROR})
        self._connectors[(tenant_id, connector_id)] = updated
        return updated
