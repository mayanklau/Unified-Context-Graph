from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query

from ucg.api.dependencies import get_connector_registry
from ucg.connectors.models import ConnectorHealth, ConnectorRegistration
from ucg.connectors.service import ConnectorRegistry

router = APIRouter()


@router.post("", response_model=ConnectorRegistration)
def register_connector(
    connector: ConnectorRegistration,
    registry: Annotated[ConnectorRegistry, Depends(get_connector_registry)],
) -> ConnectorRegistration:
    return registry.register(connector)


@router.get("", response_model=list[ConnectorRegistration])
def list_connectors(
    registry: Annotated[ConnectorRegistry, Depends(get_connector_registry)],
    tenant_id: str = Query("default"),
) -> list[ConnectorRegistration]:
    return registry.list(tenant_id)


@router.get("/{connector_id}/health", response_model=ConnectorHealth)
def connector_health(
    connector_id: str,
    registry: Annotated[ConnectorRegistry, Depends(get_connector_registry)],
    tenant_id: str = Query("default"),
) -> ConnectorHealth:
    health = registry.health(connector_id, tenant_id)
    if health is None:
        raise HTTPException(status_code=404, detail="Connector not found")
    return health
