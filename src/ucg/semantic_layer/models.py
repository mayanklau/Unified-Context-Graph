from pydantic import BaseModel, Field


class SemanticQueryRequest(BaseModel):
    query: str
    tenant_id: str = "default"
    limit: int = Field(default=10, ge=1, le=100)


class SemanticQueryResponse(BaseModel):
    query: str
    concepts: list[str]
    node_ids: list[str]
    explanation: str
