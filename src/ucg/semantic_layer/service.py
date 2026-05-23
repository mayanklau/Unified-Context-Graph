from ucg.graph.repository import GraphRepository
from ucg.semantic_layer.models import SemanticQueryRequest, SemanticQueryResponse

CONCEPT_KEYWORDS = {
    "risk": {"risk", "exposure", "impact", "critical", "quantification"},
    "privacy": {"privacy", "personal", "retention", "purpose", "obligation"},
    "identity": {"identity", "agent", "user", "service", "workload", "credential"},
    "policy": {"policy", "allow", "deny", "review", "control"},
    "llm_firewall": {"prompt", "response", "tool", "firewall", "injection"},
    "soc": {"incident", "alert", "finding", "evidence", "triage"},
}


class SemanticLayerService:
    def __init__(self, repository: GraphRepository) -> None:
        self.repository = repository

    def query(self, request: SemanticQueryRequest) -> SemanticQueryResponse:
        tokens = {token.strip(".,?!").lower() for token in request.query.split()}
        concepts = [
            concept
            for concept, keywords in CONCEPT_KEYWORDS.items()
            if tokens.intersection(keywords)
        ]
        if not concepts:
            concepts = ["context"]

        matched_nodes = []
        for node in self.repository.nodes(request.tenant_id):
            haystack = " ".join(
                [
                    node.id,
                    node.name,
                    node.type,
                    " ".join(str(value) for value in node.attributes.values()),
                ]
            ).lower()
            if any(token in haystack for token in tokens):
                matched_nodes.append(node.id)

        return SemanticQueryResponse(
            query=request.query,
            concepts=concepts,
            node_ids=matched_nodes[: request.limit],
            explanation="Matched query terms against canonical concepts and graph node metadata.",
        )
