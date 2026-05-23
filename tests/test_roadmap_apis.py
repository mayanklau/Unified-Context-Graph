from fastapi.testclient import TestClient

from ucg.main import app

client = TestClient(app)


def test_connector_evidence_control_and_capability_apis() -> None:
    capabilities = client.get("/v1/capabilities")
    assert capabilities.status_code == 200
    assert any(area["name"] == "Trust DLP" for area in capabilities.json())

    connector = client.post(
        "/v1/connectors",
        json={
            "id": "connector:siem",
            "name": "SIEM",
            "source_type": "siem",
            "owner": "security-platform",
            "supported_node_types": ["incident", "finding"],
        },
    )
    assert connector.status_code == 200

    health = client.get("/v1/connectors/connector:siem/health")
    assert health.status_code == 200
    assert health.json()["status"] == "active"

    evidence = client.post(
        "/v1/evidence",
        json={
            "id": "evidence:1",
            "kind": "log",
            "title": "Alert log",
            "source": "siem",
            "subject_ids": ["incident:1"],
        },
    )
    assert evidence.status_code == 200

    package = client.get("/v1/evidence/packages/incident:1")
    assert package.status_code == 200
    assert package.json()["evidence"][0]["id"] == "evidence:1"

    control = client.post(
        "/v1/controls",
        json={
            "control_id": "control:dlp-review",
            "framework": "SOC 2",
            "requirement": "CC6.1",
            "status": "effective",
            "evidence_node_ids": ["evidence:1"],
        },
    )
    assert control.status_code == 200

    assessment = client.get("/v1/controls/control:dlp-review/assessment")
    assert assessment.status_code == 200
    assert assessment.json()["status"] == "effective"


def test_agent_trust_dlp_privacy_and_risk_scenario_apis() -> None:
    agent_decision = client.post(
        "/v1/agents/actions/evaluate",
        json={
            "agent_id": "agent:triage",
            "action": "delete",
            "target_id": "asset:payments",
            "risk_score": 72,
            "data_classification": "restricted",
            "tool_name": "edr",
        },
    )
    assert agent_decision.status_code == 200
    assert agent_decision.json()["policy_decision"]["outcome"] == "review"

    dlp = client.post(
        "/v1/trust-dlp/evaluate",
        json={
            "signal": {
                "id": "dlp:1",
                "actor_id": "agent:triage",
                "source_id": "data:customers",
                "destination": "external-email",
                "surface": "tool_call",
                "data_categories": ["customer_pii"],
                "purpose": "support",
            },
            "policies": [
                {
                    "id": "policy:pii",
                    "name": "PII policy",
                    "sensitive_categories": ["customer_pii"],
                    "allowed_purposes": ["support"],
                    "blocked_destinations": ["external-email"],
                    "required_controls": ["manager_review"],
                }
            ],
        },
    )
    assert dlp.status_code == 200
    assert dlp.json()["decision"] == "block"

    privacy = client.post(
        "/v1/privacy/obligations/evaluate",
        json={
            "activity_id": "processing:crm",
            "purpose": "support",
            "data_categories": ["email"],
            "subject_categories": ["customer"],
            "transfer_regions": ["EU", "US"],
        },
    )
    assert privacy.status_code == 200
    assert "cross_border_transfer_review" in privacy.json()["obligations"]

    scenario = client.post(
        "/v1/risk/scenarios",
        json={
            "scenario_id": "scenario:ransomware",
            "name": "Ransomware",
            "target_ids": ["asset:payments"],
            "likelihood": 0.8,
            "impact": 0.9,
            "control_strength": 0.4,
            "annualized_loss_exposure": 1250000,
        },
    )
    assert scenario.status_code == 200
    assert scenario.json()["tier"] == "high"


def test_graph_paths_api() -> None:
    first = client.post(
        "/v1/ingest/events",
        json={
            "source": "test",
            "event_type": "identity.access",
            "actor": {"id": "identity:alice", "type": "identity", "name": "Alice"},
            "object": {"id": "asset:payments", "type": "asset", "name": "Payments"},
            "relationship": "accesses",
        },
    )
    assert first.status_code == 200

    second = client.post(
        "/v1/ingest/events",
        json={
            "source": "test",
            "event_type": "asset.stores",
            "actor": {"id": "asset:payments", "type": "asset", "name": "Payments"},
            "object": {"id": "data:customers", "type": "data_set", "name": "Customers"},
            "relationship": "stores",
        },
    )
    assert second.status_code == 200

    paths = client.get(
        "/v1/graph/paths",
        params={
            "source_id": "identity:alice",
            "target_id": "data:customers",
            "max_depth": 3,
        },
    )
    assert paths.status_code == 200
    assert paths.json()[0]["node_ids"] == [
        "identity:alice",
        "asset:payments",
        "data:customers",
    ]
