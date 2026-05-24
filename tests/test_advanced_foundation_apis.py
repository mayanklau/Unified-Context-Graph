from fastapi.testclient import TestClient

from ucg.main import app

client = TestClient(app)


def test_authorization_policy_points() -> None:
    denied = client.post(
        "/v1/authz/evaluate",
        json={
            "subject_id": "identity:analyst",
            "action": "delete",
            "resource_id": "asset:payments",
            "roles": ["analyst"],
        },
    )
    assert denied.status_code == 200
    assert denied.json()["outcome"] == "deny"
    assert "admin_role" in denied.json()["required_controls"]

    review = client.post(
        "/v1/authz/evaluate",
        json={
            "subject_id": "identity:analyst",
            "action": "read",
            "resource_id": "data:customers",
            "roles": ["analyst"],
            "data_classification": "personal_data",
        },
    )
    assert review.status_code == 200
    assert review.json()["outcome"] == "review"
    assert "purpose_binding" in review.json()["required_controls"]


def test_audit_event_capture_and_query() -> None:
    record = client.post(
        "/v1/audit/events",
        json={
            "id": "audit:advanced:1",
            "actor_id": "agent:triage",
            "action": "decision",
            "resource_id": "case:123",
            "outcome": "review",
        },
    )
    assert record.status_code == 200

    events = client.get("/v1/audit/events", params={"actor_id": "agent:triage"})
    assert events.status_code == 200
    assert any(event["id"] == "audit:advanced:1" for event in events.json()["events"])


def test_operations_developer_platform_and_ai_security() -> None:
    readiness = client.get("/v1/operations/readiness")
    assert readiness.status_code == 200
    assert readiness.json()["status"] == "degraded"

    contracts = client.get("/v1/developer-platform/connector-contracts")
    assert contracts.status_code == 200
    assert contracts.json()[0]["name"] == "normalized-event-connector"

    pack = client.get("/v1/ai-security/evaluation-packs/default")
    assert pack.status_code == 200
    assert {case["category"] for case in pack.json()["cases"]} >= {
        "prompt_injection",
        "data_exfiltration",
        "unsafe_tool_use",
    }

    summary = client.post("/v1/ai-security/evaluation-runs/summarize", json=pack.json())
    assert summary.status_code == 200
    assert summary.json()["case_count"] == len(pack.json()["cases"])
