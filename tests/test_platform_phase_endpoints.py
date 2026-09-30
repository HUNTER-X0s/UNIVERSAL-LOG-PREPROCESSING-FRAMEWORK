"""Tests for the new Phase modules API endpoints:
- GET /api/v1/parsers
- GET /api/v1/parsers/{parser_id}
- POST /api/v1/parsers/test
- GET /api/v1/schemas
- GET /api/v1/schemas/{schema_id}
"""

import pytest
from fastapi.testclient import TestClient
from ulpf_api.app import app


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def test_list_parsers(client: TestClient) -> None:
    resp = client.get("/api/v1/parsers", headers={"X-Role": "operator"})
    assert resp.status_code == 200
    data = resp.json()
    assert "count" in data
    assert "parsers" in data
    assert data["count"] >= 15
    assert len(data["parsers"]) == data["count"]
    # Check parser structure
    first = data["parsers"][0]
    assert "parser_id" in first
    assert "name" in first
    assert "vendor" in first
    assert "tier" in first
    assert "priority" in first


def test_list_parsers_filtered(client: TestClient) -> None:
    resp = client.get("/api/v1/parsers?tier=A", headers={"X-Role": "operator"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] > 0
    for p in data["parsers"]:
        assert p["tier"] == "A"


def test_get_parser_detail(client: TestClient) -> None:
    resp = client.get("/api/v1/parsers/parser.generic.json", headers={"X-Role": "operator"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["parser_id"] == "parser.generic.json"
    assert data["format"] == "json"


def test_get_parser_not_found(client: TestClient) -> None:
    resp = client.get("/api/v1/parsers/parser.nonexistent.xyz", headers={"X-Role": "operator"})
    assert resp.status_code == 404


def test_parse_json_payload(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/parsers/test",
        headers={"X-Role": "operator"},
        json={"raw_payload": '{"event_id": "test-123", "user": "admin", "action": "login"}'},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["preview"] is True
    assert data["parsed"] is True
    assert "fields" in data
    assert data["fields"].get("user") == "admin"


def test_parse_cef_payload(client: TestClient) -> None:
    cef_log = "CEF:0|Security|ThreatDetector|1.0|100|Exploit Attempt|8|src=192.168.1.50 dst=10.0.0.1 act=blocked"
    resp = client.post(
        "/api/v1/parsers/test",
        headers={"X-Role": "operator"},
        json={"raw_payload": cef_log},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["preview"] is True
    assert data["parsed"] is True
    assert data["format"] == "cef"


def test_list_schemas(client: TestClient) -> None:
    resp = client.get("/api/v1/schemas", headers={"X-Role": "operator"})
    assert resp.status_code == 200
    data = resp.json()
    assert "schemas" in data
    assert len(data["schemas"]) >= 3
    schema_ids = [s["id"] for s in data["schemas"]]
    assert "uce" in schema_ids
    assert "ocsf" in schema_ids
    assert "ecs" in schema_ids


def test_get_schema_detail(client: TestClient) -> None:
    resp = client.get("/api/v1/schemas/uce", headers={"X-Role": "operator"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == "uce"
    assert "fields" in data
    assert len(data["fields"]) > 0


def test_get_schema_not_found(client: TestClient) -> None:
    resp = client.get("/api/v1/schemas/invalid-schema", headers={"X-Role": "operator"})
    assert resp.status_code == 404
