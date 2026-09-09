"""Automated Unit & Integration Tests for CSPM Backend."""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.scoring import calculate_posture_score
from app.scanner.engine import scanner_engine

client = TestClient(app)

def test_risk_scoring_engine():
    sample_findings = [
        {"severity": "Critical", "status": "Open", "service": "IAM", "rule_id": "IAM-001", "title": "Root MFA disabled"},
        {"severity": "High", "status": "Open", "service": "EC2", "rule_id": "EC2-001", "title": "Unrestricted SSH"},
        {"severity": "Medium", "status": "Open", "service": "S3", "rule_id": "S3-003", "title": "Unencrypted transit"},
        {"severity": "Low", "status": "Open", "service": "VPC", "rule_id": "VPC-001", "title": "Default VPC in use"},
        {"severity": "Critical", "status": "Resolved", "service": "IAM", "rule_id": "IAM-002", "title": "Old resolved finding"}
    ]
    posture = calculate_posture_score(sample_findings)
    assert "overall_score" in posture
    assert 0 <= posture["overall_score"] <= 100
    assert posture["total_active_findings"] == 4
    assert posture["total_resolved_findings"] == 1
    # Check penalty points: 10 + 7 + 4 + 1 = 22
    assert posture["total_penalty_points"] == 22
    assert "pillar_scores" in posture
    assert "iam" in posture["pillar_scores"]
    assert "network" in posture["pillar_scores"]

def test_api_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "HEALTHY"

def test_api_dashboard():
    response = client.get("/api/dashboard")
    assert response.status_code == 200
    data = response.json()
    assert "overall_security_score" in data
    assert "severity_summary" in data
    assert "pillar_scores" in data
    assert "findings_by_service" in data
    assert "aws_account" in data

def test_api_findings_filtering():
    response = client.get("/api/findings")
    assert response.status_code == 200
    data = response.json()
    assert "findings" in data
    assert len(data["findings"]) > 0

    # Filter by severity = Critical
    crit_resp = client.get("/api/findings?severity=Critical")
    assert crit_resp.status_code == 200
    crit_data = crit_resp.json()
    for f in crit_data["findings"]:
        assert f["severity"] == "Critical"

def test_api_iam():
    response = client.get("/api/iam/users")
    assert response.status_code == 200
    data = response.json()
    assert "users" in data
    assert len(data["users"]) > 0
    # Check that root account MFA status is present
    assert "root_account" in data

def test_api_cloudtrail():
    response = client.get("/api/cloudtrail/events")
    assert response.status_code == 200
    data = response.json()
    assert "events" in data
    assert len(data["events"]) > 0

def test_api_compliance():
    response = client.get("/api/compliance")
    assert response.status_code == 200
    data = response.json()
    assert "frameworks" in data
    assert len(data["frameworks"]) >= 4
    for fw in data["frameworks"]:
        assert "score_percent" in fw
        assert 0 <= fw["score_percent"] <= 100

def test_api_remediation_and_audit():
    # 1. Check snippets endpoint
    findings = scanner_engine.get_findings()
    open_ssh = next((f for f in findings if "SSH" in f.get("title", "")), None)
    assert open_ssh is not None
    
    snippet_resp = client.get(f"/api/remediation/snippets/{open_ssh['id']}")
    assert snippet_resp.status_code == 200
    snippet_data = snippet_resp.json()
    assert "snippets" in snippet_data
    assert "aws_cli" in snippet_data["snippets"]

    # 2. Execute automated remediation as Security Administrator
    headers = {"x-user-role": "Security Administrator"}
    rem_resp = client.post(
        "/api/remediation",
        json={"finding_id": open_ssh["id"]},
        headers=headers
    )
    assert rem_resp.status_code == 200
    rem_data = rem_resp.json()
    assert rem_data["success"] is True

    # 3. Check that it was recorded in the audit log
    audit_resp = client.get("/api/remediation/audit-log")
    assert audit_resp.status_code == 200
    audit_data = audit_resp.json()
    assert any(entry["finding_id"] == open_ssh["id"] for entry in audit_data["audit_logs"])

def test_rbac_restriction():
    # Viewer role cannot trigger scans or remediations
    headers = {"x-user-role": "Viewer"}
    findings = scanner_engine.get_findings()
    first_finding = findings[0]["id"]
    
    rem_resp = client.post(
        "/api/remediation",
        json={"finding_id": first_finding},
        headers=headers
    )
    assert rem_resp.status_code == 403
    assert "Access Denied" in rem_resp.json()["detail"]
