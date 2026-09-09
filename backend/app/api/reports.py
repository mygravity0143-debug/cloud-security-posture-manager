"""Security Reports API endpoints."""

import io
import csv
import json
from datetime import datetime, timezone
from fastapi import APIRouter, Response
from fastapi.responses import PlainTextResponse

from app.scanner.engine import scanner_engine
from app.core.scoring import calculate_posture_score
from app.scanner.providers.mock_provider import mock_provider

router = APIRouter(prefix="/reports", tags=["Reports"])

@router.get("")
def get_security_report_summary():
    findings = scanner_engine.get_findings()
    posture = calculate_posture_score(findings)
    open_findings = [f for f in findings if f.get("status") in ("Open", "In Progress")]
    critical_findings = [f for f in open_findings if f.get("severity") == "Critical"]
    
    return {
        "report_title": "Executive Cloud Security Posture & Compliance Report",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "account_id": mock_provider.account_id,
        "account_name": mock_provider.account_name,
        "region": mock_provider.primary_region,
        "overall_security_score": posture["overall_score"],
        "posture_status": posture["status_label"],
        "total_active_findings": len(open_findings),
        "total_resolved_findings": posture["total_resolved_findings"],
        "severity_summary": posture["severity_counts"],
        "pillar_scores": posture["pillar_scores"],
        "critical_vulnerabilities": [
            {
                "id": f["id"],
                "rule_id": f["rule_id"],
                "title": f["title"],
                "service": f["service"],
                "resource": f["resource_name"],
                "recommendation": f["recommendation"]
            }
            for f in critical_findings
        ],
        "compliance_summary": {
            "CIS AWS Foundations": "78% Compliant",
            "NIST CSF v1.1": "81% Compliant",
            "SOC 2 Type II": "83% Compliant",
            "ISO/IEC 27001": "80% Compliant"
        },
        "remediation_progress": {
            "actions_executed": len(scanner_engine.remediation_audit_logs),
            "open_critical_count": len(critical_findings)
        },
        "key_recommendations": [
            "Enable MFA for AWS Root account immediately and store emergency keys in a secure HSM.",
            "Remove direct AdministratorAccess from regular IAM users; enforce role-based access.",
            "Enforce S3 Block Public Access at the AWS account level to prevent data leaks.",
            "Revoke unrestricted ingress (0.0.0.0/0) on port 22 (SSH) and port 3389 (RDP).",
            "Enable multi-region CloudTrail logging with KMS CMK encryption and log validation."
        ]
    }

@router.get("/export/csv")
def export_findings_csv():
    findings = scanner_engine.get_findings()
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Headers
    writer.writerow([
        "Finding ID",
        "AWS Account",
        "Region",
        "AWS Service",
        "Resource Name",
        "Resource ID",
        "Rule ID",
        "Severity",
        "Risk Score",
        "Status",
        "Title",
        "Description",
        "Evidence",
        "Recommendation",
        "Detection Time"
    ])
    
    for f in findings:
        writer.writerow([
            f.get("id"),
            f.get("account_id"),
            f.get("region"),
            f.get("service"),
            f.get("resource_name"),
            f.get("resource_id"),
            f.get("rule_id"),
            f.get("severity"),
            f.get("risk_score"),
            f.get("status"),
            f.get("title"),
            f.get("description"),
            f.get("evidence"),
            f.get("recommendation"),
            f.get("detected_at")
        ])
        
    csv_content = output.getvalue()
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=cspm-security-findings-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}.csv"}
    )

@router.get("/export/json")
def export_findings_json():
    findings = scanner_engine.get_findings()
    report_data = {
        "export_metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scanner_version": "2.4.0",
            "account_id": mock_provider.account_id,
            "total_findings": len(findings)
        },
        "findings": findings
    }
    return Response(
        content=json.dumps(report_data, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=cspm-audit-report-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}.json"}
    )
