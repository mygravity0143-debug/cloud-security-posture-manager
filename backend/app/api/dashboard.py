"""Dashboard API endpoints."""

from fastapi import APIRouter
from app.scanner.engine import scanner_engine
from app.core.scoring import calculate_posture_score
from app.scanner.providers.mock_provider import mock_provider

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

@router.get("")
def get_dashboard_summary():
    findings = scanner_engine.get_findings()
    total_resources = (
        len(mock_provider.iam_data.get("users", []))
        + len(mock_provider.s3_buckets)
        + len(mock_provider.ec2_data.get("instances", []))
        + len(mock_provider.ec2_data.get("security_groups", []))
        + len(mock_provider.rds_data)
        + len(mock_provider.lambda_data)
        + len(mock_provider.kms_data)
        + len(mock_provider.vpc_data.get("vpcs", []))
    )
    posture = calculate_posture_score(findings, total_resources=total_resources)

    # Findings by service
    service_counts = {}
    for f in findings:
        if f.get("status") in ("Open", "In Progress"):
            srv = f.get("service", "Other")
            service_counts[srv] = service_counts.get(srv, 0) + 1

    # Security score over time (simulated 30-day timeline trend)
    score_history = [
        {"date": "Aug 10", "score": 68},
        {"date": "Aug 17", "score": 71},
        {"date": "Aug 24", "score": 70},
        {"date": "Aug 31", "score": 74},
        {"date": "Sep 07", "score": 79},
        {"date": "Current", "score": posture["overall_score"]}
    ]

    # Recent critical alerts
    critical_alerts = [
        f for f in findings if f.get("severity") == "Critical" and f.get("status") == "Open"
    ][:4]

    # CloudTrail recent events (top 5)
    recent_events = mock_provider.cloudtrail_events[:5]

    return {
        "overall_security_score": posture["overall_score"],
        "previous_security_score": posture["previous_score"],
        "score_improvement": posture["score_delta"],
        "posture_status": posture["status_label"],
        "posture_color": posture["status_color"],
        "severity_summary": posture["severity_counts"],
        "pillar_scores": {
            "iam_security_score": posture["pillar_scores"]["iam"],
            "network_security_score": posture["pillar_scores"]["network"],
            "logging_monitoring_score": posture["pillar_scores"]["logging"],
            "encryption_score": posture["pillar_scores"]["encryption"],
            "compliance_score": posture["pillar_scores"]["compliance"]
        },
        "findings_by_service": service_counts,
        "score_history": score_history,
        "total_active_findings": posture["total_active_findings"],
        "total_resolved_findings": posture["total_resolved_findings"],
        "total_accepted_risk": posture["total_accepted_risk"],
        "last_security_scan": scanner_engine.last_scan_time,
        "aws_account": {
            "id": mock_provider.account_id,
            "name": mock_provider.account_name,
            "primary_region": mock_provider.primary_region,
            "mode": scanner_engine.mode,
            "status": "Monitored / Active"
        },
        "critical_alerts": critical_alerts,
        "recent_cloudtrail_activity": recent_events
    }
