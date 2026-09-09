"""Risk Analysis API endpoints."""

from fastapi import APIRouter
from app.scanner.engine import scanner_engine
from app.core.scoring import calculate_posture_score

router = APIRouter(prefix="/risk-score", tags=["Risk Analysis"])

@router.get("")
def get_risk_score_analysis():
    findings = scanner_engine.get_findings()
    posture = calculate_posture_score(findings)

    # Risk distribution by attack surface vectors
    active_findings = [f for f in findings if f.get("status") in ("Open", "In Progress")]
    
    attack_surfaces = [
        {
            "category": "External Attack Surface (Public Exposure)",
            "description": "Publicly reachable endpoints (0.0.0.0/0 SSH/RDP, public S3 buckets, public RDS)",
            "risk_level": "Critical",
            "findings_count": len([f for f in active_findings if f.get("rule_id") in ("EC2-001", "EC2-002", "S3-001", "RDS-001")]),
            "recommendation": "Enforce strict security groups and S3 Account-level Block Public Access."
        },
        {
            "category": "Identity & Privilege Escalation",
            "description": "Root without MFA, users without MFA, and wildcard AdministratorAccess",
            "risk_level": "Critical",
            "findings_count": len([f for f in active_findings if f.get("service") == "IAM"]),
            "recommendation": "Adopt IAM Identity Center, remove static access keys, and enforce MFA."
        },
        {
            "category": "Data Cryptography at Rest & Transit",
            "description": "Unencrypted S3 buckets, non-rotated KMS keys, unencrypted RDS, plaintext HTTP",
            "risk_level": "High",
            "findings_count": len([f for f in active_findings if "enc" in f.get("rule_id", "").lower() or "kms" in f.get("service", "").lower()]),
            "recommendation": "Mandate SSE-KMS across all databases and S3 buckets."
        },
        {
            "category": "Audit & Forensic Visibility",
            "description": "Single-region CloudTrail, disabled log validation, missing VPC flow logs",
            "risk_level": "Medium",
            "findings_count": len([f for f in active_findings if f.get("service") in ("CloudTrail", "VPC")]),
            "recommendation": "Enable multi-region CloudTrail with KMS encryption and VPC Flow Logs."
        }
    ]

    # Calculate highest risk resources
    high_risk_resources = []
    seen_resources = set()
    for f in sorted(active_findings, key=lambda x: x.get("risk_score", 0), reverse=True):
        rid = f.get("resource_id")
        if rid not in seen_resources:
            seen_resources.add(rid)
            high_risk_resources.append({
                "resource_id": rid,
                "resource_name": f.get("resource_name"),
                "service": f.get("service"),
                "risk_score": f.get("risk_score"),
                "severity": f.get("severity"),
                "top_finding": f.get("title")
            })
            if len(high_risk_resources) >= 6:
                break

    return {
        "overall_security_score": posture["overall_score"],
        "posture_status": posture["status_label"],
        "posture_color": posture["status_color"],
        "total_penalty_points": posture["total_penalty_points"],
        "points_formula": "Critical (10) + High (7) + Medium (4) + Low (1)",
        "severity_breakdown": posture["severity_counts"],
        "attack_surfaces": attack_surfaces,
        "highest_risk_resources": high_risk_resources
    }
