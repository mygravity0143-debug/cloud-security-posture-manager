"""Compliance Dashboard API endpoints."""

from fastapi import APIRouter
from app.scanner.engine import scanner_engine

router = APIRouter(prefix="/compliance", tags=["Compliance"])

FRAMEWORKS_DEFINITION = {
    "cis_aws": {
        "id": "cis_aws",
        "name": "CIS AWS Foundations Benchmark",
        "version": "v2.0",
        "category": "Industry Benchmark",
        "total_controls": 48,
        "controls": [
            {"id": "CIS-1.5", "title": "Ensure MFA is enabled for the 'root' account", "section": "1. Identity & Access", "mapped_rule": "IAM-001"},
            {"id": "CIS-1.10", "title": "Ensure multi-factor authentication is enabled for all IAM users", "section": "1. Identity & Access", "mapped_rule": "IAM-002"},
            {"id": "CIS-1.14", "title": "Ensure access keys are rotated every 90 days or less", "section": "1. Identity & Access", "mapped_rule": "IAM-003"},
            {"id": "CIS-1.16", "title": "Ensure IAM policies are not directly attached to users", "section": "1. Identity & Access", "mapped_rule": "IAM-004"},
            {"id": "CIS-2.1.1", "title": "Ensure S3 buckets have default encryption enabled", "section": "2. Storage", "mapped_rule": "S3-002"},
            {"id": "CIS-2.1.5", "title": "Ensure S3 buckets enforce Block Public Access", "section": "2. Storage", "mapped_rule": "S3-001"},
            {"id": "CIS-3.1", "title": "Ensure CloudTrail is enabled in all regions", "section": "3. Logging", "mapped_rule": "CT-002"},
            {"id": "CIS-3.2", "title": "Ensure CloudTrail log file validation is enabled", "section": "3. Logging", "mapped_rule": "CT-003"},
            {"id": "CIS-3.8", "title": "Ensure rotation for customer created KMS keys is enabled", "section": "3. Logging", "mapped_rule": "KMS-001"},
            {"id": "CIS-3.9", "title": "Ensure VPC flow logging is enabled in all VPCs", "section": "3. Logging", "mapped_rule": "VPC-002"},
            {"id": "CIS-4.3", "title": "Ensure RDS instances are not publicly accessible", "section": "4. Database", "mapped_rule": "RDS-001"},
            {"id": "CIS-5.2", "title": "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22", "section": "5. Networking", "mapped_rule": "EC2-001"},
            {"id": "CIS-5.3", "title": "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389", "section": "5. Networking", "mapped_rule": "EC2-002"},
            {"id": "CIS-5.4", "title": "Ensure EC2 instances enforce IMDSv2", "section": "5. Networking", "mapped_rule": "EC2-004"}
        ]
    },
    "nist_csf": {
        "id": "nist_csf",
        "name": "NIST Cybersecurity Framework",
        "version": "v1.1",
        "category": "Federal & Enterprise Standard",
        "total_controls": 42,
        "controls": [
            {"id": "NIST-PR.AC-1", "title": "Identities and credentials are authenticated with multi-factor tokens", "section": "Protect (PR.AC)", "mapped_rule": "IAM-001"},
            {"id": "NIST-PR.AC-3", "title": "Remote access is managed and restricted from untrusted networks", "section": "Protect (PR.AC)", "mapped_rule": "S3-001"},
            {"id": "NIST-PR.AC-5", "title": "Network integrity is protected via security groups and ingress filters", "section": "Protect (PR.AC)", "mapped_rule": "EC2-001"},
            {"id": "NIST-PR.AC-6", "title": "Principle of least privilege is enforced on all roles and permissions", "section": "Protect (PR.AC)", "mapped_rule": "IAM-004"},
            {"id": "NIST-SC-13", "title": "Cryptographic mechanisms protect data at rest across databases and buckets", "section": "Protect (PR.DS)", "mapped_rule": "S3-002"},
            {"id": "NIST-AU-2", "title": "Audit events are collected and monitored continuously across all accounts", "section": "Detect (DE.CM)", "mapped_rule": "CT-001"},
            {"id": "NIST-DE.AE-1", "title": "Baseline network and API activities are monitored for unauthorized actions", "section": "Detect (DE.AE)", "mapped_rule": "CT-005"}
        ]
    },
    "soc2": {
        "id": "soc2",
        "name": "SOC 2 Type II",
        "version": "Trust Services Criteria",
        "category": "Audit Standard",
        "total_controls": 35,
        "controls": [
            {"id": "SOC2-CC6.1", "title": "Logical access security controls and multifactor authentication", "section": "Logical and Physical Access", "mapped_rule": "IAM-002"},
            {"id": "SOC2-CC6.3", "title": "Role-based access boundaries and least privilege policies", "section": "Logical and Physical Access", "mapped_rule": "IAM-004"},
            {"id": "SOC2-CC6.6", "title": "Boundary protection against unauthorized external network entry", "section": "Logical and Physical Access", "mapped_rule": "EC2-001"},
            {"id": "SOC2-CC6.7", "title": "Data encryption at rest and in transit", "section": "Logical and Physical Access", "mapped_rule": "S3-002"},
            {"id": "SOC2-CC7.2", "title": "Security event logging and audit integrity monitoring", "section": "System Operations", "mapped_rule": "CT-003"}
        ]
    },
    "iso27001": {
        "id": "iso27001",
        "name": "ISO/IEC 27001:2022",
        "version": "Annex A",
        "category": "International Standard",
        "total_controls": 38,
        "controls": [
            {"id": "ISO-A.9.1.2", "title": "Access to networks and network services", "section": "A.9 Access Control", "mapped_rule": "EC2-001"},
            {"id": "ISO-A.9.4.2", "title": "Secure log-on procedures with MFA", "section": "A.9 Access Control", "mapped_rule": "IAM-001"},
            {"id": "ISO-A.10.1.1", "title": "Policy on the use of cryptographic controls", "section": "A.10 Cryptography", "mapped_rule": "KMS-001"},
            {"id": "ISO-A.12.4.1", "title": "Event logging and forensic log generation", "section": "A.12 Operations Security", "mapped_rule": "CT-002"},
            {"id": "ISO-A.13.1.1", "title": "Network controls and perimeter segmentation", "section": "A.13 Communications", "mapped_rule": "RDS-001"}
        ]
    }
}

@router.get("")
def get_compliance_dashboard():
    findings = scanner_engine.get_findings()
    # Active finding rule IDs
    active_failed_rules = set(
        f.get("rule_id") for f in findings if f.get("status") in ("Open", "In Progress")
    )

    frameworks_report = []
    
    for f_key, f_data in FRAMEWORKS_DEFINITION.items():
        total = f_data["total_controls"]
        evaluated_controls = []
        failed_count = 0
        
        for c in f_data["controls"]:
            mapped_rule = c.get("mapped_rule")
            is_failed = mapped_rule in active_failed_rules
            if is_failed:
                failed_count += 1
                
            # Find matching finding if failed
            attached_finding = next((f for f in findings if f.get("rule_id") == mapped_rule and f.get("status") in ("Open", "In Progress")), None)
            
            evaluated_controls.append({
                "control_id": c["id"],
                "title": c["title"],
                "section": c["section"],
                "mapped_rule": mapped_rule,
                "status": "FAILED" if is_failed else "PASSED",
                "finding_id": attached_finding.get("id") if attached_finding else None,
                "severity": attached_finding.get("severity", "Medium") if attached_finding else "Low",
                "recommendation": attached_finding.get("recommendation", "Maintain verified compliance posture.") if attached_finding else "Control verified compliant."
            })
            
        passed_count = total - failed_count
        score_percent = round((passed_count / total) * 100)
        
        frameworks_report.append({
            "id": f_data["id"],
            "name": f_data["name"],
            "version": f_data["version"],
            "category": f_data["category"],
            "score_percent": score_percent,
            "total_controls": total,
            "passed_controls": passed_count,
            "failed_controls": failed_count,
            "controls": evaluated_controls
        })

    overall_compliance_avg = round(sum(f["score_percent"] for f in frameworks_report) / len(frameworks_report))

    return {
        "overall_compliance_percentage": overall_compliance_avg,
        "frameworks_count": len(frameworks_report),
        "frameworks": frameworks_report
    }
