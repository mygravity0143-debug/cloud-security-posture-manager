"""CloudTrail Security Rules Evaluator."""

from typing import List, Dict, Any

def evaluate_cloudtrail_rules(account_id: str, region: str, ct_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    trails = ct_data.get("trails", [])
    
    if not trails:
        findings.append({
            "id": "FIND-CT-NONE",
            "account_id": account_id,
            "region": region,
            "service": "CloudTrail",
            "resource_id": f"arn:aws:cloudtrail:{region}:{account_id}:trail/missing",
            "resource_name": "Account Audit Trail",
            "resource_type": "AWS::CloudTrail::Trail",
            "rule_id": "CT-001",
            "title": "AWS CloudTrail is not configured or active",
            "severity": "Critical",
            "risk_score": 10,
            "description": "No active CloudTrail trail exists. Without CloudTrail, API activity, administrative logins, and potential security intrusions cannot be logged or audited.",
            "evidence": "DescribeTrails: 0 trails returned",
            "recommendation": "Create and enable an organization-wide or multi-region CloudTrail trail logging all management and data events.",
            "remediation_type": "manual",
            "remediation_action_id": None,
            "status": "Open",
            "compliance_mappings": {
                "CIS": "3.1 Ensure CloudTrail is enabled in all regions",
                "NIST": "AU-2",
                "SOC2": "CC7.2",
                "ISO27001": "A.12.4.1"
            },
            "detected_at": "2026-09-09T09:00:00Z"
        })
        return findings

    for trail in trails:
        trail_name = trail.get("name", "default-trail")
        trail_arn = trail.get("arn", f"arn:aws:cloudtrail:{region}:{account_id}:trail/{trail_name}")
        
        # 1. Multi-region logging
        if not trail.get("is_multi_region", True):
            findings.append({
                "id": f"FIND-CT-MULTI-{trail_name}",
                "account_id": account_id,
                "region": region,
                "service": "CloudTrail",
                "resource_id": trail_arn,
                "resource_name": trail_name,
                "resource_type": "AWS::CloudTrail::Trail",
                "rule_id": "CT-002",
                "title": f"CloudTrail trail '{trail_name}' is not enabled across all regions",
                "severity": "High",
                "risk_score": 7,
                "description": "Trail is limited to a single region. Attackers frequently deploy rogue resources or perform reconnaissance in unmonitored AWS regions.",
                "evidence": f"IsMultiRegionTrail: false, HomeRegion: {region}",
                "recommendation": "Configure CloudTrail to log API activity across all AWS regions globally.",
                "remediation_type": "automated",
                "remediation_action_id": f"enable_ct_multi_region:{trail_name}",
                "status": "Open",
                "compliance_mappings": {
                    "CIS": "3.1 Ensure CloudTrail is enabled in all regions",
                    "NIST": "AU-3",
                    "SOC2": "CC7.2",
                    "ISO27001": "A.12.4.1"
                },
                "detected_at": "2026-09-09T09:02:00Z"
            })

        # 2. Log file validation
        if not trail.get("log_validation_enabled", True):
            findings.append({
                "id": f"FIND-CT-VALID-{trail_name}",
                "account_id": account_id,
                "region": region,
                "service": "CloudTrail",
                "resource_id": trail_arn,
                "resource_name": trail_name,
                "resource_type": "AWS::CloudTrail::Trail",
                "rule_id": "CT-003",
                "title": f"CloudTrail log file validation is disabled on '{trail_name}'",
                "severity": "Medium",
                "risk_score": 4,
                "description": "Log file integrity validation uses cryptographic digests to ensure logs have not been altered, modified, or deleted after delivery.",
                "evidence": "LogFileValidationEnabled: false",
                "recommendation": "Enable log file validation to ensure forensic integrity of security audit trails.",
                "remediation_type": "automated",
                "remediation_action_id": f"enable_ct_log_validation:{trail_name}",
                "status": "Open",
                "compliance_mappings": {
                    "CIS": "3.2 Ensure CloudTrail log file validation is enabled",
                    "NIST": "AU-9",
                    "SOC2": "CC7.3",
                    "ISO27001": "A.12.4.2"
                },
                "detected_at": "2026-09-09T09:04:00Z"
            })

        # 3. KMS Encryption
        if not trail.get("kms_key_id"):
            findings.append({
                "id": f"FIND-CT-KMS-{trail_name}",
                "account_id": account_id,
                "region": region,
                "service": "CloudTrail",
                "resource_id": trail_arn,
                "resource_name": trail_name,
                "resource_type": "AWS::CloudTrail::Trail",
                "rule_id": "CT-004",
                "title": f"CloudTrail logs are not encrypted using AWS KMS Customer Managed Keys",
                "severity": "Medium",
                "risk_score": 4,
                "description": "Trail relies on default S3 server-side encryption rather than a dedicated Customer Managed KMS Key (CMK) with strict separation of duties.",
                "evidence": "KmsKeyId: None",
                "recommendation": "Configure CloudTrail to encrypt audit logs using an approved AWS KMS CMK with strict key policies.",
                "remediation_type": "manual",
                "remediation_action_id": None,
                "status": "Open",
                "compliance_mappings": {
                    "CIS": "3.7 Ensure CloudTrail logs are encrypted using KMS CMKs",
                    "NIST": "SC-13",
                    "SOC2": "CC6.7",
                    "ISO27001": "A.10.1.1"
                },
                "detected_at": "2026-09-09T09:06:00Z"
            })
            
    # 4. Unauthorized API activity detection
    unauthorized_events = ct_data.get("unauthorized_events", [])
    if unauthorized_events:
        findings.append({
            "id": "FIND-CT-UNAUTH-ACT",
            "account_id": account_id,
            "region": region,
            "service": "CloudTrail",
            "resource_id": f"arn:aws:cloudtrail:{region}:{account_id}:events/unauthorized",
            "resource_name": "Unauthorized API Activity",
            "resource_type": "AWS::CloudTrail::SecurityEvent",
            "rule_id": "CT-005",
            "title": f"{len(unauthorized_events)} Unauthorized API call(s) detected in recent audit window",
            "severity": "High",
            "risk_score": 7,
            "description": "Multiple AccessDenied and UnauthorizedOperation errors detected across IAM, S3, and Security Groups, indicating possible privilege escalation or reconnaissance.",
            "evidence": f"Events: {len(unauthorized_events)} AccessDenied records detected from source IPs: {', '.join(list(set(e.get('source_ip', '') for e in unauthorized_events))[:3])}",
            "recommendation": "Investigate affected IAM credentials, revoke active sessions, and check IP intelligence sources.",
            "remediation_type": "manual",
            "remediation_action_id": None,
            "status": "Open",
            "compliance_mappings": {
                "CIS": "4.1 Ensure a log metric filter and alarm exist for unauthorized API calls",
                "NIST": "DE.AE-1",
                "SOC2": "CC7.2",
                "ISO27001": "A.12.4.1"
            },
            "detected_at": "2026-09-09T09:10:00Z"
        })

    return findings
