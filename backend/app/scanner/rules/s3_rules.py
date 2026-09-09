"""S3 Security Rules Evaluator."""

from typing import List, Dict, Any

def evaluate_s3_rules(account_id: str, region: str, buckets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings = []
    
    for bucket in buckets:
        name = bucket.get("name", "unknown-bucket")
        bucket_arn = f"arn:aws:s3:::{name}"
        
        # 1. Public bucket check
        if bucket.get("is_public", False) or not bucket.get("block_public_access", True):
            findings.append({
                "id": f"FIND-S3-PUB-{name}",
                "account_id": account_id,
                "region": bucket.get("region", region),
                "service": "S3",
                "resource_id": bucket_arn,
                "resource_name": name,
                "resource_type": "AWS::S3::Bucket",
                "rule_id": "S3-001",
                "title": f"S3 Bucket '{name}' is publicly accessible",
                "severity": "Critical",
                "risk_score": 10,
                "description": "S3 Block Public Access is disabled or bucket ACL/policy allows public read/write access from the internet. This exposes company assets or sensitive data to data exfiltration.",
                "evidence": f"BlockPublicAccess: false, PublicPolicy: {bucket.get('is_public')}",
                "recommendation": "Enable S3 Block Public Access at the bucket and account levels immediately, and remove all public read/write grants.",
                "remediation_type": "automated",
                "remediation_action_id": "enable_s3_block_public_access",
                "status": "Open",
                "compliance_mappings": {
                    "CIS": "2.1.5 Ensure that S3 Buckets are configured with 'Block Public Access'",
                    "NIST": "PR.AC-3",
                    "SOC2": "CC6.6",
                    "ISO27001": "A.13.1.1"
                },
                "detected_at": "2026-09-09T08:35:00Z"
            })

        # 2. Disabled encryption
        if not bucket.get("encryption_enabled", False):
            findings.append({
                "id": f"FIND-S3-ENC-{name}",
                "account_id": account_id,
                "region": bucket.get("region", region),
                "service": "S3",
                "resource_id": bucket_arn,
                "resource_name": name,
                "resource_type": "AWS::S3::Bucket",
                "rule_id": "S3-002",
                "title": f"S3 Bucket '{name}' does not have default encryption enabled",
                "severity": "High",
                "risk_score": 7,
                "description": "Objects stored in this bucket are not automatically encrypted at rest with AES-256 (SSE-S3) or AWS KMS (SSE-KMS), risking unauthorized physical or disk-level disclosure.",
                "evidence": "ServerSideEncryptionConfiguration: None",
                "recommendation": "Configure default encryption on the bucket using SSE-KMS or AWS managed AES-256 key.",
                "remediation_type": "automated",
                "remediation_action_id": "enable_s3_encryption",
                "status": "Open",
                "compliance_mappings": {
                    "CIS": "2.1.1 Ensure all S3 buckets have default encryption enabled",
                    "NIST": "SC-13",
                    "SOC2": "CC6.7",
                    "ISO27001": "A.10.1.1"
                },
                "detected_at": "2026-09-09T08:37:00Z"
            })

        # 3. Missing HTTPS enforcement
        if not bucket.get("enforces_https", False):
            findings.append({
                "id": f"FIND-S3-HTTPS-{name}",
                "account_id": account_id,
                "region": bucket.get("region", region),
                "service": "S3",
                "resource_id": bucket_arn,
                "resource_name": name,
                "resource_type": "AWS::S3::Bucket",
                "rule_id": "S3-003",
                "title": f"S3 Bucket '{name}' allows unencrypted in-transit (HTTP) requests",
                "severity": "Medium",
                "risk_score": 4,
                "description": "Bucket policy lacks explicit deny for requests without 'aws:SecureTransport: true'. In-transit data can be intercepted or manipulated via man-in-the-middle attacks.",
                "evidence": "BucketPolicy: Missing 'aws:SecureTransport' condition",
                "recommendation": "Add a bucket policy denying any S3 action where 'aws:SecureTransport' evaluates to false.",
                "remediation_type": "automated",
                "remediation_action_id": "enforce_s3_https_policy",
                "status": "Open",
                "compliance_mappings": {
                    "CIS": "2.1.2 Ensure S3 bucket policy denies HTTP requests",
                    "NIST": "SC-8",
                    "SOC2": "CC6.6",
                    "ISO27001": "A.13.2.1"
                },
                "detected_at": "2026-09-09T08:40:00Z"
            })

        # 4. Missing logging
        if not bucket.get("logging_enabled", False):
            findings.append({
                "id": f"FIND-S3-LOG-{name}",
                "account_id": account_id,
                "region": bucket.get("region", region),
                "service": "S3",
                "resource_id": bucket_arn,
                "resource_name": name,
                "resource_type": "AWS::S3::Bucket",
                "rule_id": "S3-004",
                "title": f"Server access logging disabled on S3 bucket '{name}'",
                "severity": "Low",
                "risk_score": 1,
                "description": "Without server access logging, detailed records of requests (requester, bucket name, request time, action, response status) are unavailable for forensic analysis.",
                "evidence": "LoggingEnabled: false",
                "recommendation": "Enable server access logging targeting a designated centralized audit logs bucket.",
                "remediation_type": "manual",
                "remediation_action_id": None,
                "status": "Open",
                "compliance_mappings": {
                    "CIS": "2.1.3 Ensure S3 Bucket Access Logging is enabled",
                    "NIST": "AU-2",
                    "SOC2": "CC7.2",
                    "ISO27001": "A.12.4.1"
                },
                "detected_at": "2026-09-09T08:42:00Z"
            })

        # 5. Missing versioning
        if not bucket.get("versioning_enabled", False):
            findings.append({
                "id": f"FIND-S3-VER-{name}",
                "account_id": account_id,
                "region": bucket.get("region", region),
                "service": "S3",
                "resource_id": bucket_arn,
                "resource_name": name,
                "resource_type": "AWS::S3::Bucket",
                "rule_id": "S3-005",
                "title": f"S3 Bucket '{name}' versioning is not enabled",
                "severity": "Low",
                "risk_score": 1,
                "description": "Versioning protects data against accidental deletion, overwriting, and ransomware attacks by retaining previous object states.",
                "evidence": "VersioningStatus: Suspended",
                "recommendation": "Enable versioning on the bucket and configure lifecycle rules to manage older object versions.",
                "remediation_type": "automated",
                "remediation_action_id": "enable_s3_versioning",
                "status": "Open",
                "compliance_mappings": {
                    "CIS": "2.1.4 Ensure S3 Bucket versioning is enabled",
                    "NIST": "CP-9",
                    "SOC2": "CC7.1",
                    "ISO27001": "A.12.3.1"
                },
                "detected_at": "2026-09-09T08:45:00Z"
            })
            
    return findings
