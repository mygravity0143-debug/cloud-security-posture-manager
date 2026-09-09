"""AWS KMS Security Rules Evaluator."""

from typing import List, Dict, Any

def evaluate_kms_rules(account_id: str, region: str, kms_keys: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings = []
    
    for key in kms_keys:
        key_id = key.get("id", "key-unknown")
        alias = key.get("alias", key_id)
        key_arn = f"arn:aws:kms:{region}:{account_id}:key/{key_id}"
        
        # 1. Key rotation disabled
        if key.get("key_manager") == "CUSTOMER" and not key.get("rotation_enabled", False):
            findings.append({
                "id": f"FIND-KMS-ROT-{key_id}",
                "account_id": account_id,
                "region": region,
                "service": "KMS",
                "resource_id": key_arn,
                "resource_name": f"{alias} ({key_id[:8]}...)",
                "resource_type": "AWS::KMS::Key",
                "rule_id": "KMS-001",
                "title": f"Automatic key rotation disabled for KMS Key '{alias}'",
                "severity": "Medium",
                "risk_score": 4,
                "description": "AWS KMS Customer Master Key does not rotate automatically annually. Key rotation limits the blast radius if an individual cryptographic key is compromised.",
                "evidence": "KeyRotationEnabled: false",
                "recommendation": "Enable automatic annual key rotation on all customer managed KMS keys.",
                "remediation_type": "automated",
                "remediation_action_id": f"enable_kms_key_rotation:{key_id}",
                "status": "Open",
                "compliance_mappings": {
                    "CIS": "3.8 Ensure rotation for customer-created KMS keys is enabled",
                    "NIST": "SC-12",
                    "SOC2": "CC6.7",
                    "ISO27001": "A.10.1.2"
                },
                "detected_at": "2026-09-09T09:28:00Z"
            })

        # 2. Overly permissive key policy
        if key.get("has_wildcard_policy", False):
            findings.append({
                "id": f"FIND-KMS-POL-{key_id}",
                "account_id": account_id,
                "region": region,
                "service": "KMS",
                "resource_id": key_arn,
                "resource_name": alias,
                "resource_type": "AWS::KMS::Key",
                "rule_id": "KMS-002",
                "title": f"KMS Key '{alias}' policy allows unrestricted Principal '*'",
                "severity": "High",
                "risk_score": 7,
                "description": "Key policy grants kms:Decrypt or kms:* to wildcard principal '*' without appropriate condition blocks, allowing cross-account or unintended decryption.",
                "evidence": "KeyPolicy: Principal: '*', Action: 'kms:*'",
                "recommendation": "Restrict the key policy to specific IAM roles and principles requiring decryption access.",
                "remediation_type": "manual",
                "remediation_action_id": None,
                "status": "Open",
                "compliance_mappings": {
                    "CIS": "3.8 Ensure KMS key policies adhere to least privilege",
                    "NIST": "PR.AC-4",
                    "SOC2": "CC6.3",
                    "ISO27001": "A.9.1.2"
                },
                "detected_at": "2026-09-09T09:30:00Z"
            })
            
    return findings
