"""IAM Security Rules Evaluator."""

from datetime import datetime, timezone
from typing import List, Dict, Any

def evaluate_iam_rules(account_id: str, region: str, iam_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    
    # 1. Root MFA check
    root_summary = iam_data.get("root_account", {})
    if not root_summary.get("mfa_enabled", False):
        findings.append({
            "id": "FIND-IAM-001",
            "account_id": account_id,
            "region": "global",
            "service": "IAM",
            "resource_id": f"arn:aws:iam::{account_id}:root",
            "resource_name": "Root Account",
            "resource_type": "AWS::IAM::RootAccount",
            "rule_id": "IAM-001",
            "title": "Root account MFA is not enabled",
            "severity": "Critical",
            "risk_score": 10,
            "description": "The root account has unrestricted administrative privileges across the entire AWS organization. Without Multi-Factor Authentication (MFA), credentials compromised via phishing or breach grant attackers full control.",
            "evidence": "AccountSummary: AccountMFAEnabled = 0",
            "recommendation": "Enable a hardware or virtual MFA token immediately for the AWS root account and lock the credentials in a secure vault.",
            "remediation_type": "manual",
            "remediation_action_id": None,
            "status": "Open",
            "compliance_mappings": {
                "CIS": "1.5 Ensure MFA is enabled for the 'root' account",
                "NIST": "PR.AC-1",
                "SOC2": "CC6.1",
                "ISO27001": "A.9.4.2"
            },
            "detected_at": "2026-09-09T08:15:00Z"
        })

    users = iam_data.get("users", [])
    now = datetime.now(timezone.utc)
    
    for user in users:
        username = user.get("username", "unknown")
        user_arn = user.get("arn", f"arn:aws:iam::{account_id}:user/{username}")
        
        # 2. IAM User without MFA
        if not user.get("mfa_enabled", False) and user.get("has_console_access", True):
            findings.append({
                "id": f"FIND-IAM-MFA-{username}",
                "account_id": account_id,
                "region": "global",
                "service": "IAM",
                "resource_id": user_arn,
                "resource_name": username,
                "resource_type": "AWS::IAM::User",
                "rule_id": "IAM-002",
                "title": f"IAM user '{username}' does not have MFA enabled",
                "severity": "High",
                "risk_score": 7,
                "description": "Console access is enabled for this user but multi-factor authentication is not enforced, increasing risk of credential stuffing.",
                "evidence": f"User: {username}, MFAActive: false, ConsoleAccess: true",
                "recommendation": "Enforce MFA registration policy across all IAM users with console login privileges.",
                "remediation_type": "automated",
                "remediation_action_id": "enforce_user_mfa_policy",
                "status": "Open",
                "compliance_mappings": {
                    "CIS": "1.10 Ensure multi-factor authentication is enabled for all IAM users",
                    "NIST": "PR.AC-7",
                    "SOC2": "CC6.1",
                    "ISO27001": "A.9.4.3"
                },
                "detected_at": "2026-09-09T08:20:00Z"
            })
            
        # 3. Access keys older than 90 days
        for key in user.get("access_keys", []):
            age_days = key.get("age_days", 0)
            if key.get("status") == "Active" and age_days > 90:
                findings.append({
                    "id": f"FIND-IAM-KEY-{key.get('key_id', username)}",
                    "account_id": account_id,
                    "region": "global",
                    "service": "IAM",
                    "resource_id": f"{user_arn}/key/{key.get('key_id')}",
                    "resource_name": f"{username} ({key.get('key_id')})",
                    "resource_type": "AWS::IAM::AccessKey",
                    "rule_id": "IAM-003",
                    "title": f"Access key '{key.get('key_id')}' older than 90 days ({age_days} days)",
                    "severity": "Medium",
                    "risk_score": 4,
                    "description": "Long-lived static access keys heighten exposure to credential leakage and unauthorized programmatic API exploitation.",
                    "evidence": f"AccessKeyId: {key.get('key_id')}, Age: {age_days} days, Threshold: 90 days",
                    "recommendation": "Rotate access keys every 90 days or migrate workloads to temporary credentials using IAM Roles.",
                    "remediation_type": "automated",
                    "remediation_action_id": "deactivate_old_access_key",
                    "status": "Open",
                    "compliance_mappings": {
                        "CIS": "1.14 Ensure access keys are rotated every 90 days or less",
                        "NIST": "PR.AC-1",
                        "SOC2": "CC6.1",
                        "ISO27001": "A.9.4.3"
                    },
                    "detected_at": "2026-09-09T08:22:00Z"
                })
                
        # 4. Excessive / Wildcard permissions
        for policy in user.get("attached_policies", []):
            policy_name = policy.get("name", "")
            if policy_name in ("AdministratorAccess", "PowerUserAccess") or policy.get("has_wildcard", False):
                findings.append({
                    "id": f"FIND-IAM-ADMIN-{username}",
                    "account_id": account_id,
                    "region": "global",
                    "service": "IAM",
                    "resource_id": user_arn,
                    "resource_name": username,
                    "resource_type": "AWS::IAM::User",
                    "rule_id": "IAM-004",
                    "title": f"Excessive wildcard permissions ('{policy_name}') attached to '{username}'",
                    "severity": "Critical",
                    "risk_score": 10,
                    "description": "Direct attachment of full AdministratorAccess policy violates principle of least privilege and allows total account compromise if hijacked.",
                    "evidence": f"AttachedPolicy: {policy_name}, Permissions: Action: [*], Resource: [*]",
                    "recommendation": "Remove unnecessary administrative permissions and implement least-privilege role-based policies with bounded scopes.",
                    "remediation_type": "manual",
                    "remediation_action_id": None,
                    "status": "Open",
                    "compliance_mappings": {
                        "CIS": "1.16 Ensure IAM policies are not directly attached to users",
                        "NIST": "PR.AC-6",
                        "SOC2": "CC6.3",
                        "ISO27001": "A.9.1.2"
                    },
                    "detected_at": "2026-09-09T08:25:00Z"
                })

        # 5. Inactive users (>90 days)
        if user.get("days_inactive", 0) > 90 and user.get("is_active", True):
            findings.append({
                "id": f"FIND-IAM-INACTIVE-{username}",
                "account_id": account_id,
                "region": "global",
                "service": "IAM",
                "resource_id": user_arn,
                "resource_name": username,
                "resource_type": "AWS::IAM::User",
                "rule_id": "IAM-005",
                "title": f"Inactive IAM user account '{username}' detected (>90 days)",
                "severity": "Low",
                "risk_score": 1,
                "description": f"User '{username}' has had no console or API activity for {user.get('days_inactive')} days. Dormant accounts represent unmanaged attack surfaces.",
                "evidence": f"LastActivity: {user.get('days_inactive')} days ago",
                "recommendation": "Disable or remove inactive IAM users and revoke their associated credentials.",
                "remediation_type": "automated",
                "remediation_action_id": "disable_inactive_user",
                "status": "Open",
                "compliance_mappings": {
                    "CIS": "1.12 Ensure credentials unused for 90 days are disabled",
                    "NIST": "PR.AC-1",
                    "SOC2": "CC6.2",
                    "ISO27001": "A.9.2.6"
                },
                "detected_at": "2026-09-09T08:30:00Z"
            })
            
    return findings
