"""IAM Security Analyzer API endpoints."""

from fastapi import APIRouter
from app.scanner.providers.mock_provider import mock_provider

router = APIRouter(prefix="/iam", tags=["IAM Security Analyzer"])

@router.get("/users")
def get_iam_users():
    raw_users = mock_provider.iam_data.get("users", [])
    users_with_risk = []
    
    for u in raw_users:
        # Evaluate risk level
        has_wildcard = any(p.get("has_wildcard") for p in u.get("attached_policies", []))
        no_mfa = not u.get("mfa_enabled")
        has_old_key = any(k.get("age_days", 0) > 90 for k in u.get("access_keys", []))
        is_inactive = u.get("days_inactive", 0) > 90
        
        if has_wildcard:
            risk_level = "Critical"
            risk_badge = "rose"
            risk_desc = "Wildcard AdministratorAccess assigned directly"
        elif no_mfa and u.get("has_console_access"):
            risk_level = "High"
            risk_badge = "amber"
            risk_desc = "Console access without Multi-Factor Authentication"
        elif has_old_key:
            risk_level = "Medium"
            risk_badge = "yellow"
            risk_desc = "Active programmatic access key older than 90 days"
        elif is_inactive:
            risk_level = "Low"
            risk_badge = "blue"
            risk_desc = "Dormant user account with no recent activity"
        else:
            risk_level = "Secure"
            risk_badge = "emerald"
            risk_desc = "Least privilege enforced and MFA active"

        users_with_risk.append({
            **u,
            "risk_level": risk_level,
            "risk_badge": risk_badge,
            "risk_reason": risk_desc,
            "key_count": len(u.get("access_keys", []))
        })
        
    return {
        "total_users": len(users_with_risk),
        "root_account": mock_provider.iam_data.get("root_account", {}),
        "users": users_with_risk
    }

@router.get("/roles")
def get_iam_roles():
    roles = mock_provider.iam_data.get("roles", [])
    return {
        "total_roles": len(roles),
        "roles": roles
    }

@router.get("/summary")
def get_iam_summary():
    users = mock_provider.iam_data.get("users", [])
    root = mock_provider.iam_data.get("root_account", {})
    
    no_mfa_count = len([u for u in users if not u.get("mfa_enabled") and u.get("has_console_access")])
    old_keys_count = sum(len([k for k in u.get("access_keys", []) if k.get("age_days", 0) > 90 and k.get("status") == "Active"]) for u in users)
    admin_users_count = len([u for u in users if any(p.get("has_wildcard") for p in u.get("attached_policies", []))])

    return {
        "root_mfa_enabled": root.get("mfa_enabled", False),
        "total_iam_users": len(users),
        "users_without_mfa": no_mfa_count,
        "active_keys_over_90_days": old_keys_count,
        "users_with_admin_privileges": admin_users_count,
        "security_recommendations": [
            "Enable virtual/hardware MFA token for the AWS Root account immediately.",
            "Remove direct AdministratorAccess from alex.dev and delegate scoped IAM roles.",
            "Rotate or deactivate access keys older than 90 days."
        ]
    }
