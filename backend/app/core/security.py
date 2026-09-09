"""Role-Based Access Control (RBAC) and Security Utilities."""

from typing import Dict, Any, List, Optional
from fastapi import Header, HTTPException, status

ROLES = {
    "ADMIN": "Security Administrator",
    "ANALYST": "Security Analyst",
    "VIEWER": "Viewer"
}

ROLE_PERMISSIONS = {
    ROLES["ADMIN"]: {
        "can_scan": True,
        "can_remediate": True,
        "can_update_status": True,
        "can_export_reports": True,
        "can_configure_settings": True,
        "can_view_all": True
    },
    ROLES["ANALYST"]: {
        "can_scan": False,
        "can_remediate": False,
        "can_update_status": True,
        "can_export_reports": True,
        "can_configure_settings": False,
        "can_view_all": True
    },
    ROLES["VIEWER"]: {
        "can_scan": False,
        "can_remediate": False,
        "can_update_status": False,
        "can_export_reports": True,
        "can_configure_settings": False,
        "can_view_all": True
    }
}

DEMO_USERS = [
    {
        "id": "usr-admin-01",
        "username": "sec.admin",
        "name": "Sarah Connor",
        "role": ROLES["ADMIN"],
        "email": "sarah.admin@enterprise-cloud.internal",
        "avatar": "https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=100&h=100&fit=crop"
    },
    {
        "id": "usr-analyst-01",
        "username": "sec.analyst",
        "name": "Marcus Vance",
        "role": ROLES["ANALYST"],
        "email": "marcus.analyst@enterprise-cloud.internal",
        "avatar": "https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=100&h=100&fit=crop"
    },
    {
        "id": "usr-viewer-01",
        "username": "sec.viewer",
        "name": "Auditor Riley",
        "role": ROLES["VIEWER"],
        "email": "riley.audit@external-compliance.org",
        "avatar": "https://images.unsplash.com/photo-1494790108377-be9c29b29330?w=100&h=100&fit=crop"
    }
]

def get_current_user_from_header(x_user_role: Optional[str] = Header(default="Security Administrator")) -> Dict[str, Any]:
    """Retrieve active user context based on header or fallback to default admin."""
    # Find user matching the role header or match by username
    for user in DEMO_USERS:
        if user["role"] == x_user_role or user["username"] == x_user_role:
            return user
            
    # Default to first admin user
    return DEMO_USERS[0]

def check_permission(user: Dict[str, Any], required_permission: str) -> bool:
    """Verify if user has specified permission."""
    role = user.get("role", ROLES["VIEWER"])
    perms = ROLE_PERMISSIONS.get(role, ROLE_PERMISSIONS[ROLES["VIEWER"]])
    if not perms.get(required_permission, False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access Denied: Role '{role}' lacks '{required_permission}' permission."
        )
    return True
