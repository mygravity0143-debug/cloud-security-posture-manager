"""Authentication and User Roles API endpoints."""

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.core.security import DEMO_USERS, ROLE_PERMISSIONS, get_current_user_from_header

router = APIRouter(prefix="/auth", tags=["Authentication & RBAC"])

class LoginRequest(BaseModel):
    username: str

@router.get("/me")
def get_current_user(user: dict = Depends(get_current_user_from_header)):
    role = user.get("role")
    permissions = ROLE_PERMISSIONS.get(role, {})
    return {
        "user": user,
        "permissions": permissions
    }

@router.get("/users")
def list_available_roles():
    """List selectable user roles for instant testing of RBAC."""
    return {
        "users": DEMO_USERS
    }

@router.post("/login")
def mock_login(payload: LoginRequest):
    user = next((u for u in DEMO_USERS if u["username"] == payload.username), None)
    if not user:
        user = DEMO_USERS[0]
    return {
        "token": f"mock-jwt-token-{user['id']}",
        "user": user,
        "permissions": ROLE_PERMISSIONS.get(user["role"], {})
    }
