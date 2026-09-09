"""Settings and AWS Configuration API endpoints."""

from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel

from app.scanner.engine import scanner_engine
from app.scanner.providers.aws_client import LiveAWSClient
from app.core.config import settings
from app.core.security import get_current_user_from_header, check_permission

router = APIRouter(prefix="/settings", tags=["Settings"])

class SettingsUpdatePayload(BaseModel):
    mode: str
    aws_region: str
    sns_topic_arn: str
    alert_email: str

class TestAlertPayload(BaseModel):
    channel: str = "all"  # 'sns', 'email', 'dashboard', 'all'

# Runtime settings storage
runtime_settings = {
    "mode": scanner_engine.mode,
    "aws_region": settings.DEFAULT_AWS_REGION,
    "aws_account_id": settings.DEFAULT_AWS_ACCOUNT,
    "sns_topic_arn": settings.DEFAULT_SNS_TOPIC_ARN,
    "alert_email": settings.DEFAULT_ALERT_EMAIL,
    "scan_interval_hours": 6,
    "notifications_enabled": True
}

@router.get("")
def get_settings():
    aws_client = LiveAWSClient(region_name=runtime_settings["aws_region"])
    aws_conn = aws_client.verify_connection()
    
    return {
        "settings": runtime_settings,
        "aws_connection_status": aws_conn,
        "supported_modes": ["simulation", "aws"],
        "supported_regions": [
            "us-east-1", "us-west-2", "eu-west-1", "ap-south-1", "ap-southeast-1"
        ]
    }

@router.post("")
def update_settings(
    payload: SettingsUpdatePayload,
    current_user: dict = Depends(get_current_user_from_header)
):
    check_permission(current_user, "can_configure_settings")

    if payload.mode not in ("simulation", "aws"):
        raise HTTPException(status_code=400, detail="Invalid mode. Must be 'simulation' or 'aws'.")

    runtime_settings["mode"] = payload.mode
    runtime_settings["aws_region"] = payload.aws_region
    runtime_settings["sns_topic_arn"] = payload.sns_topic_arn
    runtime_settings["alert_email"] = payload.alert_email

    scanner_engine.set_mode(payload.mode)
    # Re-run scan with the new mode
    scanner_engine.run_scan()

    return {
        "success": True,
        "message": f"Configuration updated. System active in {payload.mode.upper()} mode.",
        "settings": runtime_settings
    }

@router.post("/test-alert")
def send_test_security_alert(payload: TestAlertPayload):
    """Simulate dispatching a critical security notification to Amazon SNS and Email."""
    timestamp = datetime.now(timezone.utc).isoformat()
    alert_message = {
        "event": "CSPM_CRITICAL_ALERT",
        "timestamp": timestamp,
        "subject": "CRITICAL SECURITY ALERT: Unauthorized IAM policy modification detected",
        "account_id": runtime_settings["aws_account_id"],
        "region": runtime_settings["aws_region"],
        "severity": "Critical",
        "finding": "AdministratorAccess directly assigned to IAM user 'alex.dev'",
        "dispatched_channels": ["Amazon SNS", "Email: " + runtime_settings["alert_email"], "SOC Dashboard Notification Drawer"]
    }
    return {
        "success": True,
        "message": f"Critical security alert successfully dispatched via {payload.channel.upper()}.",
        "alert_payload": alert_message
    }
