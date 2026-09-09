"""CloudTrail Monitoring API endpoints."""

from typing import Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Query
from pydantic import BaseModel

from app.scanner.providers.mock_provider import mock_provider

router = APIRouter(prefix="/cloudtrail", tags=["CloudTrail Monitoring"])

class SimulateEventPayload(BaseModel):
    event_name: str
    event_source: str
    username: str
    severity: str
    status: str
    details: str

@router.get("/events")
def get_cloudtrail_events(
    severity: Optional[str] = Query(None, description="Filter by event severity"),
    category: Optional[str] = Query(None, description="Filter by category: all, critical, iam, network, auth, unauthorized"),
    search: Optional[str] = Query(None, description="Search by username, IP, action, or service")
):
    events = list(mock_provider.cloudtrail_events)
    
    # Category filters
    if category and category.lower() != "all":
        cat = category.lower()
        if cat == "critical":
            events = [e for e in events if e.get("severity") == "Critical"]
        elif cat == "iam":
            events = [e for e in events if "iam" in e.get("event_source", "").lower() or "User" in e.get("event_name", "")]
        elif cat == "network":
            events = [e for e in events if "ec2" in e.get("event_source", "").lower() or "SecurityGroup" in e.get("event_name", "")]
        elif cat == "auth":
            events = [e for e in events if "signin" in e.get("event_source", "").lower() or "Login" in e.get("event_name", "")]
        elif cat == "unauthorized":
            events = [e for e in events if e.get("status") == "AccessDenied" or e.get("error_message")]

    if severity and severity.lower() != "all":
        events = [e for e in events if e.get("severity", "").lower() == severity.lower()]

    if search:
        s = search.lower()
        events = [
            e for e in events
            if s in e.get("username", "").lower()
            or s in e.get("source_ip", "").lower()
            or s in e.get("event_name", "").lower()
            or s in e.get("event_source", "").lower()
            or s in e.get("details", "").lower()
        ]

    # Trail configuration status
    trail_configs = mock_provider.cloudtrail_data.get("trails", [])

    return {
        "total": len(events),
        "events": events,
        "trail_configuration": trail_configs[0] if trail_configs else None,
        "anomalies_detected": len([e for e in events if e.get("severity") == "Critical" or e.get("status") == "AccessDenied"])
    }

@router.post("/simulate-event")
def simulate_new_event(payload: SimulateEventPayload):
    """Simulate receiving a new real-time CloudTrail event."""
    new_event = {
        "id": f"evt-ct-{len(mock_provider.cloudtrail_events) + 1:03d}",
        "event_time": datetime.now(timezone.utc).isoformat(),
        "event_name": payload.event_name,
        "event_source": payload.event_source,
        "username": payload.username,
        "source_ip": "198.51.100.99",
        "severity": payload.severity,
        "status": payload.status,
        "user_agent": "AWS Console / Automated Pipeline",
        "error_message": None if payload.status == "Success" else "AccessDenied",
        "details": payload.details
    }
    mock_provider.cloudtrail_events.insert(0, new_event)
    return {"success": True, "event": new_event}
