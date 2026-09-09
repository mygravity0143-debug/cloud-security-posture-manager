"""Security Scanner Execution API endpoints."""

from typing import Optional
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel

from app.scanner.engine import scanner_engine
from app.core.security import get_current_user_from_header, check_permission

router = APIRouter(prefix="/scan", tags=["Security Scanner"])

class ScanTriggerPayload(BaseModel):
    service: Optional[str] = None

@router.post("")
def trigger_security_scan(
    payload: Optional[ScanTriggerPayload] = None,
    current_user: dict = Depends(get_current_user_from_header)
):
    # RBAC check: only Security Administrator can trigger on-demand scan
    check_permission(current_user, "can_scan")

    service_filter = payload.service if payload else None
    scan_result = scanner_engine.run_scan(service_filter=service_filter)
    
    return {
        "success": True,
        "message": f"Security scan completed successfully across {service_filter or 'all AWS services'}.",
        "data": scan_result
    }

@router.get("/history")
def get_scan_history():
    return {
        "total_scans": len(scanner_engine.scan_history),
        "last_scan_time": scanner_engine.last_scan_time,
        "scan_runs": scanner_engine.scan_history
    }
