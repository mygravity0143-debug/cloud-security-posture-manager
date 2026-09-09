"""Security Findings API endpoints."""

from typing import Optional, List
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from app.scanner.engine import scanner_engine

router = APIRouter(prefix="/findings", tags=["Security Findings"])

class StatusUpdatePayload(BaseModel):
    status: str

@router.get("")
def list_findings(
    severity: Optional[str] = Query(None, description="Filter by severity (Critical, High, Medium, Low)"),
    service: Optional[str] = Query(None, description="Filter by AWS service (IAM, S3, EC2, VPC, etc.)"),
    status: Optional[str] = Query(None, description="Filter by finding status (Open, In Progress, Resolved, Accepted Risk)"),
    search: Optional[str] = Query(None, description="Search keyword in title, resource, description or rule ID"),
):
    findings = scanner_engine.get_findings()
    
    filtered = findings
    if severity and severity.lower() != "all":
        filtered = [f for f in filtered if f.get("severity", "").lower() == severity.lower()]
        
    if service and service.lower() != "all":
        filtered = [f for f in filtered if f.get("service", "").lower() == service.lower()]
        
    if status and status.lower() != "all":
        filtered = [f for f in filtered if f.get("status", "").lower() == status.lower()]
        
    if search:
        s = search.lower()
        filtered = [
            f for f in filtered 
            if s in f.get("title", "").lower() 
            or s in f.get("resource_name", "").lower()
            or s in f.get("resource_id", "").lower()
            or s in f.get("rule_id", "").lower()
            or s in f.get("description", "").lower()
        ]
        
    # Sort by risk score descending
    filtered.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
    
    return {
        "total": len(filtered),
        "total_unfiltered": len(findings),
        "findings": filtered
    }

@router.get("/{finding_id}")
def get_finding_by_id(finding_id: str):
    findings = scanner_engine.get_findings()
    target = next((f for f in findings if f.get("id") == finding_id), None)
    if not target:
        raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found.")
    return target

@router.patch("/{finding_id}/status")
def update_finding_status(finding_id: str, payload: StatusUpdatePayload):
    try:
        updated = scanner_engine.update_finding_status(finding_id, payload.status)
        if not updated:
            raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found.")
        return {
            "success": True,
            "finding_id": finding_id,
            "new_status": payload.status,
            "finding": updated
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
