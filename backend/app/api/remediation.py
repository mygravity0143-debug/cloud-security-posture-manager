"""Automated Remediation API endpoints."""

from typing import Optional
from fastapi import APIRouter, HTTPException, Depends, Header
from pydantic import BaseModel

from app.scanner.engine import scanner_engine
from app.core.security import get_current_user_from_header, check_permission

router = APIRouter(prefix="/remediation", tags=["Automated Remediation"])

class RemediationRequest(BaseModel):
    finding_id: str

def generate_remediation_code_snippets(finding: dict) -> dict:
    rule_id = finding.get("rule_id", "")
    res_id = finding.get("resource_id", "")
    res_name = finding.get("resource_name", "")

    aws_cli = ""
    terraform = ""

    if rule_id == "EC2-001":
        # Revoke SSH
        sg_id = res_id.split("/")[-1] if "/" in res_id else "sg-xxxx"
        aws_cli = f"aws ec2 revoke-security-group-ingress \\\n    --group-id {sg_id} \\\n    --protocol tcp \\\n    --port 22 \\\n    --cidr 0.0.0.0/0"
        terraform = f'resource "aws_security_group_rule" "allow_ssh" {{\n  type              = "ingress"\n  from_port         = 22\n  to_port           = 22\n  protocol          = "tcp"\n  cidr_blocks       = ["10.0.0.0/8"] # Restrict to internal CIDR\n  security_group_id = "{sg_id}"\n}}'
    elif rule_id == "EC2-002":
        # Revoke RDP
        sg_id = res_id.split("/")[-1] if "/" in res_id else "sg-xxxx"
        aws_cli = f"aws ec2 revoke-security-group-ingress \\\n    --group-id {sg_id} \\\n    --protocol tcp \\\n    --port 3389 \\\n    --cidr 0.0.0.0/0"
        terraform = f'# Remove 0.0.0.0/0 from RDP rules in {sg_id}'
    elif rule_id == "S3-001":
        # S3 BPA
        bucket = res_name
        aws_cli = f"aws s3api put-public-access-block \\\n    --bucket {bucket} \\\n    --public-access-block-configuration \\\n    \"BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true\""
        terraform = f'resource "aws_s3_bucket_public_access_block" "block_{bucket.replace("-", "_")}" {{\n  bucket = "{bucket}"\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}}'
    elif rule_id == "S3-002":
        # S3 Encryption
        bucket = res_name
        aws_cli = f"aws s3api put-bucket-encryption \\\n    --bucket {bucket} \\\n    --server-side-encryption-configuration \\\n    '{{\"Rules\": [{{\"ApplyServerSideEncryptionByDefault\": {{\"SSEAlgorithm\": \"AES256\"}}}}]}}'"
        terraform = f'resource "aws_s3_bucket_server_side_encryption_configuration" "enc_{bucket.replace("-", "_")}" {{\n  bucket = "{bucket}"\n  rule {{\n    apply_server_side_encryption_by_default {{\n      sse_algorithm = "AES256"\n    }}\n  }}\n}}'
    elif rule_id == "KMS-001":
        # KMS Rotation
        key_id = res_id.split("/")[-1] if "/" in res_id else "key-xxxx"
        aws_cli = f"aws kms enable-key-rotation \\\n    --key-id {key_id}"
        terraform = f'resource "aws_kms_key" "key" {{\n  description             = "Customer Master Key"\n  enable_key_rotation     = true\n}}'
    elif rule_id == "EC2-004":
        # IMDSv2
        inst_id = res_id.split("/")[-1] if "/" in res_id else "i-xxxx"
        aws_cli = f"aws ec2 modify-instance-metadata-options \\\n    --instance-id {inst_id} \\\n    --http-tokens required \\\n    --http-endpoint enabled"
        terraform = f'# Update aws_instance metadata_options block:\nmetadata_options {{\n  http_endpoint = "enabled"\n  http_tokens   = "required"\n}}'
    elif rule_id == "IAM-003":
        # Deactivate Key
        aws_cli = "aws iam update-access-key \\\n    --user-name alex.dev \\\n    --access-key-id AKIAI44QH8DHBEXAMPLE2 \\\n    --status Inactive"
        terraform = "# Rotate credentials or utilize IAM Roles for workloads"
    else:
        aws_cli = f"# Manual remediation required for {finding.get('title')}\n# See AWS Well-Architected Security Pillar guidance"
        terraform = f"# Review policy definition for {res_id}"

    return {
        "aws_cli": aws_cli,
        "terraform": terraform
    }

@router.post("")
def execute_remediation(
    payload: RemediationRequest,
    current_user: dict = Depends(get_current_user_from_header)
):
    # RBAC check: only Security Administrator can execute remediation
    check_permission(current_user, "can_remediate")

    result = scanner_engine.execute_remediation(
        finding_id=payload.finding_id,
        user_name=f"{current_user.get('name')} ({current_user.get('role')})"
    )
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("message"))
        
    return result

@router.get("/audit-log")
def get_remediation_audit_log():
    return {
        "total_actions": len(scanner_engine.remediation_audit_logs),
        "audit_logs": scanner_engine.remediation_audit_logs
    }

@router.get("/snippets/{finding_id}")
def get_remediation_snippets(finding_id: str):
    findings = scanner_engine.get_findings()
    finding = next((f for f in findings if f.get("id") == finding_id), None)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
        
    snippets = generate_remediation_code_snippets(finding)
    return {
        "finding_id": finding_id,
        "title": finding.get("title"),
        "remediation_type": finding.get("remediation_type"),
        "snippets": snippets
    }
