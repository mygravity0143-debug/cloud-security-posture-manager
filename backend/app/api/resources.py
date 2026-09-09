"""AWS Unified Resource Inventory API endpoints."""

from typing import Optional
from fastapi import APIRouter, Query
from app.scanner.providers.mock_provider import mock_provider
from app.scanner.engine import scanner_engine

router = APIRouter(prefix="/aws/resources", tags=["AWS Resources"])

@router.get("")
def get_aws_resources(
    service: Optional[str] = Query(None, description="Filter by service: S3, EC2, RDS, Lambda, KMS, VPC, IAM"),
    status: Optional[str] = Query(None, description="Filter by posture: Compliant, At Risk")
):
    findings = scanner_engine.get_findings()
    open_findings = [f for f in findings if f.get("status") in ("Open", "In Progress")]
    
    # Map finding count by resource id
    findings_by_resource = {}
    for f in open_findings:
        rid = f.get("resource_id")
        findings_by_resource[rid] = findings_by_resource.get(rid, 0) + 1

    resources = []
    
    # S3
    for b in mock_provider.s3_buckets:
        rid = f"arn:aws:s3:::{b['name']}"
        fc = findings_by_resource.get(rid, 0)
        resources.append({
            "id": rid,
            "name": b["name"],
            "service": "S3",
            "type": "AWS::S3::Bucket",
            "region": b["region"],
            "is_public": b["is_public"],
            "encrypted": b["encryption_enabled"],
            "findings_count": fc,
            "status": "At Risk" if fc > 0 else "Compliant",
            "details": f"{b['object_count']} objects ({b['size_gb']} GB)"
        })

    # EC2 Instances
    for inst in mock_provider.ec2_data.get("instances", []):
        rid = f"arn:aws:ec2:{mock_provider.primary_region}:{mock_provider.account_id}:instance/{inst['id']}"
        fc = findings_by_resource.get(rid, 0)
        resources.append({
            "id": rid,
            "name": inst["name"],
            "service": "EC2",
            "type": "AWS::EC2::Instance",
            "region": mock_provider.primary_region,
            "is_public": bool(inst["public_ip"]),
            "encrypted": inst["ebs_encrypted"],
            "findings_count": fc,
            "status": "At Risk" if fc > 0 else "Compliant",
            "details": f"{inst['type']} ({inst['state']})"
        })

    # Security Groups
    for sg in mock_provider.ec2_data.get("security_groups", []):
        rid = f"arn:aws:ec2:{mock_provider.primary_region}:{mock_provider.account_id}:security-group/{sg['id']}"
        fc = findings_by_resource.get(rid, 0)
        resources.append({
            "id": rid,
            "name": sg["name"],
            "service": "Security Groups",
            "type": "AWS::EC2::SecurityGroup",
            "region": mock_provider.primary_region,
            "is_public": any(r.get("cidr") == "0.0.0.0/0" for r in sg.get("inbound_rules", [])),
            "encrypted": True,
            "findings_count": fc,
            "status": "At Risk" if fc > 0 else "Compliant",
            "details": f"{len(sg.get('inbound_rules', []))} inbound rules"
        })

    # RDS
    for db in mock_provider.rds_data:
        rid = f"arn:aws:rds:{mock_provider.primary_region}:{mock_provider.account_id}:db:{db['id']}"
        fc = findings_by_resource.get(rid, 0)
        resources.append({
            "id": rid,
            "name": db["id"],
            "service": "RDS",
            "type": "AWS::RDS::DBInstance",
            "region": mock_provider.primary_region,
            "is_public": db["publicly_accessible"],
            "encrypted": db["storage_encrypted"],
            "findings_count": fc,
            "status": "At Risk" if fc > 0 else "Compliant",
            "details": f"{db['engine']} ({db['instance_class']})"
        })

    # Lambda
    for fn in mock_provider.lambda_data:
        rid = fn["arn"]
        fc = findings_by_resource.get(rid, 0)
        resources.append({
            "id": rid,
            "name": fn["name"],
            "service": "Lambda",
            "type": "AWS::Lambda::Function",
            "region": mock_provider.primary_region,
            "is_public": fn["public_policy"],
            "encrypted": not fn["has_unencrypted_env_vars"],
            "findings_count": fc,
            "status": "At Risk" if fc > 0 else "Compliant",
            "details": f"Runtime: {fn['runtime']}"
        })

    # KMS
    for k in mock_provider.kms_data:
        rid = f"arn:aws:kms:{mock_provider.primary_region}:{mock_provider.account_id}:key/{k['id']}"
        fc = findings_by_resource.get(rid, 0)
        resources.append({
            "id": rid,
            "name": k["alias"],
            "service": "KMS",
            "type": "AWS::KMS::Key",
            "region": mock_provider.primary_region,
            "is_public": k["has_wildcard_policy"],
            "encrypted": True,
            "findings_count": fc,
            "status": "At Risk" if fc > 0 else "Compliant",
            "details": f"Rotation: {'Enabled' if k['rotation_enabled'] else 'Disabled'}"
        })

    # Filter
    filtered = resources
    if service and service.lower() != "all":
        filtered = [r for r in filtered if r["service"].lower() == service.lower()]
    if status and status.lower() != "all":
        filtered = [r for r in filtered if r["status"].lower() == status.lower()]

    return {
        "total": len(filtered),
        "total_unfiltered": len(resources),
        "compliant_count": len([r for r in resources if r["status"] == "Compliant"]),
        "at_risk_count": len([r for r in resources if r["status"] == "At Risk"]),
        "resources": filtered
    }
