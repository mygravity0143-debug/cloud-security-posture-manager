"""VPC and Network Rules Evaluator."""

from typing import List, Dict, Any

def evaluate_vpc_rules(account_id: str, region: str, vpc_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    
    # 1. Default VPC check
    for vpc in vpc_data.get("vpcs", []):
        vpc_id = vpc.get("id", "vpc-unknown")
        if vpc.get("is_default", False):
            findings.append({
                "id": f"FIND-VPC-DEF-{vpc_id}",
                "account_id": account_id,
                "region": region,
                "service": "VPC",
                "resource_id": f"arn:aws:ec2:{region}:{account_id}:vpc/{vpc_id}",
                "resource_name": f"Default VPC ({vpc_id})",
                "resource_type": "AWS::EC2::VPC",
                "rule_id": "VPC-001",
                "title": f"Default VPC '{vpc_id}' exists and is unmanaged",
                "severity": "Low",
                "risk_score": 1,
                "description": "Default VPCs have public subnets by default and lack customized network segmentation, increasing chances of inadvertent public deployment.",
                "evidence": f"VpcId: {vpc_id}, IsDefault: true",
                "recommendation": "Delete the default VPC in all unused regions and utilize custom multi-tier VPC topologies.",
                "remediation_type": "manual",
                "remediation_action_id": None,
                "status": "Open",
                "compliance_mappings": {
                    "CIS": "5.5 Ensure default VPC is deleted",
                    "NIST": "AC-4",
                    "SOC2": "CC6.6",
                    "ISO27001": "A.13.1.1"
                },
                "detected_at": "2026-09-09T09:12:00Z"
            })
            
        # 2. Flow logs check
        if not vpc.get("flow_logs_enabled", True):
            findings.append({
                "id": f"FIND-VPC-FLOW-{vpc_id}",
                "account_id": account_id,
                "region": region,
                "service": "VPC",
                "resource_id": f"arn:aws:ec2:{region}:{account_id}:vpc/{vpc_id}",
                "resource_name": vpc.get("name", vpc_id),
                "resource_type": "AWS::EC2::VPC",
                "rule_id": "VPC-002",
                "title": f"VPC Flow Logs disabled for VPC '{vpc.get('name', vpc_id)}'",
                "severity": "Medium",
                "risk_score": 4,
                "description": "VPC Flow Logs capture IP traffic entering and leaving network interfaces, crucial for detecting lateral movement and network anomalies.",
                "evidence": f"VpcId: {vpc_id}, FlowLogsActive: false",
                "recommendation": "Enable VPC Flow Logs with publishing to Amazon CloudWatch Logs or an Amazon S3 audit bucket.",
                "remediation_type": "automated",
                "remediation_action_id": f"enable_vpc_flow_logs:{vpc_id}",
                "status": "Open",
                "compliance_mappings": {
                    "CIS": "3.9 Ensure VPC flow logging is enabled in all VPCs",
                    "NIST": "AU-12",
                    "SOC2": "CC7.2",
                    "ISO27001": "A.12.4.1"
                },
                "detected_at": "2026-09-09T09:14:00Z"
            })

    return findings
