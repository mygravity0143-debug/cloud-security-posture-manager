"""EC2 and Security Group Rules Evaluator."""

from typing import List, Dict, Any

def evaluate_ec2_rules(account_id: str, region: str, ec2_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    
    # 1. Security Groups checks
    for sg in ec2_data.get("security_groups", []):
        sg_id = sg.get("id", "sg-unknown")
        sg_name = sg.get("name", sg_id)
        
        for rule in sg.get("inbound_rules", []):
            cidr = rule.get("cidr", "")
            from_port = rule.get("from_port", 0)
            to_port = rule.get("to_port", 0)
            protocol = rule.get("protocol", "-1")
            
            # Check open SSH (port 22)
            if (from_port <= 22 <= to_port or protocol == "-1") and (cidr == "0.0.0.0/0" or cidr == "::/0"):
                findings.append({
                    "id": f"FIND-EC2-SSH-{sg_id}",
                    "account_id": account_id,
                    "region": region,
                    "service": "Security Groups",
                    "resource_id": f"arn:aws:ec2:{region}:{account_id}:security-group/{sg_id}",
                    "resource_name": f"{sg_name} ({sg_id})",
                    "resource_type": "AWS::EC2::SecurityGroup",
                    "rule_id": "EC2-001",
                    "title": f"Security Group '{sg_name}' allows unrestricted SSH access (0.0.0.0/0:22)",
                    "severity": "Critical",
                    "risk_score": 10,
                    "description": "Port 22 is globally open to the entire internet without restriction, inviting automated brute-force attacks, credential stuffing, and unauthorized terminal entry.",
                    "evidence": f"IngressRule: Protocol: tcp, Port: 22, CIDR: {cidr}",
                    "recommendation": "Restrict SSH access to approved corporate IP ranges, VPN gateways, or AWS Systems Manager Session Manager.",
                    "remediation_type": "automated",
                    "remediation_action_id": f"revoke_sg_open_ssh:{sg_id}",
                    "status": "Open",
                    "compliance_mappings": {
                        "CIS": "5.2 Ensure no security groups allow ingress from 0.0.0.0/0 to port 22",
                        "NIST": "PR.AC-5",
                        "SOC2": "CC6.6",
                        "ISO27001": "A.13.1.2"
                    },
                    "detected_at": "2026-09-09T08:50:00Z"
                })

            # Check open RDP (port 3389)
            if (from_port <= 3389 <= to_port or protocol == "-1") and (cidr == "0.0.0.0/0" or cidr == "::/0"):
                findings.append({
                    "id": f"FIND-EC2-RDP-{sg_id}",
                    "account_id": account_id,
                    "region": region,
                    "service": "Security Groups",
                    "resource_id": f"arn:aws:ec2:{region}:{account_id}:security-group/{sg_id}",
                    "resource_name": f"{sg_name} ({sg_id})",
                    "resource_type": "AWS::EC2::SecurityGroup",
                    "rule_id": "EC2-002",
                    "title": f"Security Group '{sg_name}' allows unrestricted RDP access (0.0.0.0/0:3389)",
                    "severity": "Critical",
                    "risk_score": 10,
                    "description": "Windows Remote Desktop Protocol (RDP) port 3389 is exposed to the entire world, exposing instances to BlueKeep-class vulnerabilities and ransomware attacks.",
                    "evidence": f"IngressRule: Protocol: tcp, Port: 3389, CIDR: {cidr}",
                    "recommendation": "Remove 0.0.0.0/0 from port 3389 and mandate AWS Client VPN or Guacamole bastion bastion access.",
                    "remediation_type": "automated",
                    "remediation_action_id": f"revoke_sg_open_rdp:{sg_id}",
                    "status": "Open",
                    "compliance_mappings": {
                        "CIS": "5.3 Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389",
                        "NIST": "PR.AC-5",
                        "SOC2": "CC6.6",
                        "ISO27001": "A.13.1.2"
                    },
                    "detected_at": "2026-09-09T08:52:00Z"
                })

    # 2. EC2 Instances checks
    for inst in ec2_data.get("instances", []):
        inst_id = inst.get("id", "i-unknown")
        inst_name = inst.get("name", inst_id)
        inst_arn = f"arn:aws:ec2:{region}:{account_id}:instance/{inst_id}"
        
        # Public IP exposure
        if inst.get("public_ip") and not inst.get("is_bastion", False):
            findings.append({
                "id": f"FIND-EC2-PUB-{inst_id}",
                "account_id": account_id,
                "region": region,
                "service": "EC2",
                "resource_id": inst_arn,
                "resource_name": f"{inst_name} ({inst_id})",
                "resource_type": "AWS::EC2::Instance",
                "rule_id": "EC2-003",
                "title": f"EC2 Instance '{inst_name}' has a public IP address in private tier",
                "severity": "High",
                "risk_score": 7,
                "description": f"Instance '{inst_name}' ({inst_id}) is directly assigned public IPv4 address {inst.get('public_ip')}, bypassing ingress boundary protections.",
                "evidence": f"PublicIpAddress: {inst.get('public_ip')}, Subnet: {inst.get('subnet_id')}",
                "recommendation": "Place backend and application servers in private subnets behind an Application Load Balancer and NAT Gateway.",
                "remediation_type": "manual",
                "remediation_action_id": None,
                "status": "Open",
                "compliance_mappings": {
                    "CIS": "5.1 Ensure all EC2 instances reside within a VPC with minimal public exposure",
                    "NIST": "AC-4",
                    "SOC2": "CC6.6",
                    "ISO27001": "A.13.1.1"
                },
                "detected_at": "2026-09-09T08:55:00Z"
            })

        # IMDSv2 token enforcement
        if inst.get("imdsv2_required") is False:
            findings.append({
                "id": f"FIND-EC2-IMDS-{inst_id}",
                "account_id": account_id,
                "region": region,
                "service": "EC2",
                "resource_id": inst_arn,
                "resource_name": f"{inst_name} ({inst_id})",
                "resource_type": "AWS::EC2::Instance",
                "rule_id": "EC2-004",
                "title": f"IMDSv2 not enforced on EC2 Instance '{inst_name}'",
                "severity": "Medium",
                "risk_score": 4,
                "description": "Instance Metadata Service Version 1 (IMDSv1) is active without session token requirements, leaving the instance vulnerable to SSRF credential theft.",
                "evidence": "MetadataOptions: HttpTokens = optional",
                "recommendation": "Enforce IMDSv2 by modifying instance metadata options to require HttpTokens = 'required'.",
                "remediation_type": "automated",
                "remediation_action_id": f"enforce_imdsv2:{inst_id}",
                "status": "Open",
                "compliance_mappings": {
                    "CIS": "5.4 Ensure that EC2 instances use IMDSv2",
                    "NIST": "SI-4",
                    "SOC2": "CC6.1",
                    "ISO27001": "A.12.1.2"
                },
                "detected_at": "2026-09-09T08:58:00Z"
            })
            
    return findings
