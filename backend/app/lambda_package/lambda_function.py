"""AWS Lambda Function Handler for Automated Security Posture Scanning.

Workflow:
AWS EventBridge (Cron: 6 hours) -> Lambda Handler -> Security Scanner -> AWS APIs -> Publish Findings & SNS Alerts
"""

import json
import logging
import os
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")

def lambda_handler(event, context):
    logger.info("Starting automated CSPM security scan execution...")
    
    # Initialize AWS clients
    session = boto3.Session(region_name=AWS_REGION)
    s3 = session.client("s3")
    ec2 = session.client("ec2")
    iam = session.client("iam")
    sns = session.client("sns")

    critical_findings = []
    total_findings_count = 0

    # 1. Audit S3 Buckets for Public Exposure
    try:
        buckets = s3.list_buckets().get("Buckets", [])
        for b in buckets:
            bname = b["Name"]
            try:
                pab = s3.get_public_access_block(Bucket=bname)
                conf = pab.get("PublicAccessBlockConfiguration", {})
                is_blocked = conf.get("BlockPublicAcls") and conf.get("BlockPublicPolicy")
            except Exception:
                is_blocked = False
                
            if not is_blocked:
                finding = {
                    "rule": "S3-001",
                    "severity": "Critical",
                    "resource": f"arn:aws:s3:::{bname}",
                    "title": f"S3 Bucket '{bname}' does not enforce Block Public Access"
                }
                critical_findings.append(finding)
                total_findings_count += 1
    except Exception as e:
        logger.error(f"Error scanning S3: {str(e)}")

    # 2. Audit Security Groups for Open Port 22 (SSH) and 3389 (RDP)
    try:
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])
        for sg in sgs:
            sg_id = sg.get("GroupId")
            for perm in sg.get("IpPermissions", []):
                from_port = perm.get("FromPort", 0)
                to_port = perm.get("ToPort", 0)
                protocol = perm.get("IpProtocol", "")
                
                for ip_range in perm.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp")
                    if (cidr == "0.0.0.0/0" or cidr == "::/0"):
                        if from_port <= 22 <= to_port or protocol == "-1":
                            critical_findings.append({
                                "rule": "EC2-001",
                                "severity": "Critical",
                                "resource": sg_id,
                                "title": f"Security Group '{sg_id}' allows unrestricted SSH (0.0.0.0/0:22)"
                            })
                            total_findings_count += 1
                        elif from_port <= 3389 <= to_port:
                            critical_findings.append({
                                "rule": "EC2-002",
                                "severity": "Critical",
                                "resource": sg_id,
                                "title": f"Security Group '{sg_id}' allows unrestricted RDP (0.0.0.0/0:3389)"
                            })
                            total_findings_count += 1
    except Exception as e:
        logger.error(f"Error scanning EC2 Security Groups: {str(e)}")

    # 3. Audit IAM Root Account & Admin Policies
    try:
        summary = iam.get_account_summary().get("SummaryMap", {})
        if summary.get("AccountMFAEnabled", 0) != 1:
            critical_findings.append({
                "rule": "IAM-001",
                "severity": "Critical",
                "resource": "arn:aws:iam::root",
                "title": "AWS Root Account MFA is disabled"
            })
            total_findings_count += 1
    except Exception as e:
        logger.error(f"Error scanning IAM: {str(e)}")

    # 4. Publish Critical Security Findings to SNS
    if critical_findings and SNS_TOPIC_ARN:
        alert_subject = f"CRITICAL SECURITY ALERT: {len(critical_findings)} high-severity misconfigurations detected"
        alert_body = (
            f"CSPM Automated Scanner detected {len(critical_findings)} critical AWS misconfigurations:\n\n"
            + "\n".join([f"- [{f['rule']}] {f['title']} (Resource: {f['resource']})" for f in critical_findings])
            + "\n\nPlease review and remediate immediately in the CSPM Dashboard."
        )
        try:
            sns.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject=alert_subject[:100],
                Message=alert_body
            )
            logger.info(f"Published alert to SNS Topic: {SNS_TOPIC_ARN}")
        except Exception as e:
            logger.error(f"Failed to publish SNS notification: {str(e)}")

    return {
        "statusCode": 200,
        "body": json.dumps({
            "status": "COMPLETED",
            "critical_findings_count": len(critical_findings),
            "total_findings_count": total_findings_count,
            "critical_findings": critical_findings
        })
    }
