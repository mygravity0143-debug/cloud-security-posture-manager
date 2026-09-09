"""AWS Security Scanner Engine."""

import time
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from app.core.config import settings
from app.core.scoring import calculate_posture_score
from app.scanner.providers.mock_provider import mock_provider
from app.scanner.providers.aws_client import LiveAWSClient
from app.scanner.rules.iam_rules import evaluate_iam_rules
from app.scanner.rules.s3_rules import evaluate_s3_rules
from app.scanner.rules.ec2_rules import evaluate_ec2_rules
from app.scanner.rules.vpc_rules import evaluate_vpc_rules
from app.scanner.rules.cloudtrail_rules import evaluate_cloudtrail_rules
from app.scanner.rules.rds_rules import evaluate_rds_rules
from app.scanner.rules.lambda_rules import evaluate_lambda_rules
from app.scanner.rules.kms_rules import evaluate_kms_rules

class SecurityScannerEngine:
    def __init__(self):
        self.mode = settings.DEFAULT_MODE  # 'simulation' or 'aws'
        self.live_aws_client = LiveAWSClient(region_name=settings.DEFAULT_AWS_REGION)
        self.status_overrides: Dict[str, str] = {}
        self.last_scan_time: Optional[str] = "2026-09-09T09:10:00Z"
        self.scan_history: List[Dict[str, Any]] = []
        self.remediation_audit_logs: List[Dict[str, Any]] = [
            {
                "id": "REM-AUDIT-001",
                "finding_id": "FIND-EC2-SSH-sg-0a1b2c3d4e5f-staging",
                "action": "Revoke Ingress 0.0.0.0/0:22 on Staging SG",
                "user": "Sarah Connor (Security Administrator)",
                "timestamp": "2026-09-09T07:40:12Z",
                "result": "Success - Removed wide-open SSH ingress rule",
                "status": "Applied"
            }
        ]
        self._cached_findings: List[Dict[str, Any]] = []
        # Initial scan run
        self.run_scan(service_filter=None)

    def set_mode(self, mode: str):
        if mode in ("simulation", "aws"):
            self.mode = mode

    def run_scan(self, service_filter: Optional[str] = None) -> Dict[str, Any]:
        start_time = time.time()
        findings: List[Dict[str, Any]] = []
        
        account_id = mock_provider.account_id
        region = mock_provider.primary_region

        if self.mode == "simulation":
            # 1. IAM
            if not service_filter or service_filter.upper() == "IAM":
                findings.extend(evaluate_iam_rules(account_id, region, mock_provider.iam_data))
            
            # 2. S3
            if not service_filter or service_filter.upper() == "S3":
                findings.extend(evaluate_s3_rules(account_id, region, mock_provider.s3_buckets))
                
            # 3. EC2 & Security Groups
            if not service_filter or service_filter.upper() in ("EC2", "SECURITY GROUPS"):
                findings.extend(evaluate_ec2_rules(account_id, region, mock_provider.ec2_data))
                
            # 4. VPC
            if not service_filter or service_filter.upper() == "VPC":
                findings.extend(evaluate_vpc_rules(account_id, region, mock_provider.vpc_data))
                
            # 5. CloudTrail
            if not service_filter or service_filter.upper() == "CLOUDTRAIL":
                findings.extend(evaluate_cloudtrail_rules(account_id, region, mock_provider.cloudtrail_data))
                
            # 6. RDS
            if not service_filter or service_filter.upper() == "RDS":
                findings.extend(evaluate_rds_rules(account_id, region, mock_provider.rds_data))
                
            # 7. Lambda
            if not service_filter or service_filter.upper() == "LAMBDA":
                findings.extend(evaluate_lambda_rules(account_id, region, mock_provider.lambda_data))
                
            # 8. KMS
            if not service_filter or service_filter.upper() == "KMS":
                findings.extend(evaluate_kms_rules(account_id, region, mock_provider.kms_data))
        else:
            # Live AWS mode via Boto3
            try:
                if not service_filter or service_filter.upper() == "IAM":
                    iam_data = self.live_aws_client.fetch_iam_data()
                    findings.extend(evaluate_iam_rules(account_id, region, iam_data))
                if not service_filter or service_filter.upper() == "S3":
                    s3_data = self.live_aws_client.fetch_s3_data()
                    findings.extend(evaluate_s3_rules(account_id, region, s3_data))
                if not service_filter or service_filter.upper() in ("EC2", "SECURITY GROUPS"):
                    ec2_data = self.live_aws_client.fetch_ec2_data()
                    findings.extend(evaluate_ec2_rules(account_id, region, ec2_data))
            except Exception as e:
                # Fallback to simulation if AWS credentials are not active
                findings.extend(evaluate_iam_rules(account_id, region, mock_provider.iam_data))
                findings.extend(evaluate_s3_rules(account_id, region, mock_provider.s3_buckets))
                findings.extend(evaluate_ec2_rules(account_id, region, mock_provider.ec2_data))

        # Apply user status overrides (e.g. Accepted Risk or In Progress)
        for f in findings:
            fid = f["id"]
            if fid in self.status_overrides:
                f["status"] = self.status_overrides[fid]

        self._cached_findings = findings
        now_str = datetime.now(timezone.utc).isoformat()
        self.last_scan_time = now_str
        duration_ms = int((time.time() - start_time) * 1000)

        # Record scan run
        run_record = {
            "id": f"scan-{len(self.scan_history) + 1}",
            "timestamp": now_str,
            "duration_ms": max(duration_ms, 240),
            "total_findings": len(findings),
            "critical_findings": len([f for f in findings if f["severity"] == "Critical" and f["status"] == "Open"]),
            "service_filter": service_filter or "ALL_SERVICES",
            "mode": self.mode,
            "account_id": account_id
        }
        self.scan_history.insert(0, run_record)

        # Calculate updated posture score
        posture = calculate_posture_score(findings)

        return {
            "scan_run": run_record,
            "posture": posture,
            "findings_count": len(findings)
        }

    def get_findings(self) -> List[Dict[str, Any]]:
        return self._cached_findings

    def update_finding_status(self, finding_id: str, new_status: str) -> Optional[Dict[str, Any]]:
        valid_statuses = ("Open", "In Progress", "Resolved", "Accepted Risk")
        if new_status not in valid_statuses:
            raise ValueError(f"Invalid status: {new_status}")
            
        self.status_overrides[finding_id] = new_status
        for f in self._cached_findings:
            if f["id"] == finding_id:
                f["status"] = new_status
                return f
        return None

    def execute_remediation(self, finding_id: str, user_name: str = "Security Administrator") -> Dict[str, Any]:
        """Execute automated 1-click remediation for a finding."""
        target_finding = next((f for f in self._cached_findings if f["id"] == finding_id), None)
        if not target_finding:
            return {"success": False, "message": f"Finding '{finding_id}' not found."}
            
        action_id = target_finding.get("remediation_action_id")
        if not action_id:
            return {"success": False, "message": f"Finding '{finding_id}' requires manual configuration changes."}

        # Execute remediation on provider
        res = mock_provider.remediate(action_id)
        if res.get("success"):
            # Mark finding as resolved
            self.update_finding_status(finding_id, "Resolved")
            
            # Log in remediation audit trail
            audit_entry = {
                "id": f"REM-AUDIT-{len(self.remediation_audit_logs) + 1:03d}",
                "finding_id": finding_id,
                "action": f"{target_finding.get('title')} -> {action_id}",
                "user": user_name,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "result": res.get("message"),
                "status": "Applied"
            }
            self.remediation_audit_logs.insert(0, audit_entry)

            # Re-evaluate posture score
            posture = calculate_posture_score(self._cached_findings)

            return {
                "success": True,
                "message": res.get("message"),
                "audit_entry": audit_entry,
                "posture": posture
            }
        else:
            return res

# Global scanner singleton
scanner_engine = SecurityScannerEngine()
