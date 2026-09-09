"""RDS Security Rules Evaluator."""

from typing import List, Dict, Any

def evaluate_rds_rules(account_id: str, region: str, rds_instances: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings = []
    
    for db in rds_instances:
        db_id = db.get("id", "db-unknown")
        db_arn = f"arn:aws:rds:{region}:{account_id}:db:{db_id}"
        
        # 1. Publicly accessible RDS
        if db.get("publicly_accessible", False):
            findings.append({
                "id": f"FIND-RDS-PUB-{db_id}",
                "account_id": account_id,
                "region": region,
                "service": "RDS",
                "resource_id": db_arn,
                "resource_name": f"{db_id} ({db.get('engine', 'postgres')})",
                "resource_type": "AWS::RDS::DBInstance",
                "rule_id": "RDS-001",
                "title": f"RDS Database instance '{db_id}' is publicly accessible",
                "severity": "Critical",
                "risk_score": 10,
                "description": "Database instance has PubliclyAccessible set to true and resolves to a public IP, exposing internal relational databases to internet port scanners and authentication attacks.",
                "evidence": "PubliclyAccessible: true, Endpoint: Available on public DNS",
                "recommendation": "Modify the RDS instance to set PubliclyAccessible to false and restrict access exclusively to private application subnets.",
                "remediation_type": "automated",
                "remediation_action_id": f"disable_rds_public_access:{db_id}",
                "status": "Open",
                "compliance_mappings": {
                    "CIS": "4.3 Ensure that RDS instances are not publicly accessible",
                    "NIST": "AC-3",
                    "SOC2": "CC6.6",
                    "ISO27001": "A.13.1.1"
                },
                "detected_at": "2026-09-09T09:16:00Z"
            })

        # 2. Storage encryption
        if not db.get("storage_encrypted", True):
            findings.append({
                "id": f"FIND-RDS-ENC-{db_id}",
                "account_id": account_id,
                "region": region,
                "service": "RDS",
                "resource_id": db_arn,
                "resource_name": db_id,
                "resource_type": "AWS::RDS::DBInstance",
                "rule_id": "RDS-002",
                "title": f"RDS Database instance '{db_id}' storage is not encrypted at rest",
                "severity": "High",
                "risk_score": 7,
                "description": "Database tables, automated backups, and read replicas are stored in unencrypted storage volumes.",
                "evidence": "StorageEncrypted: false",
                "recommendation": "Migrate data by taking a snapshot, encrypting the snapshot copy with AWS KMS, and restoring a new encrypted DB instance.",
                "remediation_type": "manual",
                "remediation_action_id": None,
                "status": "Open",
                "compliance_mappings": {
                    "CIS": "4.1 Ensure RDS storage is encrypted",
                    "NIST": "SC-13",
                    "SOC2": "CC6.7",
                    "ISO27001": "A.10.1.1"
                },
                "detected_at": "2026-09-09T09:18:00Z"
            })
            
        # 3. Backup retention
        retention = db.get("backup_retention_days", 0)
        if retention < 7:
            findings.append({
                "id": f"FIND-RDS-BAK-{db_id}",
                "account_id": account_id,
                "region": region,
                "service": "RDS",
                "resource_id": db_arn,
                "resource_name": db_id,
                "resource_type": "AWS::RDS::DBInstance",
                "rule_id": "RDS-003",
                "title": f"RDS Database backup retention period is inadequate ({retention} days)",
                "severity": "Medium",
                "risk_score": 4,
                "description": f"Automated backup retention is set to {retention} days, below recommended security & compliance thresholds of at least 7 to 30 days.",
                "evidence": f"BackupRetentionPeriod: {retention} days (Required: >= 7)",
                "recommendation": "Increase automated backup retention period to at least 7 days to ensure disaster recovery resilience.",
                "remediation_type": "automated",
                "remediation_action_id": f"set_rds_backup_retention:{db_id}",
                "status": "Open",
                "compliance_mappings": {
                    "CIS": "4.2 Ensure RDS automated backup is enabled with retention >= 7 days",
                    "NIST": "CP-9",
                    "SOC2": "CC7.1",
                    "ISO27001": "A.12.3.1"
                },
                "detected_at": "2026-09-09T09:20:00Z"
            })

    return findings
