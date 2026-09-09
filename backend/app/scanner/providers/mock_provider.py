"""Enterprise Cloud Simulator Provider (High-Fidelity Stateful AWS Mock)."""

import copy
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional

class EnterpriseAWSMockProvider:
    def __init__(self):
        self.reset_to_defaults()

    def reset_to_defaults(self):
        self.account_id = "123456789012"
        self.account_name = "Production (Core Workloads)"
        self.primary_region = "us-east-1"
        self.secondary_region = "ap-south-1"
        
        # IAM State
        self.iam_data = {
            "root_account": {
                "mfa_enabled": False,
                "access_keys_present": False
            },
            "users": [
                {
                    "username": "sarah.devops",
                    "arn": f"arn:aws:iam::{self.account_id}:user/sarah.devops",
                    "mfa_enabled": True,
                    "has_console_access": True,
                    "days_inactive": 1,
                    "is_active": True,
                    "attached_policies": [
                        {"name": "PowerUserAccess", "has_wildcard": False, "arn": "arn:aws:iam::aws:policy/PowerUserAccess"}
                    ],
                    "access_keys": [
                        {"key_id": "AKIAIOSFODNN7EXAMPLE1", "status": "Active", "age_days": 42, "last_used": "1 hour ago"}
                    ]
                },
                {
                    "username": "alex.dev",
                    "arn": f"arn:aws:iam::{self.account_id}:user/alex.dev",
                    "mfa_enabled": False,  # Missing MFA!
                    "has_console_access": True,
                    "days_inactive": 3,
                    "is_active": True,
                    "attached_policies": [
                        {"name": "AdministratorAccess", "has_wildcard": True, "arn": "arn:aws:iam::aws:policy/AdministratorAccess"}  # Wildcard Admin!
                    ],
                    "access_keys": [
                        {"key_id": "AKIAI44QH8DHBEXAMPLE2", "status": "Active", "age_days": 145, "last_used": "2 days ago"}  # Old key!
                    ]
                },
                {
                    "username": "legacy-service-account",
                    "arn": f"arn:aws:iam::{self.account_id}:user/legacy-service-account",
                    "mfa_enabled": False,
                    "has_console_access": False,
                    "days_inactive": 118,  # Inactive > 90 days!
                    "is_active": True,
                    "attached_policies": [
                        {"name": "AmazonS3FullAccess", "has_wildcard": True, "arn": "arn:aws:iam::aws:policy/AmazonS3FullAccess"}
                    ],
                    "access_keys": [
                        {"key_id": "AKIAIOSFODNN7EXAMPLE3", "status": "Active", "age_days": 210, "last_used": "118 days ago"}  # Inactive key!
                    ]
                },
                {
                    "username": "contractor.temp",
                    "arn": f"arn:aws:iam::{self.account_id}:user/contractor.temp",
                    "mfa_enabled": True,
                    "has_console_access": True,
                    "days_inactive": 12,
                    "is_active": True,
                    "attached_policies": [
                        {"name": "ReadOnlyAccess", "has_wildcard": False, "arn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}
                    ],
                    "access_keys": []
                }
            ],
            "roles": [
                {
                    "role_name": "EC2-Admin-SuperRole",
                    "arn": f"arn:aws:iam::{self.account_id}:role/EC2-Admin-SuperRole",
                    "trust_principal": "ec2.amazonaws.com",
                    "attached_policies": ["AdministratorAccess"],
                    "risk_level": "Critical"
                },
                {
                    "role_name": "LambdaExecutionRole",
                    "arn": f"arn:aws:iam::{self.account_id}:role/LambdaExecutionRole",
                    "trust_principal": "lambda.amazonaws.com",
                    "attached_policies": ["AWSLambdaBasicExecutionRole", "AmazonDynamoDBReadOnlyAccess"],
                    "risk_level": "Low"
                },
                {
                    "role_name": "SecurityAuditAssumedRole",
                    "arn": f"arn:aws:iam::{self.account_id}:role/SecurityAuditAssumedRole",
                    "trust_principal": "arn:aws:iam::999988887777:root",
                    "attached_policies": ["SecurityAudit"],
                    "risk_level": "Low"
                }
            ]
        }

        # S3 Buckets
        self.s3_buckets = [
            {
                "name": "acme-customer-pii-raw",
                "region": "us-east-1",
                "creation_date": "2024-03-15",
                "is_public": True,  # Public exposure!
                "block_public_access": False,
                "encryption_enabled": False,  # No encryption!
                "enforces_https": False,
                "logging_enabled": False,
                "versioning_enabled": False,
                "object_count": 142095,
                "size_gb": 48.6
            },
            {
                "name": "acme-finance-backup-2024",
                "region": "us-east-1",
                "creation_date": "2024-01-10",
                "is_public": False,
                "block_public_access": True,
                "encryption_enabled": True,
                "enforces_https": False,  # Missing HTTPS enforce!
                "logging_enabled": False,
                "versioning_enabled": True,
                "object_count": 8920,
                "size_gb": 12.4
            },
            {
                "name": "acme-app-assets-prod",
                "region": "us-east-1",
                "creation_date": "2024-02-01",
                "is_public": False,
                "block_public_access": True,
                "encryption_enabled": True,
                "enforces_https": True,
                "logging_enabled": True,
                "versioning_enabled": True,
                "object_count": 45100,
                "size_gb": 5.2
            },
            {
                "name": "acme-cloudtrail-logs-vault",
                "region": "us-east-1",
                "creation_date": "2023-11-20",
                "is_public": False,
                "block_public_access": True,
                "encryption_enabled": True,
                "enforces_https": True,
                "logging_enabled": True,
                "versioning_enabled": True,
                "object_count": 520000,
                "size_gb": 128.5
            }
        ]

        # EC2 & Security Groups
        self.ec2_data = {
            "security_groups": [
                {
                    "id": "sg-0a1b2c3d4e5f-public-web",
                    "name": "prod-public-web-sg",
                    "description": "Security group for public facing ALBs and web nodes",
                    "vpc_id": "vpc-0123456789abcdef0",
                    "inbound_rules": [
                        {"protocol": "tcp", "from_port": 80, "to_port": 80, "cidr": "0.0.0.0/0", "description": "HTTP"},
                        {"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr": "0.0.0.0/0", "description": "HTTPS"},
                        {"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "0.0.0.0/0", "description": "SSH Open to World!"}  # Critical SSH open!
                    ]
                },
                {
                    "id": "sg-0987654321ab-bastion",
                    "name": "bastion-windows-admin-sg",
                    "description": "Windows bastion jump box",
                    "vpc_id": "vpc-0123456789abcdef0",
                    "inbound_rules": [
                        {"protocol": "tcp", "from_port": 3389, "to_port": 3389, "cidr": "0.0.0.0/0", "description": "RDP Open to World!"}  # Critical RDP open!
                    ]
                },
                {
                    "id": "sg-1122334455cc-db-internal",
                    "name": "internal-db-tier-sg",
                    "description": "Private database tier SG",
                    "vpc_id": "vpc-0123456789abcdef0",
                    "inbound_rules": [
                        {"protocol": "tcp", "from_port": 5432, "to_port": 5432, "cidr": "10.0.0.0/16", "description": "Postgres Internal Only"}
                    ]
                }
            ],
            "instances": [
                {
                    "id": "i-0a1b2c3d4e5f67890",
                    "name": "prod-api-server-01",
                    "state": "running",
                    "type": "c6i.xlarge",
                    "public_ip": "54.210.88.19",  # Public IP on backend server!
                    "private_ip": "10.0.1.45",
                    "subnet_id": "subnet-01234-app-tier",
                    "security_groups": ["sg-0a1b2c3d4e5f-public-web"],
                    "imdsv2_required": False,  # Missing IMDSv2!
                    "ebs_encrypted": True,
                    "is_bastion": False
                },
                {
                    "id": "i-0fe9dcba876543210",
                    "name": "analytics-worker-02",
                    "state": "running",
                    "type": "m6i.2xlarge",
                    "public_ip": None,
                    "private_ip": "10.0.2.112",
                    "subnet_id": "subnet-05678-private-tier",
                    "security_groups": ["sg-1122334455cc-db-internal"],
                    "imdsv2_required": True,
                    "ebs_encrypted": True,
                    "is_bastion": False
                },
                {
                    "id": "i-056789abcdef01234",
                    "name": "bastion-host-jumppoint",
                    "state": "running",
                    "type": "t3.micro",
                    "public_ip": "34.201.12.99",
                    "private_ip": "10.0.0.15",
                    "subnet_id": "subnet-09999-public-tier",
                    "security_groups": ["sg-0987654321ab-bastion"],
                    "imdsv2_required": False,
                    "ebs_encrypted": True,
                    "is_bastion": True
                }
            ]
        }

        # VPCs
        self.vpc_data = {
            "vpcs": [
                {
                    "id": "vpc-0123456789abcdef0",
                    "name": "production-core-vpc",
                    "cidr": "10.0.0.0/16",
                    "is_default": False,
                    "flow_logs_enabled": False  # Missing Flow Logs!
                },
                {
                    "id": "vpc-default-us-east-1",
                    "name": "Default VPC",
                    "cidr": "172.31.0.0/16",
                    "is_default": True,  # Unused Default VPC present!
                    "flow_logs_enabled": False
                }
            ]
        }

        # CloudTrail
        self.cloudtrail_data = {
            "trails": [
                {
                    "name": "acme-enterprise-security-trail",
                    "arn": f"arn:aws:cloudtrail:{self.primary_region}:{self.account_id}:trail/acme-enterprise-security-trail",
                    "is_multi_region": False,  # Only single-region!
                    "log_validation_enabled": False,  # Missing log file validation!
                    "kms_key_id": None,  # No KMS CMK!
                    "s3_bucket_name": "acme-cloudtrail-logs-vault",
                    "is_logging": True
                }
            ],
            "unauthorized_events": [
                {"source_ip": "198.51.100.23", "event_name": "GetSecretValue", "error_code": "AccessDenied", "time": "2026-09-09T07:12:00Z"},
                {"source_ip": "203.0.113.88", "event_name": "AuthorizeSecurityGroupIngress", "error_code": "UnauthorizedOperation", "time": "2026-09-09T08:04:00Z"},
                {"source_ip": "198.51.100.23", "event_name": "AssumeRole", "error_code": "AccessDenied", "time": "2026-09-09T08:45:00Z"}
            ]
        }

        # RDS Databases
        self.rds_data = [
            {
                "id": "prod-postgres-db",
                "engine": "postgres-15.4",
                "instance_class": "db.r6g.2xlarge",
                "storage_encrypted": True,
                "publicly_accessible": True,  # Public RDS!
                "backup_retention_days": 14,
                "multi_az": True,
                "endpoint": "prod-postgres-db.c7x8y9z0.us-east-1.rds.amazonaws.com"
            },
            {
                "id": "staging-mysql-replica",
                "engine": "mysql-8.0",
                "instance_class": "db.t4g.medium",
                "storage_encrypted": False,  # Unencrypted DB!
                "publicly_accessible": False,
                "backup_retention_days": 3,  # Retention < 7 days!
                "multi_az": False,
                "endpoint": "staging-mysql-replica.c7x8y9z0.us-east-1.rds.amazonaws.com"
            }
        ]

        # Lambda Functions
        self.lambda_data = [
            {
                "name": "legacy-webhook-handler",
                "arn": f"arn:aws:lambda:us-east-1:{self.account_id}:function:legacy-webhook-handler",
                "runtime": "python3.7",  # Deprecated runtime!
                "public_policy": True,  # Public invoke policy!
                "has_unencrypted_env_vars": True,
                "last_modified": "2023-04-12"
            },
            {
                "name": "order-processor",
                "arn": f"arn:aws:lambda:us-east-1:{self.account_id}:function:order-processor",
                "runtime": "python3.11",
                "public_policy": False,
                "has_unencrypted_env_vars": False,
                "last_modified": "2026-08-10"
            },
            {
                "name": "thumbnail-generator",
                "arn": f"arn:aws:lambda:us-east-1:{self.account_id}:function:thumbnail-generator",
                "runtime": "nodejs20.x",
                "public_policy": False,
                "has_unencrypted_env_vars": False,
                "last_modified": "2026-07-22"
            }
        ]

        # KMS Keys
        self.kms_data = [
            {
                "id": "key-prod-data-key-001",
                "alias": "alias/prod-data-encryption-key",
                "key_manager": "CUSTOMER",
                "rotation_enabled": False,  # Rotation disabled!
                "has_wildcard_policy": True,  # Overly broad policy!
                "state": "Enabled"
            },
            {
                "id": "key-app-secrets-key-002",
                "alias": "alias/app-secrets-key",
                "key_manager": "CUSTOMER",
                "rotation_enabled": True,
                "has_wildcard_policy": False,
                "state": "Enabled"
            }
        ]

        # Real-time CloudTrail Event Log for SOC Monitoring
        self.cloudtrail_events = [
            {
                "id": "evt-ct-001",
                "event_time": "2026-09-09T09:35:12Z",
                "event_name": "ConsoleLogin",
                "event_source": "signin.amazonaws.com",
                "username": "root",
                "source_ip": "198.51.100.44",
                "severity": "Critical",
                "status": "Success",
                "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
                "error_message": None,
                "details": "Root account console login succeeded without MFA token verification challenge."
            },
            {
                "id": "evt-ct-002",
                "event_time": "2026-09-09T09:28:44Z",
                "event_name": "AuthorizeSecurityGroupIngress",
                "event_source": "ec2.amazonaws.com",
                "username": "alex.dev",
                "source_ip": "203.0.113.88",
                "severity": "High",
                "status": "Success",
                "user_agent": "aws-cli/2.15.15 Python/3.11",
                "error_message": None,
                "details": "Modified security group 'sg-0a1b2c3d4e5f-public-web' adding 0.0.0.0/0 on port 22."
            },
            {
                "id": "evt-ct-003",
                "event_time": "2026-09-09T09:15:20Z",
                "event_name": "PutBucketPolicy",
                "event_source": "s3.amazonaws.com",
                "username": "sarah.devops",
                "source_ip": "54.240.198.1",
                "severity": "Medium",
                "status": "Success",
                "user_agent": "Terraform/1.7.0 (+https://www.terraform.io)",
                "error_message": None,
                "details": "Updated access policy on S3 bucket 'acme-customer-pii-raw'."
            },
            {
                "id": "evt-ct-004",
                "event_time": "2026-09-09T09:02:18Z",
                "event_name": "GetSecretValue",
                "event_source": "secretsmanager.amazonaws.com",
                "username": "contractor.temp",
                "source_ip": "198.51.100.23",
                "severity": "High",
                "status": "AccessDenied",
                "user_agent": "Boto3/1.34.0 Python/3.12",
                "error_message": "User contractor.temp is not authorized to perform secretsmanager:GetSecretValue on resource arn:aws:secretsmanager:us-east-1:123456789012:secret:prod-db-credentials",
                "details": "Unauthorized attempt to read database production master secrets."
            },
            {
                "id": "evt-ct-005",
                "event_time": "2026-09-09T08:44:02Z",
                "event_name": "CreateUser",
                "event_source": "iam.amazonaws.com",
                "username": "alex.dev",
                "source_ip": "203.0.113.88",
                "severity": "High",
                "status": "Success",
                "user_agent": "aws-cli/2.15.15",
                "error_message": None,
                "details": "Created new IAM user 'auditor-guest' and requested console access password."
            },
            {
                "id": "evt-ct-006",
                "event_time": "2026-09-09T08:20:11Z",
                "event_name": "AttachUserPolicy",
                "event_source": "iam.amazonaws.com",
                "username": "alex.dev",
                "source_ip": "203.0.113.88",
                "severity": "Critical",
                "status": "Success",
                "user_agent": "aws-cli/2.15.15",
                "error_message": None,
                "details": "Attached managed policy 'AdministratorAccess' directly to user 'alex.dev'."
            },
            {
                "id": "evt-ct-007",
                "event_time": "2026-09-09T07:55:40Z",
                "event_name": "StopLogging",
                "event_source": "cloudtrail.amazonaws.com",
                "username": "unknown-intruder",
                "source_ip": "185.220.101.5",
                "severity": "Critical",
                "status": "AccessDenied",
                "user_agent": "python-requests/2.31.0",
                "error_message": "AccessDenied: User lacks cloudtrail:StopLogging permission",
                "details": "Blocked adversarial attempt to terminate CloudTrail audit logging stream."
            }
        ]

    # Stateful Automated Remediation Handlers
    def remediate(self, action_id: str) -> Dict[str, Any]:
        """Execute safe automated remediation directly mutating the stateful mock environment."""
        action_parts = action_id.split(":")
        verb = action_parts[0]
        target = action_parts[1] if len(action_parts) > 1 else None

        if verb == "enable_s3_block_public_access":
            for b in self.s3_buckets:
                if b["name"] == "acme-customer-pii-raw":
                    b["block_public_access"] = True
                    b["is_public"] = False
            return {"success": True, "message": "Successfully enabled S3 Block Public Access on 'acme-customer-pii-raw' and revoked public read/write grants."}

        elif verb == "enable_s3_encryption":
            for b in self.s3_buckets:
                if b["name"] == "acme-customer-pii-raw":
                    b["encryption_enabled"] = True
            return {"success": True, "message": "Successfully applied default AES-256 SSE-S3 encryption to bucket 'acme-customer-pii-raw'."}

        elif verb == "enforce_s3_https_policy":
            for b in self.s3_buckets:
                b["enforces_https"] = True
            return {"success": True, "message": "Attached explicit HTTPS-only (aws:SecureTransport: true) bucket policy to all active buckets."}

        elif verb == "enable_s3_versioning":
            for b in self.s3_buckets:
                b["versioning_enabled"] = True
            return {"success": True, "message": "Enabled S3 object versioning with lifecycle archiving rules."}

        elif verb == "revoke_sg_open_ssh":
            sg_id = target or "sg-0a1b2c3d4e5f-public-web"
            for sg in self.ec2_data["security_groups"]:
                if sg["id"] == sg_id:
                    sg["inbound_rules"] = [r for r in sg["inbound_rules"] if not (r.get("from_port") == 22 and r.get("cidr") == "0.0.0.0/0")]
            return {"success": True, "message": f"Revoked unrestricted 0.0.0.0/0:22 ingress rule from security group '{sg_id}'."}

        elif verb == "revoke_sg_open_rdp":
            sg_id = target or "sg-0987654321ab-bastion"
            for sg in self.ec2_data["security_groups"]:
                if sg["id"] == sg_id:
                    sg["inbound_rules"] = [r for r in sg["inbound_rules"] if not (r.get("from_port") == 3389 and r.get("cidr") == "0.0.0.0/0")]
            return {"success": True, "message": f"Revoked unrestricted 0.0.0.0/0:3389 ingress rule from security group '{sg_id}'."}

        elif verb == "enforce_imdsv2":
            inst_id = target or "i-0a1b2c3d4e5f67890"
            for inst in self.ec2_data["instances"]:
                if inst["id"] == inst_id or target is None:
                    inst["imdsv2_required"] = True
            return {"success": True, "message": f"Configured IMDSv2 (HttpTokens = required) on instance '{inst_id}'."}

        elif verb == "enable_kms_key_rotation":
            key_id = target or "key-prod-data-key-001"
            for k in self.kms_data:
                if k["id"] == key_id:
                    k["rotation_enabled"] = True
            return {"success": True, "message": f"Enabled automatic annual rotation for KMS Customer Managed Key '{key_id}'."}

        elif verb == "deactivate_old_access_key":
            for user in self.iam_data["users"]:
                for k in user.get("access_keys", []):
                    if k["age_days"] > 90:
                        k["status"] = "Inactive"
            return {"success": True, "message": "Deactivated all IAM access keys older than 90 days."}

        elif verb == "enforce_user_mfa_policy":
            for user in self.iam_data["users"]:
                user["mfa_enabled"] = True
            return {"success": True, "message": "Enforced mandatory virtual MFA registration for all active console users."}

        elif verb == "disable_inactive_user":
            for user in self.iam_data["users"]:
                if user.get("days_inactive", 0) > 90:
                    user["is_active"] = False
            return {"success": True, "message": "Disabled dormant user accounts (>90 days without activity)."}

        elif verb == "enable_ct_multi_region":
            for t in self.cloudtrail_data["trails"]:
                t["is_multi_region"] = True
            return {"success": True, "message": "CloudTrail configured as Multi-Region trail across all AWS regions."}

        elif verb == "enable_ct_log_validation":
            for t in self.cloudtrail_data["trails"]:
                t["log_validation_enabled"] = True
            return {"success": True, "message": "Enabled cryptographic log file validation digests on CloudTrail audit logs."}

        elif verb == "enable_vpc_flow_logs":
            for vpc in self.vpc_data["vpcs"]:
                vpc["flow_logs_enabled"] = True
            return {"success": True, "message": "Enabled VPC Flow Logs streaming to CloudWatch Logs."}

        elif verb == "disable_rds_public_access":
            db_id = target or "prod-postgres-db"
            for db in self.rds_data:
                if db["id"] == db_id:
                    db["publicly_accessible"] = False
            return {"success": True, "message": f"Modified RDS instance '{db_id}' to set PubliclyAccessible = false."}

        elif verb == "set_rds_backup_retention":
            db_id = target or "staging-mysql-replica"
            for db in self.rds_data:
                if db["id"] == db_id:
                    db["backup_retention_days"] = 14
            return {"success": True, "message": f"Configured 14-day automated backup retention period on RDS instance '{db_id}'."}

        elif verb == "restrict_lambda_policy":
            fn_name = target or "legacy-webhook-handler"
            for fn in self.lambda_data:
                if fn["name"] == fn_name:
                    fn["public_policy"] = False
            return {"success": True, "message": f"Removed wildcard invocation grant ('*') from Lambda function '{fn_name}' resource policy."}

        return {"success": False, "message": f"Unknown remediation action identifier: '{action_id}'"}

# Singleton instance
mock_provider = EnterpriseAWSMockProvider()
