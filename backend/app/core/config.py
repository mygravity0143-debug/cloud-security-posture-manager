"""Configuration and constants for Cloud Security Posture Manager (CSPM)."""

import os
from typing import Dict, List
from pydantic import BaseModel

class Settings(BaseModel):
    PROJECT_NAME: str = "Cloud Security Posture Manager (CSPM)"
    VERSION: str = "2.4.0"
    API_V1_STR: str = "/api"
    DESCRIPTION: str = "Enterprise Cloud Security Posture Management platform for AWS environments"
    
    # Execution mode: 'simulation' or 'aws'
    DEFAULT_MODE: str = os.getenv("CSPM_MODE", "simulation")
    DEFAULT_AWS_ACCOUNT: str = "123456789012"
    DEFAULT_AWS_REGION: str = "us-east-1"
    
    # Severity Point Weightings (as per specification)
    SEVERITY_WEIGHTS: Dict[str, int] = {
        "Critical": 10,
        "High": 7,
        "Medium": 4,
        "Low": 1,
        "Informational": 0,
    }
    
    # Supported compliance frameworks
    COMPLIANCE_FRAMEWORKS: List[str] = [
        "CIS AWS Foundations Benchmark v2.0",
        "NIST CSF v1.1",
        "ISO/IEC 27001:2022",
        "SOC 2 Type II",
        "AWS Security Best Practices"
    ]
    
    # Notification defaults
    DEFAULT_SNS_TOPIC_ARN: str = "arn:aws:sns:us-east-1:123456789012:cspm-critical-security-alerts"
    DEFAULT_ALERT_EMAIL: str = "security-admin@enterprise-cloud.internal"

settings = Settings()
