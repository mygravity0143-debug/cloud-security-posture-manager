"""AWS Lambda Security Rules Evaluator."""

from typing import List, Dict, Any

DEPRECATED_RUNTIMES = ["python2.7", "python3.6", "python3.7", "nodejs10.x", "nodejs12.x", "nodejs14.x", "ruby2.5"]

def evaluate_lambda_rules(account_id: str, region: str, lambda_functions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings = []
    
    for fn in lambda_functions:
        fn_name = fn.get("name", "unknown-function")
        fn_arn = fn.get("arn", f"arn:aws:lambda:{region}:{account_id}:function:{fn_name}")
        runtime = fn.get("runtime", "")
        
        # 1. Public resource policy
        if fn.get("public_policy", False):
            findings.append({
                "id": f"FIND-LAM-PUB-{fn_name}",
                "account_id": account_id,
                "region": region,
                "service": "Lambda",
                "resource_id": fn_arn,
                "resource_name": fn_name,
                "resource_type": "AWS::Lambda::Function",
                "rule_id": "LAM-001",
                "title": f"Lambda function '{fn_name}' has a public invocation policy ('*')",
                "severity": "Critical",
                "risk_score": 10,
                "description": "The function's resource policy allows invocation by any AWS principal or anonymous caller ('Principal': '*'), exposing serverless logic and compute capacity to unauthorized execution.",
                "evidence": "ResourcePolicy: Principal = '*', Action = 'lambda:InvokeFunction'",
                "recommendation": "Restrict the resource policy to specific authorized service principals (e.g. apigateway.amazonaws.com) or IAM roles.",
                "remediation_type": "automated",
                "remediation_action_id": f"restrict_lambda_policy:{fn_name}",
                "status": "Open",
                "compliance_mappings": {
                    "CIS": "4.5 Ensure Lambda functions do not allow global invoke access",
                    "NIST": "AC-3",
                    "SOC2": "CC6.6",
                    "ISO27001": "A.9.4.1"
                },
                "detected_at": "2026-09-09T09:22:00Z"
            })

        # 2. Outdated runtime
        if runtime in DEPRECATED_RUNTIMES:
            findings.append({
                "id": f"FIND-LAM-RUN-{fn_name}",
                "account_id": account_id,
                "region": region,
                "service": "Lambda",
                "resource_id": fn_arn,
                "resource_name": f"{fn_name} ({runtime})",
                "resource_type": "AWS::Lambda::Function",
                "rule_id": "LAM-002",
                "title": f"Lambda function '{fn_name}' uses end-of-life runtime '{runtime}'",
                "severity": "High",
                "risk_score": 7,
                "description": f"The runtime '{runtime}' is deprecated and no longer receives security patches, critical vulnerability updates, or runtime bug fixes from AWS.",
                "evidence": f"Runtime: {runtime} (Deprecated / End-of-Life)",
                "recommendation": "Upgrade function code to supported runtimes (such as Python 3.12 or Node.js 20.x).",
                "remediation_type": "manual",
                "remediation_action_id": None,
                "status": "Open",
                "compliance_mappings": {
                    "CIS": "4.6 Ensure Lambda functions use supported runtimes",
                    "NIST": "SI-2",
                    "SOC2": "CC7.1",
                    "ISO27001": "A.12.6.1"
                },
                "detected_at": "2026-09-09T09:24:00Z"
            })

        # 3. Plaintext environment variables / KMS encryption
        if fn.get("has_unencrypted_env_vars", False):
            findings.append({
                "id": f"FIND-LAM-ENV-{fn_name}",
                "account_id": account_id,
                "region": region,
                "service": "Lambda",
                "resource_id": fn_arn,
                "resource_name": fn_name,
                "resource_type": "AWS::Lambda::Function",
                "rule_id": "LAM-003",
                "title": f"Lambda function '{fn_name}' uses unencrypted environment variables",
                "severity": "Medium",
                "risk_score": 4,
                "description": "Environment variables configured with sensitive keys are not protected with a Customer Managed KMS Key (CMK) helper encryption.",
                "evidence": "KmsKeyArn: Default / Unspecified",
                "recommendation": "Encrypt sensitive configuration variables using AWS Secrets Manager or KMS CMK.",
                "remediation_type": "manual",
                "remediation_action_id": None,
                "status": "Open",
                "compliance_mappings": {
                    "CIS": "4.7 Ensure Lambda environment variables are encrypted with CMK",
                    "NIST": "SC-13",
                    "SOC2": "CC6.7",
                    "ISO27001": "A.10.1.1"
                },
                "detected_at": "2026-09-09T09:25:00Z"
            })
            
    return findings
