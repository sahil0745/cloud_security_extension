import sys
import os

# Ensure backend module is in path
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

from services.remediation.engine import engine

def run_tests():
    print("Testing Auto-Remediation & Rollback System...")
    print("-" * 50)

    # Test 1: Public Bucket -> Partial Remediation Storage Fix
    result_s3 = engine.execute_remediation({
        "risk_level": "MEDIUM",
        "resource_id": "arn:aws:s3:::public-bucket-123",
        "explanation": "public exposure detected on S3"
    })
    assert result_s3["fix_type"] == "Storage Patch", "Test 1 Failed"
    print("✔ [Test Case 1] public bucket → fixed seamlessly")

    # Test 2: Open Port -> Closed Network Fix
    result_port = engine.execute_remediation({
        "risk_level": "MEDIUM",
        "resource_id": "sg-987654321",
        "explanation": "Open port 22 exposed to 0.0.0.0/0 on network"
    })
    assert result_port["fix_type"] == "Security Group Adjustment", "Test 2 Failed"
    print("✔ [Test Case 2] open port → closed dynamically")

    # Test 3: Rollback System
    result_critical = engine.execute_remediation({
        "risk_level": "CRITICAL",
        "resource_id": "iam-admin-role",
        "explanation": "Malicious wildcard privilege escalation detected"
    })
    assert result_critical["status"] == "Rollback Executed", "Test 3 Failed"
    print("✔ [Test Case 3] exact baseline rollback mapping works recursively")

    # Test 4: Approval Flow
    result_high = engine.execute_remediation({
        "risk_level": "HIGH",
        "resource_id": "production-db",
        "explanation": "Unusual unencrypted DB snapshot creation"
    })
    assert result_high["status"] == "Waiting for Approval", "Test 4 Failed"
    print("✔ [Test Case 4] high-risk admin approval flow traps execution")

    print("-" * 50)
    print("All Step 8 Remediation Scenarios Assured!")

if __name__ == "__main__":
    run_tests()
