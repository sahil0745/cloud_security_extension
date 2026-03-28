import os
import sys

ROOT_DIR = os.path.dirname(__file__)
BACKEND_DIR = os.path.join(ROOT_DIR, "backend")
sys.path.insert(0, BACKEND_DIR)

from services.reporting.csv_export import csv_exporter
from services.reporting.pdf_export import pdf_exporter


def _sample_report_data():
    return {
        "metadata": {
            "generatedAt": "2026-03-26T00:00:00+00:00",
            "compliance": {
                "mode": True,
                "standard": "SOC2",
                "controls": ["CC6.1", "CC7.2"],
            },
        },
        "overview": {
            "total_vulns": 2,
            "risk_score": 78,
            "status": "At Risk",
        },
        "vulnerabilities": [
            {"id": "VULN-001", "title": "Public bucket", "resource": "s3://prod-public", "severity": "CRITICAL"},
            {"id": "VULN-002", "title": "MFA missing", "resource": "iam://alice", "severity": "HIGH"},
        ],
        "risk_analysis": {
            "score": 78,
            "explanation": "Combined from rule and behavior signals.",
            "contributing_factors": ["Public bucket", "MFA missing"],
        },
        "user_behavior": {
            "anomaly_score": 84,
            "status": "Critical",
            "suspicious_activity": [
                {"user": "alice", "action": "policy_delete_attempt", "score": 92},
            ],
        },
        "remediation_actions": [
            {"action": "close_public_access", "target": "s3://prod-public", "status": "applied", "type": "remediation"},
            {"action": "rollback_fix", "target": "sg-123", "status": "success", "type": "rollback"},
        ],
        "timeline": {
            "attack_attempts": [
                {"time": "10:00", "type": "anomaly", "target": "s3://prod-public"},
            ],
            "config_changes": [
                {"time": "10:05", "change": "security_group_modified", "user": "alice"},
            ],
        },
    }


def test_csv_export_contains_required_sections():
    csv_data = csv_exporter.export_report_to_csv(_sample_report_data())
    assert "System Overview" in csv_data
    assert "Vulnerability" in csv_data
    assert "Risk Analysis" in csv_data
    assert "User Behavior" in csv_data
    assert "Remediation" in csv_data
    assert "Timeline Event" in csv_data


def test_pdf_export_builds_valid_pdf_bytes():
    pdf_data = pdf_exporter.export_report_to_pdf(_sample_report_data())
    assert pdf_data.startswith(b"%PDF")
    assert len(pdf_data) > 500
