import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from services.reporting.pdf_export import pdf_exporter

report_data = {
    "metadata": {"generatedAt": "2023-10-10", "scope": "global", "requester": "admin"},
    "overview": {"total_vulns": 0, "risk_score": 50, "status": "Monitoring"},
    "vulnerabilities": [],
    "risk_analysis": {"score": 50, "explanation": "Test", "contributing_factors": []},
    "user_behavior": {"anomaly_score": 0, "status": "Normal", "suspicious_activity": []},
    "remediation_actions": [],
    "timeline": {"attack_attempts": [], "config_changes": []}
}

try:
    pdf_bytes = pdf_exporter.export_report_to_pdf(report_data)
    print(f"Success! Generated {len(pdf_bytes)} bytes.")
except Exception as e:
    import traceback
    traceback.print_exc()
