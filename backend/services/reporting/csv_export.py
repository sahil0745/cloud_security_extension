import pandas as pd
import io

class CSVExporter:
    @staticmethod
    def export_report_to_csv(report_data: dict) -> str:
        """
        Converts report data into a flat CSV string using pandas.
        """
        flattened_data = []

        metadata = report_data.get("metadata", {})
        compliance = metadata.get("compliance") or {}
        flattened_data.append(
            {
                "Category": "Metadata",
                "ID": "META-01",
                "Item": "Generated At",
                "Severity": "Info",
                "Resource": metadata.get("generatedAt", ""),
                "Status": "OK",
            }
        )
        if compliance:
            flattened_data.append(
                {
                    "Category": "Compliance",
                    "ID": "COMP-01",
                    "Item": "Compliance Standard",
                    "Severity": "Info",
                    "Resource": compliance.get("standard", "SOC2"),
                    "Status": "Enabled",
                }
            )

        # Extract System Overview
        overview = report_data.get("overview", {})
        flattened_data.append({
            "Category": "System Overview",
            "ID": "SYS-01",
            "Item": f"Total Vulns: {overview.get('total_vulns', 0)}",
            "Severity": f"Risk Score: {overview.get('risk_score', 0)}/100",
            "Resource": "Global System",
            "Status": overview.get("status", "Monitoring")
        })

        # Extract vulnerabilities
        for vuln in report_data.get("vulnerabilities", []):
            flattened_data.append({
                "Category": "Vulnerability",
                "ID": vuln.get("id", ""),
                "Item": vuln.get("title"),
                "Severity": vuln.get("severity"),
                "Resource": vuln.get("resource"),
                "Status": vuln.get("status", "Active")
            })

        # Extract Risk Analysis
        risk_analysis = report_data.get("risk_analysis", {})
        flattened_data.append(
            {
                "Category": "Risk Analysis",
                "ID": "RISK-01",
                "Item": risk_analysis.get("explanation", ""),
                "Severity": f"Risk Score: {risk_analysis.get('score', 0)}/100",
                "Resource": ", ".join(risk_analysis.get("contributing_factors", [])),
                "Status": "Computed",
            }
        )

        # Extract User Behavior Anomalies
        behavior = report_data.get("user_behavior", {})
        flattened_data.append(
            {
                "Category": "User Behavior",
                "ID": "BEH-01",
                "Item": f"Anomaly score: {behavior.get('anomaly_score', 0)}",
                "Severity": behavior.get("status", "Normal"),
                "Resource": "Behavior Engine",
                "Status": "Computed",
            }
        )
        for idx, anom in enumerate(behavior.get("suspicious_activity", []), start=1):
            flattened_data.append({
                "Category": "User Anomaly",
                "ID": f"ANOM-{idx:03d}",
                "Item": anom.get("action"),
                "Severity": "High" if anom.get("score", 0) > 80 else "Medium",
                "Resource": anom.get("user"),
                "Status": "Detected"
            })

        # Extract Remediation Actions
        for idx, rem in enumerate(report_data.get("remediation_actions", []), start=1):
            flattened_data.append({
                "Category": "Remediation",
                "ID": f"REM-{idx:03d}",
                "Item": rem.get("action"),
                "Severity": rem.get("type", "remediation").upper(),
                "Resource": rem.get("target"),
                "Status": rem.get("status")
            })

        # Extract Timeline (Attacks & Changes)
        timeline = report_data.get("timeline", {})
        for att in timeline.get("attack_attempts", []):
            flattened_data.append({
                "Category": "Timeline Event",
                "ID": f"ATTACK - {att.get('time')}",
                "Item": att.get("type"),
                "Severity": "Critical Warning",
                "Resource": att.get("target"),
                "Status": "Blocked/Logged"
            })
            
        for chg in timeline.get("config_changes", []):
            flattened_data.append({
                "Category": "Timeline Event",
                "ID": f"CHANGE - {chg.get('time')}",
                "Item": chg.get("change"),
                "Severity": "Info",
                "Resource": chg.get("user"),
                "Status": "Tracked"
            })

        # Process with Pandas
        df = pd.DataFrame(flattened_data)
        
        # Write to in-memory string buffer
        csv_buffer = io.StringIO()
        df.to_csv(csv_buffer, index=False)
        return csv_buffer.getvalue()

csv_exporter = CSVExporter()
