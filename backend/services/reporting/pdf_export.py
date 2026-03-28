import io
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from datetime import datetime

class PDFExporter:
    @staticmethod
    def export_report_to_pdf(report_data: dict) -> bytes:
        """
        Generates a professional PDF document using ReportLab.
        """
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=50, bottomMargin=50)
        
        styles = getSampleStyleSheet()
        title_style = styles["Heading1"]
        title_style.textColor = colors.HexColor("#1e293b")
        title_style.alignment = 1 # Center
        
        h2_style = styles["Heading2"]
        h2_style.textColor = colors.HexColor("#334155")
        
        normal_style = styles["Normal"]
        normal_style.leading = 14
        
        elements = []
        metadata = report_data.get("metadata", {})
        compliance = metadata.get("compliance") or {}

        # 1. Title & Header
        elements.append(Paragraph("CloudSec Copilot - Comprehensive Security Report", title_style))
        elements.append(Spacer(1, 10))
        elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
        if compliance:
            controls = ", ".join(compliance.get("controls", [])[:3])
            elements.append(Paragraph(f"Compliance Mode: {compliance.get('standard', 'SOC2')} ({controls})", normal_style))
        elements.append(Spacer(1, 20))

        # AI executive summary block
        ai_summary = report_data.get("ai_summary", "")
        if ai_summary:
            elements.append(Paragraph("Executive Summary (AI)", h2_style))
            elements.append(Paragraph(ai_summary, normal_style))
            elements.append(Spacer(1, 16))

        # 2. System Overview
        elements.append(Paragraph("1. System Overview", h2_style))
        overview = report_data.get("overview", {})
        o_data = [
            ["Metric", "Value"],
            ["Total Vulnerabilities", str(overview.get("total_vulns", 0))],
            ["Overall Risk Score", f"{overview.get('risk_score', 0)}/100"],
            ["System Status", overview.get("status", "Monitoring")]
        ]
        
        o_table = Table(o_data, colWidths=[200, 200])
        o_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (1,0), colors.HexColor("#0f172a")),
            ('TEXTCOLOR', (0,0), (1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,0), 12),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor("#f8fafc")),
            ('GRID', (0,0), (-1,-1), 1, colors.HexColor("#e2e8f0"))
        ]))
        elements.append(o_table)
        elements.append(Spacer(1, 20))

        # 3. Vulnerabilities Log
        elements.append(Paragraph("2. Active Vulnerabilities", h2_style))
        vulns = report_data.get("vulnerabilities", [])
        if vulns:
            v_data = [["Threat ID", "Vulnerability", "Resource", "Severity"]]
            for v in vulns:
                v_data.append([v.get("id"), v.get("title"), v.get("resource"), v.get("severity")])
            
            v_table = Table(v_data, colWidths=[80, 180, 140, 80])
            v_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0f172a")),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('GRID', (0,0), (-1,-1), 0.5, colors.grey)
            ]))
            elements.append(v_table)
        else:
            elements.append(Paragraph("No active vulnerabilities detected.", normal_style))
            
        elements.append(Spacer(1, 20))

        # 3. Risk Analysis
        elements.append(Paragraph("3. Risk Analysis", h2_style))
        risk_analysis = report_data.get("risk_analysis", {})
        elements.append(Paragraph(f"Risk Score: {risk_analysis.get('score', 0)}/100", normal_style))
        elements.append(Paragraph(f"Explanation: {risk_analysis.get('explanation', 'N/A')}", normal_style))
        factors = risk_analysis.get("contributing_factors", [])
        elements.append(Paragraph(f"Contributing Factors: {', '.join(factors) if factors else 'None'}", normal_style))
        elements.append(Spacer(1, 16))

        # 4. User Behavior Anomalies
        elements.append(Paragraph("4. User Behavior", h2_style))
        behavior = report_data.get("user_behavior", {})
        elements.append(Paragraph(f"Anomaly Score: {behavior.get('anomaly_score', 0)}", normal_style))
        elements.append(Paragraph(f"Behavior Status: {behavior.get('status', 'Normal')}", normal_style))
        anoms = behavior.get("suspicious_activity", [])
        if anoms:
            a_data = [["User", "Suspicious Action", "Anomaly Score"]]
            for a in anoms:
                a_data.append([a.get("user"), a.get("action"), str(a.get("score"))])

            a_table = Table(a_data, colWidths=[150, 200, 100])
            a_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0f172a")),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('GRID', (0,0), (-1,-1), 0.5, colors.grey)
            ]))
            elements.append(a_table)
        else:
            elements.append(Paragraph("No anomalous behavior detected.", normal_style))

        elements.append(Spacer(1, 20))

        # 5. Remediation and rollback actions
        elements.append(Paragraph("5. Remediation Actions", h2_style))
        remediation = report_data.get("remediation_actions", [])
        if remediation:
            r_data = [["Action", "Target", "Type", "Status"]]
            for item in remediation:
                r_data.append([
                    item.get("action", ""),
                    item.get("target", ""),
                    item.get("type", "remediation"),
                    item.get("status", ""),
                ])
            r_table = Table(r_data, colWidths=[180, 120, 80, 90])
            r_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0f172a")),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('GRID', (0,0), (-1,-1), 0.5, colors.grey)
            ]))
            elements.append(r_table)
        else:
            elements.append(Paragraph("No remediation/rollback actions logged.", normal_style))

        elements.append(Spacer(1, 20))

        # 6. Timeline & Attacks
        elements.append(Paragraph("6. Timeline", h2_style))
        timeline = report_data.get("timeline", {})
        t_data = [["Time", "Type", "Event", "Target/User"]]
        for att in timeline.get("attack_attempts", []):
            t_data.append([att.get("time"), "Attack", att.get("type"), att.get("target")])
        for chg in timeline.get("config_changes", []):
            t_data.append([chg.get("time"), "Config", chg.get("change"), chg.get("user")])
        
        if len(t_data) > 1:
            t_table = Table(t_data, colWidths=[80, 80, 150, 140])
            t_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0f172a")),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('GRID', (0,0), (-1,-1), 0.5, colors.grey)
            ]))
            elements.append(t_table)
        elements.append(Spacer(1, 20))

        # Visual chart section
        elements.append(Paragraph("Visual Risk Breakdown", h2_style))
        
        # Adding actual ReportLab vector graphic chart
        from reportlab.graphics.shapes import Drawing
        from reportlab.graphics.charts.piecharts import Pie
        
        d = Drawing(400, 200)
        pc = Pie()
        pc.x = 100
        pc.y = 20
        pc.width = 150
        pc.height = 150
        vulns = report_data.get("vulnerabilities", [])
        critical_count = len([v for v in vulns if (v.get("severity") or "").upper() == "CRITICAL"])
        high_count = len([v for v in vulns if (v.get("severity") or "").upper() == "HIGH"])
        medium_count = len([v for v in vulns if (v.get("severity") or "").upper() == "MEDIUM"])
        low_count = len([v for v in vulns if (v.get("severity") or "").upper() == "LOW"])
        chart_data = [critical_count, high_count, medium_count, low_count]
        if sum(chart_data) == 0:
            chart_data = [1, 0, 0, 0]
        pc.data = chart_data
        pc.labels = ['Critical', 'High', 'Medium', 'Low']
        pc.slices.strokeWidth = 0.5
        pc.slices[0].fillColor = colors.red
        pc.slices[1].fillColor = colors.orange
        pc.slices[2].fillColor = colors.gold
        pc.slices[3].fillColor = colors.green
        d.add(pc)
        elements.append(d)

        # Severity bar chart
        from reportlab.graphics.charts.barcharts import VerticalBarChart
        d_bar = Drawing(420, 180)
        bar = VerticalBarChart()
        bar.x = 40
        bar.y = 30
        bar.height = 120
        bar.width = 320
        bar.data = [chart_data]
        bar.categoryAxis.categoryNames = ['Critical', 'High', 'Medium', 'Low']
        bar.valueAxis.valueMin = 0
        bar.valueAxis.valueMax = max(5, max(chart_data) + 1)
        bar.valueAxis.valueStep = 1
        bar.bars[0].fillColor = colors.HexColor("#0ea5e9")
        d_bar.add(bar)
        elements.append(Spacer(1, 8))
        elements.append(d_bar)

        # Risk trend line chart
        from reportlab.graphics.charts.lineplots import LinePlot
        risk_points = report_data.get("timeline", {}).get("attack_attempts", [])[:10]
        d_line = Drawing(420, 190)
        line = LinePlot()
        line.x = 40
        line.y = 40
        line.height = 120
        line.width = 320
        if risk_points:
            line.data = [[(idx, min(100, 20 + idx * 8)) for idx, _ in enumerate(risk_points, start=1)]]
        else:
            line.data = [[(1, 10), (2, 15), (3, 12), (4, 18), (5, 14)]]
        line.lines[0].strokeColor = colors.HexColor("#ef4444")
        line.lines[0].strokeWidth = 2
        line.xValueAxis.valueMin = 1
        line.xValueAxis.valueMax = 10
        line.xValueAxis.valueStep = 1
        line.yValueAxis.valueMin = 0
        line.yValueAxis.valueMax = 100
        line.yValueAxis.valueStep = 20
        d_line.add(line)
        elements.append(Spacer(1, 8))
        elements.append(d_line)

        elements.append(Spacer(1, 16))
        elements.append(Paragraph("This report supports security operations, compliance auditing, and incident response review.", normal_style))

        # Build PDF Document
        doc.build(elements)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes

pdf_exporter = PDFExporter()
