import asyncio
import os
import uuid
import smtplib
import json
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from .csv_export import csv_exporter
from .pdf_export import pdf_exporter
from typing import Dict, Any, Optional, List
import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from models.models import ConfigHistory, AuditLog, Logs, RiskHistory, User
from services.rules_engine.evaluator import RuleEvaluator

try:
    import httpx
    HTTPX_AVAILABLE = True
except Exception:
    httpx = None
    HTTPX_AVAILABLE = False

logger = structlog.get_logger()

class ReportGenerator:
    def __init__(self):
        # In-memory schedule registry for local/dev operation.
        self._schedules: Dict[str, Dict[str, Any]] = {}

    @staticmethod
    def _parse_time(value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _within_range(ts: Optional[datetime], start: Optional[datetime], end: Optional[datetime]) -> bool:
        if ts is None:
            return False
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        if start and ts < start:
            return False
        if end and ts > end:
            return False
        return True

    @staticmethod
    def _next_run_utc(frequency: str) -> datetime:
        now = datetime.now(timezone.utc)
        if frequency == "weekly":
            return now + timedelta(days=7)
        return now + timedelta(days=1)

    @staticmethod
    def _username_in_tenant(username: Optional[str], tenant_id: Optional[str]) -> bool:
        if not username or not tenant_id:
            return False
        normalized = username.lower()
        tenant = tenant_id.lower()
        return normalized.startswith(f"{tenant}_") or normalized.endswith(f"@{tenant}") or f"tenant:{tenant}" in normalized

    @staticmethod
    def _safe_text(value: Any, default: str = "") -> str:
        if value is None:
            return default
        if isinstance(value, (str, int, float, bool)):
            return str(value)
        return json.dumps(value, default=str)

    @staticmethod
    async def _build_fallback_summary(report: Dict[str, Any]) -> str:
        overview = report.get("overview", {})
        risk = int(overview.get("risk_score", 0) or 0)
        status = overview.get("status", "Monitoring")
        vuln_count = int(overview.get("total_vulns", 0) or 0)
        behavior = report.get("user_behavior", {})
        anomaly = int(behavior.get("anomaly_score", 0) or 0)
        return (
            f"Executive Summary: Current system status is {status} with risk score {risk}/100 and "
            f"{vuln_count} open vulnerabilities. Behavior anomaly score is {anomaly}. "
            f"Prioritize remediation of high/critical vulnerabilities and monitor suspicious user actions."
        )

    async def generate_ai_executive_summary(self, report: Dict[str, Any]) -> str:
        provider = (os.getenv("REPORT_LLM_PROVIDER", "gemini") or "gemini").lower()
        if provider != "gemini" or not HTTPX_AVAILABLE:
            return await self._build_fallback_summary(report)

        api_key = os.getenv("GEMINI_API_KEY", "")
        if not api_key:
            return await self._build_fallback_summary(report)

        prompt = {
            "overview": report.get("overview", {}),
            "risk_analysis": report.get("risk_analysis", {}),
            "user_behavior": {
                "anomaly_score": report.get("user_behavior", {}).get("anomaly_score", 0),
                "status": report.get("user_behavior", {}).get("status", "Normal"),
            },
            "top_vulnerabilities": report.get("vulnerabilities", [])[:5],
        }
        body = {
            "contents": [
                {
                    "parts": [
                        {
                            "text": (
                                "Generate a concise executive summary (4-6 sentences) for a cloud security report. "
                                "Include risk posture, key threats, behavior risk, and immediate actions. "
                                f"JSON context: {json.dumps(prompt)}"
                            )
                        }
                    ]
                }
            ]
        }

        try:
            url = (
                "https://generativelanguage.googleapis.com/v1beta/models/"
                f"gemini-1.5-flash:generateContent?key={api_key}"
            )
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.post(url, json=body)
                if resp.status_code >= 300:
                    return await self._build_fallback_summary(report)
                payload = resp.json()
                candidates = payload.get("candidates", [])
                if not candidates:
                    return await self._build_fallback_summary(report)
                parts = candidates[0].get("content", {}).get("parts", [])
                text = "\n".join([p.get("text", "") for p in parts if p.get("text")]).strip()
                return text or await self._build_fallback_summary(report)
        except Exception:
            return await self._build_fallback_summary(report)

    def schedule_report(
        self,
        frequency: str,
        report_format: str,
        recipient_email: Optional[str] = None,
        severity: Optional[str] = None,
        compliance_mode: bool = False,
        compliance_standard: str = "SOC2",
        scope: str = "global",
        tenant_id: Optional[str] = None,
        requester_username: Optional[str] = None,
    ) -> Dict[str, Any]:
        normalized_frequency = (frequency or "daily").lower()
        if normalized_frequency not in {"daily", "weekly"}:
            raise ValueError("frequency must be daily or weekly")
        normalized_format = (report_format or "pdf").lower()
        if normalized_format not in {"json", "csv", "pdf"}:
            raise ValueError("format must be json, csv, or pdf")

        schedule_id = f"sched-{uuid.uuid4().hex[:10]}"
        item = {
            "schedule_id": schedule_id,
            "frequency": normalized_frequency,
            "format": normalized_format,
            "recipient_email": recipient_email,
            "severity": (severity or "").upper() or None,
            "compliance_mode": bool(compliance_mode),
            "compliance_standard": (compliance_standard or "SOC2").upper(),
            "scope": (scope or "global").lower(),
            "tenant_id": tenant_id,
            "requester_username": requester_username,
            "enabled": True,
            "next_run": self._next_run_utc(normalized_frequency),
            "last_run": None,
        }
        self._schedules[schedule_id] = item
        return {
            **item,
            "next_run": item["next_run"].isoformat(),
            "last_run": None,
        }

    def list_schedules(self) -> List[Dict[str, Any]]:
        out = []
        for item in self._schedules.values():
            out.append(
                {
                    **item,
                    "next_run": item["next_run"].isoformat() if item.get("next_run") else None,
                    "last_run": item["last_run"].isoformat() if item.get("last_run") else None,
                }
            )
        return out

    async def run_due_schedules_async(self, db: AsyncSession) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        ran = []
        for schedule_id, item in self._schedules.items():
            if not item.get("enabled"):
                continue
            if item.get("next_run") and item["next_run"] > now:
                continue

            fmt = item.get("format", "pdf")
            severity = item.get("severity")
            compliance_mode = bool(item.get("compliance_mode"))
            compliance_standard = item.get("compliance_standard", "SOC2")
            recipient = item.get("recipient_email")
            scope = item.get("scope", "global")
            tenant_id = item.get("tenant_id")
            requester_username = item.get("requester_username")

            if recipient:
                await self.send_report_email_async(
                    db,
                    recipient_email=recipient,
                    report_format=fmt,
                    severity=severity,
                    compliance_mode=compliance_mode,
                    compliance_standard=compliance_standard,
                    scope=scope,
                    tenant_id=tenant_id,
                    requester_username=requester_username,
                )
            else:
                if fmt == "json":
                    await self.generate_json_report_async(
                        db,
                        severity=severity,
                        compliance_mode=compliance_mode,
                        compliance_standard=compliance_standard,
                        scope=scope,
                        tenant_id=tenant_id,
                        requester_username=requester_username,
                    )
                elif fmt == "csv":
                    await self.generate_csv_report_async(
                        db,
                        severity=severity,
                        compliance_mode=compliance_mode,
                        compliance_standard=compliance_standard,
                        scope=scope,
                        tenant_id=tenant_id,
                        requester_username=requester_username,
                    )
                else:
                    await self.generate_pdf_report_async(
                        db,
                        severity=severity,
                        compliance_mode=compliance_mode,
                        compliance_standard=compliance_standard,
                        scope=scope,
                        tenant_id=tenant_id,
                        requester_username=requester_username,
                    )

            item["last_run"] = now
            item["next_run"] = self._next_run_utc(item.get("frequency", "daily"))
            ran.append(schedule_id)

        return {"ran": ran, "count": len(ran)}

    @staticmethod
    def _send_email_with_attachment(
        recipient_email: str,
        subject: str,
        body: str,
        filename: str,
        content: bytes,
        mime_type: str,
    ) -> bool:
        smtp_user = os.getenv("SMTP_USER", "")
        smtp_pass = os.getenv("SMTP_PASS", "")
        smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
        if not smtp_user or not smtp_pass:
            logger.warning("report_email_skipped", reason="SMTP_USER/SMTP_PASS missing")
            return False

        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = smtp_user
        msg["To"] = recipient_email
        msg.set_content(body)

        maintype, subtype = mime_type.split("/", 1)
        msg.add_attachment(content, maintype=maintype, subtype=subtype, filename=filename)

        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        return True

    async def send_report_email_async(
        self,
        db: AsyncSession,
        recipient_email: str,
        report_format: str = "pdf",
        severity: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        compliance_mode: bool = False,
        compliance_standard: str = "SOC2",
        scope: str = "global",
        tenant_id: Optional[str] = None,
        requester_username: Optional[str] = None,
    ) -> Dict[str, Any]:
        fmt = (report_format or "pdf").lower()
        if fmt == "csv":
            content = (await self.generate_csv_report_async(
                db,
                severity=severity,
                start_time=start_time,
                end_time=end_time,
                compliance_mode=compliance_mode,
                compliance_standard=compliance_standard,
                scope=scope,
                tenant_id=tenant_id,
                requester_username=requester_username,
            )).encode("utf-8")
            mime_type = "text/csv"
            filename = "cloudsec-report.csv"
        else:
            content = await self.generate_pdf_report_async(
                db,
                severity=severity,
                start_time=start_time,
                end_time=end_time,
                compliance_mode=compliance_mode,
                compliance_standard=compliance_standard,
                scope=scope,
                tenant_id=tenant_id,
                requester_username=requester_username,
            )
            mime_type = "application/pdf"
            filename = "cloudsec-report.pdf"

        sent = await asyncio.to_thread(
            self._send_email_with_attachment,
            recipient_email,
            "CloudSec Security Report",
            "Attached is your requested CloudSec security report.",
            filename,
            content,
            mime_type,
        )
        return {"sent": sent, "recipient": recipient_email, "format": fmt}

    async def fetch_unified_context_async(
        self,
        db: AsyncSession,
        severity_filter: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        compliance_mode: bool = False,
        compliance_standard: str = "SOC2",
        scope: str = "global",
        tenant_id: Optional[str] = None,
        requester_username: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Build unified reporting context from persisted database events and evaluations."""
        start_dt = self._parse_time(start_time)
        end_dt = self._parse_time(end_time)

        history_result = await db.execute(select(ConfigHistory).order_by(ConfigHistory.scanned_at.desc()).limit(1))
        latest_history = history_result.scalars().first()

        vulnerabilities = []
        risk_score = 0
        if latest_history:
            try:
                evaluation = RuleEvaluator.evaluate(latest_history.platform, latest_history.configuration)
            except Exception as exc:
                logger.warning(
                    "report_rule_evaluation_fallback",
                    error=str(exc),
                    platform=latest_history.platform,
                )
                evaluation = {"risk_score": 0, "violations": []}
            risk_score = evaluation.get("risk_score", 0)
            for i, v in enumerate(evaluation.get("violations", []), start=1):
                vulnerabilities.append({
                    "id": f"VULN-{i:03d}",
                    "title": self._safe_text(v.get("description", "Policy violation"), "Policy violation"),
                    "resource": self._safe_text(v.get("resource", "Unknown"), "Unknown"),
                    "severity": self._safe_text(v.get("severity", "LOW"), "LOW").upper(),
                })

        if severity_filter:
            vulnerabilities = [v for v in vulnerabilities if v.get("severity") == severity_filter.upper()]
        if scope == "tenant" and tenant_id:
            vulnerabilities = [v for v in vulnerabilities if tenant_id.lower() in str(v.get("resource", "")).lower()]

        risk_rows = await db.execute(select(RiskHistory).order_by(RiskHistory.timestamp.desc()).limit(30))
        risk_values = []
        for row in risk_rows.scalars().all():
            if row.score is None or not self._within_range(row.timestamp, start_dt, end_dt):
                continue
            if scope == "user" and requester_username:
                user_result = await db.execute(select(User).filter(User.id == row.user_id))
                row_user = user_result.scalars().first()
                if not row_user or row_user.username != requester_username:
                    continue
            if scope == "tenant" and tenant_id:
                user_result = await db.execute(select(User).filter(User.id == row.user_id))
                row_user = user_result.scalars().first()
                if row_user and not self._username_in_tenant(row_user.username, tenant_id):
                    continue
            risk_values.append(row.score)
        if risk_values:
            risk_score = int(sum(risk_values) / len(risk_values))

        audit_rows = await db.execute(
            select(AuditLog, User.username)
            .join(User, AuditLog.user_id == User.id, isouter=True)
            .order_by(AuditLog.timestamp.desc())
            .limit(50)
        )
        user_behavior = []
        config_changes = []
        remediation_actions = []
        for log, username in audit_rows.all():
            if not self._within_range(log.timestamp, start_dt, end_dt):
                continue
            if scope == "user" and requester_username and username != requester_username:
                continue
            if scope == "tenant" and tenant_id and not self._username_in_tenant(username, tenant_id):
                continue
            item = {
                "time": log.timestamp.strftime("%H:%M") if log.timestamp else "",
                "user": username or "system",
                "change": log.action,
            }
            lowered_action = (log.action or "").lower()
            if "remediation" in lowered_action or "rollback" in lowered_action:
                remediation_actions.append({
                    "action": log.action,
                    "target": log.resource,
                    "status": log.status,
                    "type": "rollback" if "rollback" in lowered_action else "remediation"
                })
            else:
                config_changes.append(item)

            user_behavior.append({
                "user": username or "system",
                "action": log.action,
                "score": 90 if (log.status or "").lower() in {"failed", "denied"} else 30
            })

        attack_attempts = []
        try:
            log_rows = await db.execute(select(Logs).order_by(Logs.timestamp.desc()).limit(30))
            for row in log_rows.scalars().all():
                if not self._within_range(row.timestamp, start_dt, end_dt):
                    continue
                if scope in {"user", "tenant"} and row.user_id:
                    u_res = await db.execute(select(User).filter(User.id == row.user_id))
                    row_user = u_res.scalars().first()
                    if scope == "user" and requester_username and (not row_user or row_user.username != requester_username):
                        continue
                    if scope == "tenant" and tenant_id and row_user and not self._username_in_tenant(row_user.username, tenant_id):
                        continue
                attack_attempts.append({
                    "time": row.timestamp.strftime("%H:%M") if row.timestamp else "",
                    "type": row.event_type,
                    "target": row.resource_id or "unknown"
                })
        except Exception as exc:
            # Older dev databases may not have all columns (e.g. previous_hash/log_hash). Keep reporting available.
            logger.warning("report_logs_query_fallback", error=str(exc))

        contributing_factors = []
        for vuln in vulnerabilities[:3]:
            contributing_factors.append(self._safe_text(vuln.get("title", "unknown"), "unknown"))
        if any((a.get("score") or 0) >= 80 for a in user_behavior):
            contributing_factors.append("High-severity anomalous user behavior")

        max_behavior_score = max([int(a.get("score", 0)) for a in user_behavior], default=0)
        behavior_status = "Critical" if max_behavior_score >= 80 else "Suspicious" if max_behavior_score >= 40 else "Normal"

        compliance = None
        if compliance_mode:
            standard = (compliance_standard or "SOC2").upper()
            if standard == "ISO":
                controls = ["A.12.4 Logging and monitoring", "A.16 Incident management", "A.18 Compliance"]
            else:
                controls = ["CC6.1 Logical access", "CC7.2 Change management", "CC7.3 Security monitoring"]
            compliance = {
                "mode": True,
                "standard": standard,
                "controls": controls,
            }

        report_time = datetime.now(timezone.utc).isoformat()

        report = {
            "metadata": {
                "generatedAt": report_time,
                "scope": scope,
                "tenantId": tenant_id,
                "requester": requester_username,
                "filters": {
                    "severity": severity_filter.upper() if severity_filter else None,
                    "startTime": start_dt.isoformat() if start_dt else None,
                    "endTime": end_dt.isoformat() if end_dt else None,
                },
                "compliance": compliance,
            },
            "overview": {
                "total_vulns": len(vulnerabilities),
                "risk_score": risk_score,
                "status": "Monitoring" if risk_score < 70 else "At Risk"
            },
            "vulnerabilities": vulnerabilities,
            "risk_analysis": {
                "score": risk_score,
                "explanation": "Risk score combines rule violations, risk history trend, and observed behavioral anomalies.",
                "contributing_factors": contributing_factors
            },
            "user_behavior": {
                "anomaly_score": max_behavior_score,
                "status": behavior_status,
                "suspicious_activity": user_behavior[:20],
            },
            "remediation_actions": remediation_actions[:20],
            "timeline": {
                "attack_attempts": attack_attempts,
                "config_changes": config_changes[:20]
            }
        }

        report["ai_summary"] = await self.generate_ai_executive_summary(report)
        return report

    async def generate_json_report_async(
        self,
        db: AsyncSession,
        severity: str = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        compliance_mode: bool = False,
        compliance_standard: str = "SOC2",
        scope: str = "global",
        tenant_id: Optional[str] = None,
        requester_username: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generate raw JSON report for /generate-report endpoint."""
        return await self.fetch_unified_context_async(
            db,
            severity_filter=severity,
            start_time=start_time,
            end_time=end_time,
            compliance_mode=compliance_mode,
            compliance_standard=compliance_standard,
            scope=scope,
            tenant_id=tenant_id,
            requester_username=requester_username,
        )

    async def generate_csv_report_async(
        self,
        db: AsyncSession,
        severity: str = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        compliance_mode: bool = False,
        compliance_standard: str = "SOC2",
        scope: str = "global",
        tenant_id: Optional[str] = None,
        requester_username: Optional[str] = None,
    ) -> str:
        """Asynchronously builds the CSV context to avoid blocking the event loop."""
        data = await self.fetch_unified_context_async(
            db,
            severity_filter=severity,
            start_time=start_time,
            end_time=end_time,
            compliance_mode=compliance_mode,
            compliance_standard=compliance_standard,
            scope=scope,
            tenant_id=tenant_id,
            requester_username=requester_username,
        )
        # Offload to another thread if pandas takes long
        csv_string = await asyncio.to_thread(csv_exporter.export_report_to_csv, data)
        logger.info("report_csv_generated")
        return csv_string

    async def generate_pdf_report_async(
        self,
        db: AsyncSession,
        severity: str = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        compliance_mode: bool = False,
        compliance_standard: str = "SOC2",
        scope: str = "global",
        tenant_id: Optional[str] = None,
        requester_username: Optional[str] = None,
    ) -> bytes:
        """Asynchronously builds the PDF context to avoid blocking the event loop."""
        data = await self.fetch_unified_context_async(
            db,
            severity_filter=severity,
            start_time=start_time,
            end_time=end_time,
            compliance_mode=compliance_mode,
            compliance_standard=compliance_standard,
            scope=scope,
            tenant_id=tenant_id,
            requester_username=requester_username,
        )
        # ReportLab is heavy I/O, run in thread
        pdf_bytes = await asyncio.to_thread(pdf_exporter.export_report_to_pdf, data)
        logger.info("report_pdf_generated")
        return pdf_bytes

    async def trigger_alert_report_async(
        self,
        db: AsyncSession,
        event_type: str,
        severity: str,
        recipient_email: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generate report automatically when a critical event happens."""
        if (severity or "").upper() != "CRITICAL":
            return {"triggered": False, "reason": "severity_not_critical"}

        logger.warning("critical_event_report_triggered", event_type=event_type)
        report_data = await self.generate_json_report_async(db)

        email_result = None
        recipient = recipient_email or os.getenv("ALERT_EMAIL_TO", "")
        if recipient:
            email_result = await self.send_report_email_async(
                db,
                recipient_email=recipient,
                report_format="pdf",
                compliance_mode=True,
                compliance_standard="SOC2",
            )

        return {
            "triggered": True,
            "event_type": event_type,
            "severity": severity,
            "report_summary": {
                "total_vulns": report_data.get("overview", {}).get("total_vulns", 0),
                "risk_score": report_data.get("overview", {}).get("risk_score", 0),
            },
            "email": email_result,
        }

report_generator = ReportGenerator()
