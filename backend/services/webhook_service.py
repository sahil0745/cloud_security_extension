"""
Enterprise Webhook Notification Service
Dispatches security alerts to Slack, Microsoft Teams, and Email (SMTP).
"""
import os
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, Optional
import structlog

logger = structlog.get_logger()

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    httpx = None
    HTTPX_AVAILABLE = False

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
TEAMS_WEBHOOK_URL = os.getenv("TEAMS_WEBHOOK_URL", "")
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
ALERT_EMAIL_TO = os.getenv("ALERT_EMAIL_TO", "")


class WebhookService:

    @staticmethod
    def get_health_status() -> Dict[str, Any]:
        """Returns safe webhook channel readiness details without exposing secrets."""
        return {
            "slack_configured": bool(SLACK_WEBHOOK_URL),
            "teams_configured": bool(TEAMS_WEBHOOK_URL),
            "email_configured": bool(SMTP_USER and SMTP_PASS and ALERT_EMAIL_TO),
            "http_client_available": HTTPX_AVAILABLE,
            "smtp_host": SMTP_HOST,
            "smtp_port": SMTP_PORT,
        }

    @staticmethod
    async def send_slack_alert(title: str, message: str, severity: str = "HIGH"):
        """Send structured alert to Slack via Incoming Webhook."""
        if not SLACK_WEBHOOK_URL or not HTTPX_AVAILABLE:
            logger.warning("slack_webhook_skipped", reason="URL not configured or httpx missing")
            return False
        
        color = {"CRITICAL": "#FF0000", "HIGH": "#FF6600", "MEDIUM": "#FFCC00", "LOW": "#00CC00"}.get(severity, "#808080")
        payload = {
            "attachments": [{
                "color": color,
                "title": f"🚨 CloudSec Alert: {title}",
                "text": message,
                "fields": [
                    {"title": "Severity", "value": severity, "short": True},
                    {"title": "System", "value": "CloudSec Copilot", "short": True}
                ]
            }]
        }
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(SLACK_WEBHOOK_URL, json=payload, timeout=10)
                logger.info("slack_alert_sent", status=resp.status_code, title=title)
                return resp.status_code == 200
        except Exception as e:
            logger.error("slack_alert_failed", error=str(e))
            return False

    @staticmethod
    async def send_teams_alert(title: str, message: str, severity: str = "HIGH"):
        """Send structured alert to Microsoft Teams via Incoming Webhook."""
        if not TEAMS_WEBHOOK_URL or not HTTPX_AVAILABLE:
            logger.warning("teams_webhook_skipped", reason="URL not configured or httpx missing")
            return False
        
        color = {"CRITICAL": "FF0000", "HIGH": "FF6600", "MEDIUM": "FFCC00", "LOW": "00CC00"}.get(severity, "808080")
        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color,
            "summary": f"CloudSec Alert: {title}",
            "sections": [{
                "activityTitle": f"🚨 {title}",
                "activitySubtitle": "CloudSec Copilot - Enterprise",
                "facts": [
                    {"name": "Severity", "value": severity},
                    {"name": "Details", "value": message}
                ],
                "markdown": True
            }]
        }
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(TEAMS_WEBHOOK_URL, json=payload, timeout=10)
                logger.info("teams_alert_sent", status=resp.status_code, title=title)
                return resp.status_code == 200
        except Exception as e:
            logger.error("teams_alert_failed", error=str(e))
            return False

    @staticmethod
    def send_email_alert(title: str, message: str, severity: str = "HIGH"):
        """Send alert via SMTP email."""
        if not SMTP_USER or not ALERT_EMAIL_TO:
            logger.warning("email_alert_skipped", reason="SMTP not configured")
            return False
        
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[CloudSec-{severity}] {title}"
            msg["From"] = SMTP_USER
            msg["To"] = ALERT_EMAIL_TO

            html = f"""
            <html><body>
            <h2 style="color: red;">🚨 CloudSec Security Alert</h2>
            <p><strong>Title:</strong> {title}</p>
            <p><strong>Severity:</strong> {severity}</p>
            <p><strong>Details:</strong></p>
            <pre>{message}</pre>
            <hr>
            <p><em>CloudSec Copilot - Enterprise Edition</em></p>
            </body></html>
            """
            msg.attach(MIMEText(html, "html"))

            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
                server.starttls()
                server.login(SMTP_USER, SMTP_PASS)
                server.send_message(msg)
            
            logger.info("email_alert_sent", to=ALERT_EMAIL_TO, title=title)
            return True
        except Exception as e:
            logger.error("email_alert_failed", error=str(e))
            return False

    @staticmethod
    async def broadcast_alert(title: str, message: str, severity: str = "HIGH"):
        """Send alert to ALL configured channels simultaneously."""
        logger.info("broadcasting_alert", title=title, severity=severity)
        results = {
            "slack": await WebhookService.send_slack_alert(title, message, severity),
            "teams": await WebhookService.send_teams_alert(title, message, severity),
            "email": WebhookService.send_email_alert(title, message, severity)
        }
        logger.info("broadcast_complete", results=results)
        return results


webhook_service = WebhookService()
