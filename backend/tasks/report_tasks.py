import asyncio
import base64
import structlog
from tasks.celery_app import celery_app
from database.db import AsyncSessionLocal
from services.reporting.report_generator import report_generator

logger = structlog.get_logger()


async def _generate_report(fmt: str, severity: str = None):
    async with AsyncSessionLocal() as db:
        if fmt == "json":
            return await report_generator.generate_json_report_async(db, severity=severity)
        if fmt == "csv":
            csv_data = await report_generator.generate_csv_report_async(db, severity=severity)
            return {"format": "csv", "content": csv_data}
        if fmt == "pdf":
            pdf_data = await report_generator.generate_pdf_report_async(db, severity=severity)
            return {"format": "pdf", "content_base64": base64.b64encode(pdf_data).decode("utf-8")}
        raise ValueError("Unsupported report format")


async def _generate_report_with_options(fmt: str, options: dict | None = None):
    options = options or {}
    async with AsyncSessionLocal() as db:
        if fmt == "json":
            return await report_generator.generate_json_report_async(db, **options)
        if fmt == "csv":
            csv_data = await report_generator.generate_csv_report_async(db, **options)
            return {"format": "csv", "content": csv_data}
        if fmt == "pdf":
            pdf_data = await report_generator.generate_pdf_report_async(db, **options)
            return {"format": "pdf", "content_base64": base64.b64encode(pdf_data).decode("utf-8")}
        raise ValueError("Unsupported report format")


@celery_app.task(bind=True, autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={"max_retries": 3})
def generate_report_task(self, fmt: str, severity: str = None):
    logger.info("report_task_started", task_id=self.request.id, format=fmt)
    result = asyncio.run(_generate_report(fmt, severity))
    logger.info("report_task_completed", task_id=self.request.id, format=fmt)
    return result


@celery_app.task(bind=True, autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={"max_retries": 3})
def generate_custom_report_task(self, fmt: str, options: dict | None = None):
    logger.info("custom_report_task_started", task_id=self.request.id, format=fmt)
    result = asyncio.run(_generate_report_with_options(fmt, options))
    logger.info("custom_report_task_completed", task_id=self.request.id, format=fmt)
    return result
