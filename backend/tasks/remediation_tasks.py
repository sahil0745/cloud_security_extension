from tasks.celery_app import celery_app
from services.remediation.engine import engine as remediation_engine
import structlog

logger = structlog.get_logger()


@celery_app.task(bind=True, autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={"max_retries": 3})
def run_remediation_task(self, risk_data: dict):
    logger.info("remediation_task_started", task_id=self.request.id)
    result = remediation_engine.execute_remediation(risk_data)
    logger.info("remediation_task_completed", task_id=self.request.id)
    return result
