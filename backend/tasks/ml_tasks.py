from tasks.celery_app import celery_app
from ml_engine import engine as ml_engine
import structlog

logger = structlog.get_logger()


@celery_app.task(bind=True, autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={"max_retries": 3})
def run_ml_inference_task(self, features: dict):
    logger.info("ml_task_started", task_id=self.request.id)
    prediction = ml_engine.predict(features)
    logger.info("ml_task_completed", task_id=self.request.id)
    return prediction
