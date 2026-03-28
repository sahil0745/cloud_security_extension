import os
from celery import Celery

BROKER_URL = os.getenv("CELERY_BROKER_URL", os.getenv("REDIS_URL", "redis://localhost:6379/0"))
RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", BROKER_URL)
TASK_ALWAYS_EAGER = os.getenv("CELERY_TASK_ALWAYS_EAGER", "true").lower() == "true"

if TASK_ALWAYS_EAGER:
    BROKER_URL = "memory://"
    RESULT_BACKEND = "cache+memory://"

celery_app = Celery("cloudsec_tasks", broker=BROKER_URL, backend=RESULT_BACKEND)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_soft_time_limit=int(os.getenv("CELERY_TASK_SOFT_TIME_LIMIT", "45")),
    task_time_limit=int(os.getenv("CELERY_TASK_TIME_LIMIT", "60")),
    broker_connection_retry_on_startup=True,
    task_track_started=True,
    task_always_eager=TASK_ALWAYS_EAGER,
    task_store_eager_result=True,
)

celery_app.autodiscover_tasks(["tasks"])
