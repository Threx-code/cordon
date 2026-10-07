FROM python:3.12-slim
RUN pip install --no-cache-dir celery==5.4.0
CMD ["celery", "-A", "worker", "worker"]
