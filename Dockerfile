FROM python:3.14-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY ssl-audit.py /app/ssl-audit.py

RUN useradd -ms /bin/bash appuser && chown -R appuser:appuser /app
USER appuser

ENTRYPOINT ["python", "/app/ssl-audit.py"]

