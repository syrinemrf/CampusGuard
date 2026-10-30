FROM python:3.11-slim
WORKDIR /srv
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY app/requirements.txt /srv/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt && groupadd -r sentinel && useradd --no-log-init -r -g sentinel sentinel
COPY app /srv/app
USER sentinel
EXPOSE 8000
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "app.main:app"]
