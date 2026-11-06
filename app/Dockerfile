FROM python:3.11-slim
WORKDIR /srv
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY app/requirements.txt /srv/requirements.txt
# Fixed uid so the shared upload volume (see uploads-init in docker-compose.yml) can be chowned to it.
RUN pip install --no-cache-dir -r requirements.txt \
    && groupadd -r -g 10001 sentinel \
    && useradd --no-log-init -r -u 10001 -g sentinel sentinel \
    && mkdir -p /data/uploads/staging /data/uploads/ready \
    && chown -R sentinel:sentinel /data/uploads
COPY app /srv/app
USER sentinel
EXPOSE 8000
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--threads", "2", "--timeout", "60", "app.main:app"]
