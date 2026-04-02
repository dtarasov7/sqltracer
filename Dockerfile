FROM python:3.11-slim

WORKDIR /app

COPY sqltracer.py /app/sqltracer.py
COPY sqltracer_config_sources.py /app/sqltracer_config_sources.py
COPY sqltracer_packetio.py /app/sqltracer_packetio.py
COPY demo_pg_client.py /app/demo_pg_client.py

RUN pip install --no-cache-dir "psycopg[binary]==3.2.9"

ENV PYTHONUNBUFFERED=1
