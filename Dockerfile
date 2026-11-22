# NIDS service image. The pipeline is stdlib-only, so the image is just Python plus the code and model.
FROM python:3.12-slim

RUN useradd --system --uid 10001 --home-dir /app nids
WORKDIR /app
COPY --chown=nids:nids app.py ./
COPY --chown=nids:nids nids_agent/ nids_agent/
COPY --chown=nids:nids data/ data/
RUN mkdir -p /app/logs && chown nids:nids /app/logs

USER nids
ENV PYTHONUNBUFFERED=1 \
    NIDS_LOG_MAX_BYTES=104857600 \
    NIDS_LOG_BACKUPS=5
VOLUME ["/app/logs"]
EXPOSE 9108

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:9108/healthz', timeout=4).status == 200 else 1)"

# Follows a Zeek conn.log mounted at /zeek-logs (see docker-compose.yml). Override CMD for other sources.
ENTRYPOINT ["python", "app.py"]
CMD ["--serve", "--follow", "/zeek-logs/conn.log", "--format", "zeek", \
     "--metrics-host", "0.0.0.0", "--metrics-port", "9108", "--print-alerts"]
