# Alpine packages are prebuilt for arm64 and armv7, so this builds quickly on a Pi.
FROM alpine:3.24

RUN apk add --no-cache python3 py3-flask py3-yaml py3-cryptography py3-requests py3-gunicorn py3-bcrypt tzdata

WORKDIR /app
COPY *.py ./
COPY templates ./templates
COPY static ./static
COPY sso_pages ./sso_pages

ENV TM_DATA_DIR=/data \
    PYTHONUNBUFFERED=1
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD wget -qO- http://127.0.0.1:8000/healthz >/dev/null || exit 1
# One worker: the mutation lock and the renewal thread are process-local.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "8", "--timeout", "120", "--access-logfile", "-", "app:create_app()"]
