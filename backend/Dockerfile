# ── CertMgr API image ────────────────────────────────────────────────────────
# Multi-stage: build wheels, then slim runtime with a non-root user.
FROM python:3.13-slim AS builder

ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /wheels

COPY requirements.txt .
RUN pip wheel --wheel-dir /wheels -r requirements.txt

# ── Runtime ─────────────────────────────────────────────────────────────────
FROM python:3.13-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH="/venv/bin:$PATH"

# Runtime system deps: certbot + plugins, ssh client, rsync, openssl, curl
RUN apt-get update && apt-get install -y --no-install-recommends \
        certbot \
        openssl \
        openssh-client \
        rsync \
        curl \
        ca-certificates \
        tini \
    && rm -rf /var/lib/apt/lists/* \
    && python -m venv /venv

COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels

WORKDIR /srv/certmgr
COPY app ./app
COPY cli ./cli
COPY alembic ./alembic
COPY alembic.ini pyproject.toml ./
RUN pip install --no-cache-dir --no-deps -e .   # registers the `certmgr` CLI entry point

# Non-root runtime user
RUN useradd --system --create-home --shell /usr/sbin/nologin certmgr \
    && mkdir -p /var/lib/certmgr/{certificates,backups,tmp} /var/log/certmgr /etc/letsencrypt \
    && chown -R certmgr:certmgr /var/lib/certmgr /var/log/certmgr /srv/certmgr

USER certmgr
EXPOSE 8000

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
