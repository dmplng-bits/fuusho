# syntax=docker/dockerfile:1

# Multi-stage build using uv (astral.sh) instead of pip — installs
# dependencies 10-100x faster and, more importantly for a project other
# people are cloning for the first time, makes the very first
# `docker compose up -d` noticeably faster than a pip-based build.
FROM python:3.12-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:0.5.11 /uv /uvx /bin/

WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

# Dependencies install in their own cached layer, separate from app code —
# --mount=type=cache persists uv's download cache across builds, and
# --mount=type=bind means requirements.txt doesn't even need a COPY here.
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=requirements.txt,target=requirements.txt \
    uv pip install --system --no-cache-dir -r requirements.txt

FROM python:3.12-slim

WORKDIR /app
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY . .

EXPOSE 5000

CMD ["gunicorn", "-b", "0.0.0.0:5000", "--workers", "3", "--timeout", "60", "server:flask_app"]
