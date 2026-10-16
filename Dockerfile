# ==============================================================================
# VulnTracker API - Production-Grade Dockerfile
# Security Controls:
# - Minimal, pinned Debian base image (Python 3.11-slim)
# - Multi-stage build to strip build tools, cache, and compilers
# - Dedicated non-privileged user and group (appuser:appuser, UID 10001)
# - Container HEALTHCHECK using built-in Python standard library
# - Zero hardcoded credentials or secrets
# ==============================================================================

# Stage 1: Build stage
FROM python:3.11-slim-bookworm AS builder

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /install

# Install build dependencies if needed
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libffi-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy dependency specification and compile wheels
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install/wheels -r requirements.txt


# Stage 2: Minimal Runtime stage
FROM python:3.11-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Create dedicated non-root service account
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /sbin/nologin -M appuser

# Copy installed python dependencies from builder
COPY --from=builder /install/wheels /usr/local

# Set up working directory
WORKDIR /app

# Copy application source code
COPY --chown=appuser:appgroup app/ /app

# Switch to non-root user
USER 10001:10001

# Expose API port
EXPOSE 8000

# Container healthcheck using Python's standard library (no external binaries needed)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health', timeout=3)" || exit 1

# Start VulnTracker API (modules use bare imports, run from /app)
ENTRYPOINT ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
