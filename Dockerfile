# =============================================================================
# IoTGuard Dockerfile
# =============================================================================
# Multi-stage build for the IoTGuard IoT Intrusion Detection System
# 
# This Dockerfile creates a production-ready container that:
# - Uses a multi-stage build to minimize image size
# - Runs the API dashboard (Flask server) as a non-root user
# - Exposes port 5001 for HTTP access
# - Includes health check for container orchestration
#
# Build: docker build -t iotguard:latest .
# Run:   docker run -p 5001:5001 iotguard:latest
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Builder — install Python dependencies
# -----------------------------------------------------------------------------
FROM python:3.13-slim AS builder

WORKDIR /build

# Install dependencies into a virtual environment for clean copy
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# -----------------------------------------------------------------------------
# Stage 2: Runtime — slim production image
# -----------------------------------------------------------------------------
FROM python:3.13-slim AS runtime

# OCI-compliant labels for container metadata
LABEL org.opencontainers.image.title="IoTGuard"
LABEL org.opencontainers.image.description="IoT Intrusion Detection System with ML-based threat detection"
LABEL org.opencontainers.image.version="2.0.0"
LABEL org.opencontainers.image.authors="IoTGuard Team"
LABEL org.opencontainers.image.source="https://github.com/A7medico/iotguard"

# Copy the pre-built virtual environment from builder stage
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Create a non-root user for security
RUN groupadd --gid 1000 iotguard && \
    useradd --uid 1000 --gid iotguard --create-home iotguard

WORKDIR /app

# Copy the entire project
COPY --chown=iotguard:iotguard . ./

# Ensure data directories exist and are writable
RUN mkdir -p /app/data /app/logs && \
    chown -R iotguard:iotguard /app/data /app/logs

# -----------------------------------------------------------------------------
# Environment Configuration
# -----------------------------------------------------------------------------
# Default configuration file path (can be overridden at runtime)
ENV IOTGUARD_CONFIG=configs/model.yaml
# Optional: Set log level (DEBUG, INFO, WARNING, ERROR)
ENV IOTGUARD_LOG_LEVEL=INFO
# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Switch to non-root user
USER iotguard

# -----------------------------------------------------------------------------
# Networking
# -----------------------------------------------------------------------------
EXPOSE 5001

# -----------------------------------------------------------------------------
# Health Check
# -----------------------------------------------------------------------------
# Kubernetes/Docker health check - verifies the API is responding
# Checks every 30 seconds, timeout after 10 seconds, 3 retries before unhealthy
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5001/health/live')" || exit 1

# -----------------------------------------------------------------------------
# Startup Command
# -----------------------------------------------------------------------------
# Run the Flask API dashboard
# In production, consider using gunicorn: 
# CMD ["gunicorn", "-b", "0.0.0.0:5001", "-w", "2", "scripts.api_dashboard:app"]
CMD ["python", "scripts/5_dashboard/api_dashboard.py"]
