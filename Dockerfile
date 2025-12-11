# =============================================================================
# IoTGuard Dockerfile
# =============================================================================
# Multi-stage build for the IoTGuard IoT Intrusion Detection System
# 
# This Dockerfile creates a production-ready container that:
# - Runs the API dashboard (Flask server)
# - Exposes port 5001 for HTTP access
# - Includes health check for container orchestration
#
# Build: docker build -t iotguard:latest .
# Run:   docker run -p 5001:5001 iotguard:latest
# =============================================================================

# -----------------------------------------------------------------------------
# Base Image
# -----------------------------------------------------------------------------
# Using Python 3.13 slim for minimal footprint while maintaining compatibility
FROM python:3.13-slim

# -----------------------------------------------------------------------------
# Metadata Labels
# -----------------------------------------------------------------------------
# OCI-compliant labels for container metadata
LABEL org.opencontainers.image.title="IoTGuard"
LABEL org.opencontainers.image.description="IoT Intrusion Detection System with ML-based threat detection"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.authors="IoTGuard Team"
LABEL org.opencontainers.image.source="https://github.com/A7medico/iotguard"

# -----------------------------------------------------------------------------
# Working Directory
# -----------------------------------------------------------------------------
WORKDIR /app

# -----------------------------------------------------------------------------
# Dependencies Installation
# -----------------------------------------------------------------------------
# Copy requirements first for better Docker layer caching
# Dependencies won't be reinstalled unless requirements.txt changes
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# -----------------------------------------------------------------------------
# Application Code
# -----------------------------------------------------------------------------
# Copy the entire project
COPY . ./

# -----------------------------------------------------------------------------
# Environment Configuration
# -----------------------------------------------------------------------------
# Default configuration file path (can be overridden at runtime)
# Options: configs/model.yaml (default), configs/model_lab.yaml, configs/model_prod.yaml
ENV IOTGUARD_CONFIG=configs/model.yaml

# Optional: Set log level (DEBUG, INFO, WARNING, ERROR)
ENV IOTGUARD_LOG_LEVEL=INFO

# -----------------------------------------------------------------------------
# Networking
# -----------------------------------------------------------------------------
# Expose the API dashboard port
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
CMD ["python", "scripts/api_dashboard.py"]
