# Website Authenticity Detector - Container Image
# Minimal container for Playwright + Chromium with non-root user

FROM python:3.11-slim

# Install system dependencies for Playwright/Chromium
RUN apt-get update && apt-get install -y \
    wget \
    gnupg \
    ca-certificates \
    fonts-liberation \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libatspi2.0-0 \
    libcups2 \
    libdbus-1-3 \
    libdrm2 \
    libgbm1 \
    libnspr4 \
    libnss3 \
    libwayland-client0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxkbcommon0 \
    libxrandr2 \
    xdg-utils \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for defense-in-depth
RUN useradd -m -u 1000 analyzer

# Copy requirements and install Python dependencies
COPY requirements.txt /tmp/
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Install Playwright and Chromium as root, then move to analyzer user
RUN playwright install --with-deps chromium

# Move Playwright cache to analyzer user's home directory
RUN mkdir -p /home/analyzer/.cache && \
    cp -r /root/.cache/ms-playwright /home/analyzer/.cache/ && \
    chown -R analyzer:analyzer /home/analyzer/.cache

# Setup analysis directories with restricted permissions
RUN mkdir -p /analysis /results && \
    chown -R analyzer:analyzer /analysis /results

# Switch to non-root user
USER analyzer
WORKDIR /analysis

# Copy application code (only what's needed for container execution)
COPY src/ /analysis/src/
COPY config/ /analysis/config/

# Default command - will be overridden for smoke tests
CMD ["python", "-m", "src.container_analyzer"]
