# Website Authenticity Detector - Cloud Production Container Image
# Complete production container for FastAPI + Uvicorn + Playwright + XGBoost

FROM python:3.11-slim

# Install system dependencies for Playwright / Chromium headless execution
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

# Create non-root application user for defense-in-depth security
RUN useradd -m -u 1000 appuser

# Install Python dependencies
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Install Playwright and Chromium browser binary as root
RUN playwright install --with-deps chromium

# Copy Playwright browser cache to non-root user directory
RUN mkdir -p /home/appuser/.cache && \
    cp -r /root/.cache/ms-playwright /home/appuser/.cache/ && \
    chown -R appuser:appuser /home/appuser/.cache

# Setup application directories
RUN mkdir -p /app /app/models /app/results && \
    chown -R appuser:appuser /app

# Switch to non-root user
ENV PLAYWRIGHT_BROWSERS_PATH=/home/appuser/.cache/ms-playwright
ENV HOME=/home/appuser
ENV PYTHONUNBUFFERED=1
ENV PORT=8000
ENV HOST=0.0.0.0

USER appuser
WORKDIR /app

# Copy all application assets, models, web UI, and configuration
COPY src/ /app/src/
COPY config/ /app/config/
COPY models/ /app/models/
COPY web/ /app/web/
COPY run_server.py /app/run_server.py

# Expose default HTTP port (dynamically overridden by $PORT on cloud platforms)
EXPOSE 8000

# Default command: Start Uvicorn web server
CMD ["python", "run_server.py"]
