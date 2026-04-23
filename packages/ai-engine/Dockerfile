# Use lightweight Python base image
FROM python:3.11-slim

# Set security headers and environment
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Create non-root user for security (NFR-01)
RUN groupadd -r verichain && useradd -r -g verichain verichain

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Set ownership to non-root user
RUN chown -R verichain:verichain /app
USER verichain

# Internal port only (mTLS/Gateway handles external traffic)
EXPOSE 5001

# Start AI Risk Engine
CMD ["python", "app.py"]
