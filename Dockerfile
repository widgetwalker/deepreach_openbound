# Use a slim, official Python base image
FROM python:3.11-slim as builder

# Set build directory
WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy packaging and source files
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Install the package and dependencies using pip
RUN pip install --no-cache-dir --user .

# Use a clean slim image for run stage to keep it lightweight and secure
FROM python:3.11-slim

# Create a non-privileged user and group for security hardening
RUN groupadd -g 10001 deepreach && \
    useradd -u 10001 -g deepreach -m -s /bin/bash deepreach

# Set environment path for pip installed scripts
ENV PATH=/home/deepreach/.local/bin:$PATH

WORKDIR /workspace
USER deepreach

# Copy installed package and libraries from builder
COPY --from=builder --chown=deepreach:deepreach /root/.local /home/deepreach/.local

# Define entrypoint to run deepreach CLI directly
ENTRYPOINT ["deepreach"]
CMD ["--help"]
