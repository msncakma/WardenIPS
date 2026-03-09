FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ipset iptables ip6tables && \
    rm -rf /var/lib/apt/lists/*

# Create app directories
RUN mkdir -p /opt/wardenips /var/lib/wardenips /var/log/wardenips

WORKDIR /opt/wardenips

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY main.py config.yaml ./
COPY wardenips/ wardenips/

# Data and log volumes
VOLUME ["/var/lib/wardenips", "/var/log/wardenips"]

# Default config can be overridden via mount
VOLUME ["/opt/wardenips/config.yaml"]

# Required for ipset/iptables — container must run with NET_ADMIN capability
# Run with: docker run --cap-add NET_ADMIN --net host ...

ENTRYPOINT ["python3", "main.py"]
CMD ["--config", "config.yaml"]
