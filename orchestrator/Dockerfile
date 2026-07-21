FROM python:3.12-slim

WORKDIR /app

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl git wget tor torsocks netcat-openbsd \
    libxml2-dev libxslt1-dev libssl-dev libffi-dev \
    libmagic-dev libpango-1.0-0 libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 libffi-dev shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Install OSINT CLI tools
RUN mkdir -p /tools && \
    pip install maigret sherlock whatsmyname holehe social-analyzer && \
    git clone --depth 1 https://github.com/laramies/theHarvester.git /tools/theHarvester && \
    cd /tools/theHarvester && pip install -r requirements/base.txt && \
    git clone --depth 1 https://github.com/DedSecInside/TorBot.git /tools/TorBot && \
    cd /tools/TorBot && pip install -r requirements.txt && python3 setup.py install || true

# Create data directories
RUN mkdir -p /data/reports /data/screenshots /data/artifacts

CMD ["celery", "-A", "main", "worker", "--beat", "--loglevel=info"]
