FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl git wget tor torsocks netcat-openbsd \
    libxml2-dev libxslt1-dev libssl-dev libffi-dev \
    libmagic-dev libpango-1.0-0 libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Install the CLI tools invoked by the person-intelligence connectors.
# Keep this step fail-closed: a missing executable must fail the image build
# instead of producing a worker that silently skips a selected source.
RUN pip install --no-cache-dir \
    maigret==0.6.3 \
    sherlock-project==0.16.0 \
    holehe==1.61 && \
    command -v maigret && \
    command -v sherlock && \
    command -v holehe

RUN python -m pip check

# Create a fixed, unprivileged runtime identity and writable data directories.
RUN groupadd --gid 10001 deepvault && \
    useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin deepvault && \
    mkdir -p /data/reports /data/screenshots /data/artifacts && \
    chown -R deepvault:deepvault /app /data

USER deepvault:deepvault

CMD ["celery", "-A", "main", "worker", "--beat", "--loglevel=info", "--schedule=/data/celerybeat-schedule"]
