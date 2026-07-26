FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN groupadd --gid 10001 deepvault && \
    useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin deepvault && \
    mkdir -p /data && \
    chown -R deepvault:deepvault /app /data

USER deepvault:deepvault

EXPOSE 8080

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
