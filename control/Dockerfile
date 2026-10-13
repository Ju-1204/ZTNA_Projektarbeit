FROM python:3.12-slim

# wireguard-tools: 'wg genkey'/'wg pubkey' für die Schlüsselgenerierung im Enrollment
RUN apt-get update \
    && apt-get install -y --no-install-recommends wireguard-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
