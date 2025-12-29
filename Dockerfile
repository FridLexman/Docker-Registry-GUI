FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

COPY . .

ENV REGISTRY_URL=http://docker-registry:5000
EXPOSE 12000

CMD ["gunicorn", "--bind", "0.0.0.0:12000", "app:app"]
