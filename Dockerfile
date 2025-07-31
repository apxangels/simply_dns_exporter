FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt ./
COPY exporter.py config.yml ./
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 9116
ENTRYPOINT ["python", "/app/exporter.py", "-config.file=/app/config.yml"]