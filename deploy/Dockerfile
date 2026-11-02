FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY oriap ./oriap
RUN useradd -r -u 10001 oria
USER oria
EXPOSE 8765
CMD ["python", "-m", "oriap", "serve", "--host", "0.0.0.0", "--port", "8765"]
