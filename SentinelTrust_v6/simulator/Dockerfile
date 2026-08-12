FROM python:3.11-slim
WORKDIR /app
RUN pip install requests loguru --no-cache-dir
COPY simulator.py .
CMD ["python", "simulator.py"]
