FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1
RUN useradd -r -u 10002 shipper
WORKDIR /app
COPY shipper.py .
USER shipper
CMD ["python", "shipper.py"]
