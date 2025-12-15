FROM python:3.9-slim

WORKDIR /app

# Install system dependencies if needed
# RUN apt-get update && apt-get install -y gcc

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Expose port (must match app_enhanced.py)
EXPOSE 8080

CMD ["python", "app_enhanced.py"]
