FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py pytest.ini ./
COPY src ./src
COPY static ./static

EXPOSE 8000 2222 2323
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
