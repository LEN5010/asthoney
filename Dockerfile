FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt requirements.lock ./
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py pytest.ini .env.example ./
COPY src ./src
COPY static ./static
COPY scripts ./scripts
COPY tests ./tests

EXPOSE 8000 2222 2323
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
