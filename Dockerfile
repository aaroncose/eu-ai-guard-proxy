FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml .
RUN pip install --upgrade pip && pip install .

COPY . .

EXPOSE 8000 8501

CMD ["uvicorn", "proxy.main:app", "--host", "0.0.0.0", "--port", "8000"]