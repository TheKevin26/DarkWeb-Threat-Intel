# --- build the dashboard ---------------------------------------------------------------------
FROM node:20-alpine AS web
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci --no-audit --no-fund || npm install --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# --- python app ------------------------------------------------------------------------------
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN useradd --create-home --uid 1000 onionlens
COPY pyproject.toml README.md ./
COPY onionlens ./onionlens
RUN pip install --no-cache-dir ".[postgres,queue,search]"
COPY config ./config
COPY --from=web /web/dist ./frontend/dist
RUN mkdir -p /app/data && chown -R onionlens /app/data
USER onionlens
EXPOSE 8000
CMD ["uvicorn", "onionlens.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
