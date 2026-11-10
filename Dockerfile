# Chronica DFIR Workbench Container
FROM python:3.11-slim-bullseye

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Create unprivileged non-root user
RUN groupadd -r chronica && useradd -r -g chronica -u 1000 -d /app -s /sbin/nologin chronica

# Copy dependency specifications and install
COPY pyproject.toml requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir -e .

# Copy application source code and scenarios
COPY src/ ./src/
COPY synthetic_data/ ./synthetic_data/
COPY app.py ./
COPY .streamlit/ ./.streamlit/

# Create data directory with permissions for non-root user
RUN mkdir -p /app/data && chown -R chronica:chronica /app

# Switch to non-root user
USER chronica

# Expose Streamlit default local port
EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health').read()" || exit 1

# Launch Streamlit bound to localhost in headless mode
ENTRYPOINT ["streamlit", "run", "app.py", "--server.address=127.0.0.1", "--server.headless=true", "--browser.gatherUsageStats=false"]
