FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app

WORKDIR /app

COPY strike/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# ADR-010 deliberately reuses Gate's live leak-detector implementation for
# synthesis verification; copy source only, never Gate's Prompt Guard cache.
COPY strike /app/strike
COPY gate /app/gate
COPY strike/docker-entrypoint.sh /usr/local/bin/bastion-strike-entrypoint
RUN chmod +x /usr/local/bin/bastion-strike-entrypoint

ENTRYPOINT ["/usr/local/bin/bastion-strike-entrypoint"]
