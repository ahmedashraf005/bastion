FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HF_HOME=/var/lib/bastion/huggingface

WORKDIR /app

COPY requirements.txt ./
# Gate is CPU-bound; use PyTorch's CPU wheel index so the image does not
# include unused CUDA runtime packages.
RUN pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch \
    && pip install --no-cache-dir -r requirements.txt \
    && python -m spacy download en_core_web_sm

COPY . ./
COPY docker-entrypoint.sh /usr/local/bin/bastion-gate-entrypoint
RUN chmod +x /usr/local/bin/bastion-gate-entrypoint

ENTRYPOINT ["/usr/local/bin/bastion-gate-entrypoint"]
