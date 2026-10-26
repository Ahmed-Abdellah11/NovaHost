FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      dnsmasq-base iproute2 iputils-ping dnsutils procps \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements-runtime.txt .
RUN pip install --no-cache-dir -r requirements-runtime.txt
COPY nova ./nova
COPY models ./models
COPY config ./config
COPY docker/dnsmasq.conf /etc/dnsmasq.conf
COPY docker/entrypoint.sh /entrypoint.sh
ENV NOVA_DATA_DIR=/data NOVA_CONFIG_DIR=/app/config UPSTREAM_DNS=8.8.8.8 PYTHONUNBUFFERED=1
VOLUME /data
EXPOSE 53/udp 53/tcp 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/health', timeout=3)" || exit 1
CMD ["/entrypoint.sh"]
