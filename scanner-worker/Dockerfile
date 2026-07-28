# Scanner worker: runs the real OWASP ZAP Baseline (passive) scan.
# Base image is the official, version-pinned OWASP ZAP stable image, which
# already contains zap-baseline.py and every ZAP add-on needed for a
# baseline scan. Node.js is added on top only to run our thin HTTP wrapper.
FROM zaproxy/zap-stable:2.16.0

USER root

# Node.js 20.x from NodeSource, pinned major version for reproducibility.
RUN apt-get update \
  && apt-get install -y --no-install-recommends curl ca-certificates gnupg \
  && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
  && apt-get install -y --no-install-recommends nodejs \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY src ./src

# The official ZAP image already runs as a non-root "zap" user with a
# writable home directory — reuse it instead of creating a new one.
RUN mkdir -p /app/tmp && chown -R zap:zap /app
USER zap

ENV PORT=8080
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

CMD ["node", "src/server.js"]
