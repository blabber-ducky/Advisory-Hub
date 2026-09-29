# syntax=docker/dockerfile:1
# TLS-terminating proxy for the HTTPS overlay (docker-compose.https.yml).
#
# Stock nginx with the Advisory Hub site template baked in, so a deployment
# host needs only the compose files and its certificates — not a checkout of
# docker/nginx/. Certificates are never baked in: they are mounted at
# /etc/nginx/certs at runtime (scripts/https-setup.sh, docs/operations.md §7).
FROM nginx:1.27-alpine

# Rendered by the image's own entrypoint (envsubst) at container start.
COPY docker/nginx/advisory-hub.conf.template /etc/nginx/templates/default.conf.template

# Only substitute our own variables; leave nginx's $host etc. alone.
ENV NGINX_ENVSUBST_FILTER="^(SERVER_NAME|HSTS_MAX_AGE)$" \
    HSTS_MAX_AGE=31536000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -q --spider http://127.0.0.1/health/live || exit 1
