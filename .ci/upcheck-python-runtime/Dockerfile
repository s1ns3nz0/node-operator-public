FROM python@sha256:5e0ede45886712ce95b0e66232f743cc3d69ff6c2f62cc0d63778e1e894f8bd4
RUN apk upgrade --no-cache libcrypto3 libssl3 libuuid && \
    python3 -c 'import sys, ssl, socket, http.client, http.server; assert sys.version_info[:3] == (3, 14, 7); print(ssl.OPENSSL_VERSION)'
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 1000:1000
CMD ["python3", "--version"]
