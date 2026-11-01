# Disposable FTPS server (pyftpdlib, TLS required) for the end-to-end tests.
FROM python:3.13-alpine
RUN apk add --no-cache openssl && pip install --no-cache-dir pyftpdlib pyopenssl \
 && openssl req -x509 -nodes -newkey rsa:2048 -days 3650 -subj /CN=ftps -keyout /key.pem -out /cert.pem \
 && mkdir -p /data/www
COPY server.py /server.py
CMD ["python", "/server.py"]
