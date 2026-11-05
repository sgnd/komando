# registry:2 with HTTPS and a certificate from a private CA (like mkcert or
# an internal CA), for the registry TLS checks in the end-to-end tests. The
# name registry.lab.test only resolves on the lab's private network, so
# komando reaches it through bastion, which looks the name up.
FROM registry:2
RUN apk add --no-cache openssl && mkdir /certs && cd /certs \
 && openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=komando e2e CA" \
      -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign \
      -keyout ca.key -out ca.crt \
 && openssl req -newkey rsa:2048 -nodes -subj /CN=registry.lab.test -keyout server.key -out server.csr \
 && printf 'subjectAltName=DNS:registry.lab.test\nextendedKeyUsage=serverAuth\n' > ext \
 && openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 3650 -extfile ext -out server.crt \
 && rm ca.key server.csr ext
ENV REGISTRY_HTTP_ADDR=:443 REGISTRY_HTTP_TLS_CERTIFICATE=/certs/server.crt REGISTRY_HTTP_TLS_KEY=/certs/server.key
