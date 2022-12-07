## Internal HTTP server

#### create a new self-signed certificate:
```bash
cd cnv-tests/containers/internal_http/certs

openssl req -x509 -new -newkey rsa:4096 -sha256 -days 3650 -nodes \
   -keyout tls.key -out tls.crt \
   -subj '/CN=internal-http.cnv-tests-utilities/O=Red Hat/OU=Engineering/ST=Massachussetts/C=US' \
   -extensions san \
   -config <(echo '[req]'; echo 'distinguished_name=req';
             echo '[san]'; echo 'subjectAltName=DNS:internal-http.cnv-tests-utilities')

chmod 644 tls.crt
chmod 644 tls.key
```

#### build:
```bash
cd cnv-tests
make build-and-push-internal-http-server-container
```
