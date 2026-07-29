Self-signed CA certificate and key for signing dynamically minted downstream certificates

```bash
openssl req -x509 -newkey rsa:2048 -keyout tls.key -out tls.crt -sha256 -days 18250 -nodes \
  -subj "/CN=test-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
```
