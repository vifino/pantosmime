
# Manual Cert Extraction from .p7s
```sh
openssl pkcs7 -inform DER -in user@example.com.p7s -print_certs -outform PEM
```

We only need the cert matching the email for encryption, the previous certs are for validation.
