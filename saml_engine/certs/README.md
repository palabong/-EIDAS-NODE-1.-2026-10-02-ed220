# SAML Trust Anchor Certificates

Mount trusted eIDAS Identity Provider (IdP) X.509 certificates (`*.crt` / `*.pem`) here in deployment or point `SAML_TRUSTED_CERTS_DIR` to a Secret Manager volume mount (e.g. `/run/secrets/saml-idp-certs`).

> **Security Note:** Never store private keys (`*.key` or PEM private key files) in the repository. For local development and automated test suites, `saml_engine` dynamically generates ephemeral keypairs in OS-protected temporary storage (`0700` permissions).
