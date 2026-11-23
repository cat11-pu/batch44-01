class OidcJweDecryptor:
    """JWE algorithm policy, key selection, rotation and claim checks."""

    def __init__(self, allowed_algs=("RSA-OAEP",), allowed_encs=("A256GCM",),
                 clock_skew=0, max_plaintext=4096):
        raise NotImplementedError()

    def add_key(self, kid, key, retire_at=None):
        raise NotImplementedError()

    def decrypt(self, token, now=0, issuer="https://issuer", audience="client"):
        raise NotImplementedError()

    def validate_claims(self, claims, issuer, audience, now):
        raise NotImplementedError()
