class OcspStapleResponder:
    """OCSP response cache, refresh gating and staple binding."""

    def __init__(self, allowed_schemes=("https",), produced_skew=0):
        raise NotImplementedError()

    def store_response(self, record):
        raise NotImplementedError()

    def lookup(self, serial, issuer, nonce, now):
        raise NotImplementedError()

    def validate_delegate(self, delegate):
        raise NotImplementedError()

    def staple(self, hostname, chain, serial, issuer, now):
        raise NotImplementedError()

    def refresh(self, serial, issuer, fetch_result):
        raise NotImplementedError()
