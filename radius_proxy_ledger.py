class RadiusProxyLedger:
    """RADIUS proxy routing, authenticator checks and accounting dedupe."""

    def __init__(self, shared_secret="shared", max_hops=16, queue_limit=10,
                 nas_sources=None, trusted_proxies=("10.0.0.1",)):
        raise NotImplementedError()

    def authenticate(self, request):
        raise NotImplementedError()

    def forward(self, request):
        raise NotImplementedError()

    def account(self, request, now):
        raise NotImplementedError()

    def check_response(self, request, response):
        raise NotImplementedError()

    def hide_user_password(self, secret, plain):
        raise NotImplementedError()

    def sessions(self):
        raise NotImplementedError()
