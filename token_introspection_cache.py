class TokenIntrospectionCache:
    """Introspection caching, revocation propagation and response checks."""

    def __init__(self, endpoint="https://as.example/introspect", propagation_limit=10,
                 negative_ttl=5):
        raise NotImplementedError()

    def introspect(self, token, tenant, audience, token_type, now, fetch=None):
        raise NotImplementedError()

    def on_revocation(self, token, now):
        raise NotImplementedError()

    def on_scope_change(self, token):
        raise NotImplementedError()

    def validate_response(self, raw):
        raise NotImplementedError()

    def set_endpoint(self, url):
        raise NotImplementedError()

    def begin_introspection(self, token, tenant, audience, token_type):
        raise NotImplementedError()

    def should_introspect(self, token_format, locally_verifiable):
        raise NotImplementedError()

    def stats(self):
        raise NotImplementedError()
