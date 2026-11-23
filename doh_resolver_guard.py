class DohResolverGuard:
    """Encrypted DNS request parsing, upstream validation and cache."""

    def __init__(self, internal_suffixes=(".internal", ".corp"), upstreams=None):
        raise NotImplementedError()

    def parse_request(self, method, path, headers, body):
        raise NotImplementedError()

    def check_response(self, query, response):
        raise NotImplementedError()

    def resolve(self, query, now, upstream_response=None, tcp_response=None):
        raise NotImplementedError()

    def begin_fetch(self, query):
        raise NotImplementedError()

    def build_upstream_query(self, query):
        raise NotImplementedError()
