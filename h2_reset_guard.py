class H2ResetGuard:
    """HTTP/2 stream lifecycle, concurrency quota and overload control."""

    def __init__(self, max_streams=100, reset_rate=100, header_block_limit=16384,
                 header_list_limit=8192, push_limit=0, tls_required=True):
        raise NotImplementedError()

    def open_stream(self, conn_id, stream_id):
        raise NotImplementedError()

    def reset_stream(self, conn_id, stream_id, now, cleanup_done=False):
        raise NotImplementedError()

    def close_stream(self, conn_id, stream_id):
        raise NotImplementedError()

    def check_headers(self, conn_id, stream_id, header_block):
        raise NotImplementedError()

    def goaway(self, conn_id):
        raise NotImplementedError()

    def set_priority(self, conn_id, stream_id, depends_on):
        raise NotImplementedError()

    def window_update(self, conn_id, delta):
        raise NotImplementedError()

    def upgrade(self, conn_id, scheme):
        raise NotImplementedError()
