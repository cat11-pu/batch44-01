class IsisLspGuard:
    """IS-IS LSP acceptance, flooding, LSDB and sequence handling."""

    def __init__(self, level=2, auth_key="key"):
        raise NotImplementedError()

    def accept_lsp(self, lsp, now):
        raise NotImplementedError()

    def purge(self, lsp_id, now):
        raise NotImplementedError()

    def expire(self, now):
        raise NotImplementedError()

    def process_csnp(self, csnp):
        raise NotImplementedError()

    def run_spf(self, converged=True):
        raise NotImplementedError()

    def lsdb(self):
        raise NotImplementedError()
