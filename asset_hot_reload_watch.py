class ReloadError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class AssetHotReloadWatch:
    """Watch events, dependency graph, atomic swap and handle generations."""

    def __init__(self, *, debounce_ms=200):
        self.debounce_ms = debounce_ms

    def register(self, path, *, data=None, deps=(), kind="texture", uid=None,
                 packed=False, source=None):
        raise NotImplementedError

    def update(self, path, data):
        raise NotImplementedError

    def notify(self, path, *, now=0, force=False):
        raise NotImplementedError

    def flush(self, *, fail_at=None):
        raise NotImplementedError

    def read(self, path):
        raise NotImplementedError

    def handle(self, path):
        raise NotImplementedError

    def resolve(self, handle):
        raise NotImplementedError

    def remove(self, path):
        raise NotImplementedError

    def move(self, old_path, new_path):
        raise NotImplementedError

    def set_source(self, path, data):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError
