class SaveError(ValueError):
    def __init__(self, code, detail=None):
        super().__init__(code)
        self.code = code
        self.detail = detail


class SaveCloudMerge:
    """Version chain, field-level conflict merge and atomic save commit."""

    def __init__(self):
        self._slots = {}

    def upload(self, slot, device, payload, *, version=None, device_time=0,
               complete=True, recreate=False):
        raise NotImplementedError

    def download(self, slot, device=None):
        raise NotImplementedError

    def merge(self, local, cloud, *, strategy="field"):
        raise NotImplementedError

    def delete(self, slot):
        raise NotImplementedError

    def history(self, slot=None):
        raise NotImplementedError

    def recover(self, slot):
        raise NotImplementedError

    def slots(self):
        raise NotImplementedError
