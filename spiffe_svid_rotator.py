class SpiffeSvidRotator:
    """SVID issuance, trust bundle handling, revocation and rotation."""

    def __init__(self, trust_bundle=("root-a",), required_selectors=None,
                 bundle_confirmed=True, audiences=("api",)):
        raise NotImplementedError()

    def attest(self, workload):
        raise NotImplementedError()

    def rotate(self, spiffe_id, now):
        raise NotImplementedError()

    def validate(self, svid, bundle, now):
        raise NotImplementedError()

    def revoke(self, serial):
        raise NotImplementedError()

    def update_bundle(self, roots, expired=()):
        raise NotImplementedError()

    def bundle(self):
        raise NotImplementedError()
