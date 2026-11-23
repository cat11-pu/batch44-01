class LorawanJoinGuard:
    """LoRaWAN join validation, address allocation and session derivation."""

    def __init__(self, join_euis=("70B3D57ED0000001",),
                 dev_addr_pool=("01000001", "01000002"),
                 cf_list=(868100000, 868300000, 868500000)):
        raise NotImplementedError()

    def check_join_request(self, request):
        raise NotImplementedError()

    def handle_join_accept(self, accept):
        raise NotImplementedError()

    def allocate_dev_addr(self, dev_eui):
        raise NotImplementedError()

    def derive_session_keys(self, dev_eui, version):
        raise NotImplementedError()

    def rotate_root_key(self, new_key, retire_previous=False):
        raise NotImplementedError()

    def sessions(self):
        raise NotImplementedError()
