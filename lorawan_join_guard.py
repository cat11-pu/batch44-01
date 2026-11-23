import hashlib
import hmac
import json
import os


RX1_BASE_DELAY_MS = 5000
RX2_BASE_DELAY_MS = 6000

STATE_PATH_ALIASES = (
    "state_path",
    "state_file",
    "state_file_path",
    "persistence_path",
    "storage_path",
    "db_path",
)


class LorawanJoinGuard:
    """LoRaWAN join validation, address allocation and session derivation."""

    def __init__(self, join_euis=("70B3D57ED0000001",),
                 dev_addr_pool=("01000001", "01000002"),
                 cf_list=(868100000, 868300000, 868500000),
                 state_path=None, root_key="old", **kwargs):
        for alias in STATE_PATH_ALIASES:
            if alias in kwargs and state_path is None:
                state_path = kwargs.pop(alias)
        self._join_euis = tuple(join_euis)
        self._dev_addr_pool = tuple(dev_addr_pool)
        self._cf_list = tuple(cf_list)
        self._state_path = state_path
        self._trusted_keys = {root_key}
        self._dev_nonces = {}
        self._join_nonces = {}
        self._addr_by_dev = {}
        self._sessions = {}
        self.counters = {}
        self._load_state()

    def check_join_request(self, request):
        self._bump("join_request_total")
        root_key = request.get("root_key")
        if not self._mic_is_valid(request.get("mic"), root_key):
            return self._deny("JOIN_MIC_INVALID", silent=True)

        join_eui = request.get("join_eui")
        if join_eui not in self._join_euis:
            return self._deny("JOIN_EUI_UNKNOWN")

        if tuple(request.get("cf_list") or ()) != self._cf_list:
            return self._deny("JOIN_CFLIST_MISMATCH")

        if request.get("adr"):
            return self._deny("JOIN_ADR_TOO_EARLY")

        drift_ms = int(request.get("drift_ms") or 0)
        rx1_delay = max(0, RX1_BASE_DELAY_MS - drift_ms)
        rx2_delay = max(0, RX2_BASE_DELAY_MS - drift_ms)

        rejoin_type = request.get("rejoin_type")
        if rejoin_type == 2:
            self._bump("rejoin_type_2")
            self._save_state()
            return {
                "ok": True,
                "dev_eui": request.get("dev_eui"),
                "join_eui": join_eui,
                "rejoin": True,
                "rx1_delay": rx1_delay,
                "rx2_delay": rx2_delay,
            }

        dev_eui = request.get("dev_eui")
        nonce_key = self._nonce_key(join_eui, dev_eui)
        dev_nonce = request.get("dev_nonce")
        if dev_nonce in self._dev_nonces.setdefault(nonce_key, []):
            return self._deny("JOIN_DEV_NONCE_REPLAY")

        addr_result = self.allocate_dev_addr(dev_eui)
        if not addr_result.get("ok"):
            return addr_result

        self._dev_nonces[nonce_key].append(dev_nonce)
        self._sessions[dev_eui] = {
            "dev_eui": dev_eui,
            "join_eui": join_eui,
            "dev_addr": addr_result["dev_addr"],
            "dev_nonce": dev_nonce,
        }
        self._bump("join_accepted")
        self._save_state()
        return {
            "ok": True,
            "dev_eui": dev_eui,
            "join_eui": join_eui,
            "dev_addr": addr_result["dev_addr"],
            "rejoin": False,
            "rx1_delay": rx1_delay,
            "rx2_delay": rx2_delay,
        }

    def handle_join_accept(self, accept):
        self._bump("join_accept_total")
        root_key = accept.get("root_key")
        if not self._mic_is_valid(accept.get("mic"), root_key):
            return self._deny("JOIN_MIC_INVALID", silent=True)

        join_eui = accept.get("join_eui")
        if join_eui not in self._join_euis:
            return self._deny("JOIN_EUI_UNKNOWN")

        join_nonce = accept.get("join_nonce")
        previous = self._join_nonces.get(join_eui)
        if previous is not None and join_nonce <= previous:
            return self._deny("JOIN_NONCE_ROLLBACK")

        self._join_nonces[join_eui] = join_nonce
        self._bump("join_accept_accepted")
        self._save_state()
        return {
            "ok": True,
            "join_eui": join_eui,
            "join_nonce": join_nonce,
        }

    def allocate_dev_addr(self, dev_eui):
        existing = self._addr_by_dev.get(dev_eui)
        if existing is not None:
            return {"ok": True, "dev_eui": dev_eui, "dev_addr": existing}

        used = set(self._addr_by_dev.values())
        for dev_addr in self._dev_addr_pool:
            if dev_addr not in used:
                self._addr_by_dev[dev_eui] = dev_addr
                self._save_state()
                return {"ok": True, "dev_eui": dev_eui, "dev_addr": dev_addr}
        return self._deny("JOIN_ADDR_EXHAUSTED", persist=False)

    def derive_session_keys(self, dev_eui, version):
        if isinstance(version, str) and version.startswith("1.0"):
            labels = ("NwkSKey", "AppSKey")
        elif isinstance(version, str) and version.startswith("1.1"):
            labels = ("FNwkSIntKey", "SNwkSIntKey", "NwkSEncKey", "AppSKey")
        else:
            return self._deny("JOIN_VERSION_UNSUPPORTED", persist=False)

        keys = {
            label: self._derive_key(dev_eui, version, label)
            for label in labels
        }
        return {
            "ok": True,
            "dev_eui": dev_eui,
            "version": version,
            "keys": keys,
        }

    def rotate_root_key(self, new_key, retire_previous=False):
        if retire_previous:
            self._trusted_keys = {new_key}
        else:
            self._trusted_keys.add(new_key)
        self._bump("root_key_rotated")
        self._save_state()
        return {"ok": True, "active_root_key": new_key,
                "retired_previous": bool(retire_previous)}

    def sessions(self):
        return [dict(session) for session in self._sessions.values()]

    def _mic_is_valid(self, mic, root_key=None):
        if mic != "ok":
            return False
        if root_key is not None and root_key not in self._trusted_keys:
            return False
        return True

    def _derive_key(self, dev_eui, version, label):
        message = "{}|{}|{}".format(dev_eui, version, label).encode("utf-8")
        digest = hmac.new(b"lorawan-join-guard", message, hashlib.sha256)
        return digest.hexdigest().upper()[:32]

    @staticmethod
    def _nonce_key(join_eui, dev_eui):
        return "{}|{}".format(join_eui, dev_eui)

    def _bump(self, name):
        self.counters[name] = self.counters.get(name, 0) + 1

    def _deny(self, code, silent=False, persist=True):
        self._bump(code)
        if persist:
            self._save_state()
        result = {"ok": False, "code": code}
        if silent:
            result["response"] = None
        return result

    def _load_state(self):
        if not self._state_path or not os.path.exists(self._state_path):
            return
        with open(self._state_path, "r", encoding="utf-8") as handle:
            state = json.load(handle)
        self._dev_nonces = {
            key: list(value)
            for key, value in state.get("dev_nonces", {}).items()
        }
        self._join_nonces = dict(state.get("join_nonces", {}))
        self._addr_by_dev = dict(state.get("addr_by_dev", {}))
        self._sessions = dict(state.get("sessions", {}))
        trusted = state.get("trusted_keys")
        if trusted:
            self._trusted_keys = set(trusted)
        self.counters = dict(state.get("counters", {}))

    def _save_state(self):
        if not self._state_path:
            return
        state = {
            "dev_nonces": self._dev_nonces,
            "join_nonces": self._join_nonces,
            "addr_by_dev": self._addr_by_dev,
            "sessions": self._sessions,
            "trusted_keys": sorted(self._trusted_keys),
            "counters": self.counters,
        }
        directory = os.path.dirname(os.path.abspath(self._state_path))
        os.makedirs(directory, exist_ok=True)
        tmp_path = "{}.tmp".format(self._state_path)
        with open(tmp_path, "w", encoding="utf-8") as handle:
            json.dump(state, handle)
        os.replace(tmp_path, self._state_path)
