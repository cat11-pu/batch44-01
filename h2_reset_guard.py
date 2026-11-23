from collections import deque
from threading import RLock


class H2ResetGuard:
    """HTTP/2 stream lifecycle, concurrency quota and overload control."""

    MAX_WINDOW_SIZE = (1 << 31) - 1
    RESET_WINDOW_SECONDS = 1.0

    def __init__(self, max_streams=100, reset_rate=100, header_block_limit=16384,
                 header_list_limit=8192, push_limit=0, tls_required=True):
        self.max_streams = max(0, int(max_streams))
        self.reset_rate = max(0, int(reset_rate))
        self.header_block_limit = max(0, int(header_block_limit))
        self.header_list_limit = max(0, int(header_list_limit))
        self.push_limit = max(0, int(push_limit))
        self.tls_required = bool(tls_required)

        self._connections = {}
        self._lock = RLock()

    @staticmethod
    def _ok(**fields):
        result = {"ok": True}
        result.update(fields)
        return result

    @staticmethod
    def _error(code, error=None, **fields):
        result = {"ok": False, "code": code}
        if error is not None:
            result["error"] = error
        result.update(fields)
        return result

    @staticmethod
    def _is_stream_id(stream_id):
        return (isinstance(stream_id, int)
                and not isinstance(stream_id, bool)
                and stream_id > 0)

    def _connection(self, conn_id):
        conn = self._connections.get(conn_id)
        if conn is None:
            conn = {
                "streams": {},
                "active_streams": 0,
                "reset_times": deque(),
                "closed": False,
                "goaway_needed": False,
                "goaway_sent": False,
                "last_stream_id": 0,
                "max_seen_stream_id": 0,
                "window": 0,
                "priorities": {},
                "header_blocks": {},
            }
            self._connections[conn_id] = conn
        return conn

    @staticmethod
    def _connection_closed_result():
        return H2ResetGuard._error(
            "H2_CONNECTION_CLOSED",
            error="PROTOCOL_ERROR",
            close_connection=True,
        )

    @staticmethod
    def _mark_for_reset(conn, stream_id):
        state = conn["streams"].get(stream_id)
        if state is not None and state["state"] == "open":
            state["state"] = "resetting"

    def _release_stream(self, conn, stream_id):
        state = conn["streams"].get(stream_id)
        if state is None or state["state"] == "closed":
            return False
        state["state"] = "closed"
        conn["active_streams"] = max(0, conn["active_streams"] - 1)
        conn["header_blocks"].pop(stream_id, None)
        return True

    def open_stream(self, conn_id, stream_id):
        with self._lock:
            conn = self._connection(conn_id)
            if conn["closed"]:
                return self._connection_closed_result()
            if conn["goaway_sent"] or conn["goaway_needed"]:
                return self._error(
                    "H2_GOAWAY",
                    error="NO_ERROR",
                    action="GOAWAY",
                    last_stream_id=conn["last_stream_id"],
                )
            if not self._is_stream_id(stream_id):
                return self._error("H2_STREAM_ID_INVALID", error="PROTOCOL_ERROR")
            if stream_id <= conn["max_seen_stream_id"]:
                return self._error(
                    "H2_STREAM_REUSED",
                    error="PROTOCOL_ERROR",
                    stream_id=stream_id,
                    last_stream_id=conn["last_stream_id"],
                )

            conn["max_seen_stream_id"] = stream_id
            if conn["active_streams"] >= self.max_streams:
                conn["goaway_needed"] = True
                return self._error(
                    "H2_STREAM_LIMIT",
                    error="REFUSED_STREAM",
                    action="GOAWAY",
                    stream_id=stream_id,
                    last_stream_id=conn["last_stream_id"],
                    active_streams=conn["active_streams"],
                    max_streams=self.max_streams,
                    goaway_needed=True,
                )

            conn["streams"][stream_id] = {"state": "open"}
            conn["active_streams"] += 1
            conn["last_stream_id"] = stream_id
            return self._ok(
                stream_id=stream_id,
                active_streams=conn["active_streams"],
                max_streams=self.max_streams,
                state="open",
            )

    def reset_stream(self, conn_id, stream_id, now, cleanup_done=False):
        with self._lock:
            conn = self._connection(conn_id)
            if conn["closed"]:
                return self._connection_closed_result()

            state = conn["streams"].get(stream_id)
            if state is None:
                return self._error(
                    "H2_STREAM_NOT_OPEN",
                    error="PROTOCOL_ERROR",
                    stream_id=stream_id,
                )
            if state["state"] == "closed":
                return self._error(
                    "H2_STREAM_CLOSED",
                    error="STREAM_CLOSED",
                    stream_id=stream_id,
                )

            if state["state"] == "resetting":
                if cleanup_done:
                    self._release_stream(conn, stream_id)
                    return self._ok(
                        stream_id=stream_id,
                        state="closed",
                        active_streams=conn["active_streams"],
                        quota_released=True,
                        quota_held=False,
                    )
                return self._ok(
                    stream_id=stream_id,
                    state="resetting",
                    active_streams=conn["active_streams"],
                    quota_released=False,
                    quota_held=True,
                )

            timestamp = float(now)
            cutoff = timestamp - self.RESET_WINDOW_SECONDS
            reset_times = conn["reset_times"]
            while reset_times and reset_times[0] <= cutoff:
                reset_times.popleft()

            if len(reset_times) >= self.reset_rate:
                conn["closed"] = True
                conn["goaway_needed"] = True
                return self._error(
                    "H2_RESET_FLOOD",
                    error="ENHANCE_YOUR_CALM",
                    action="GOAWAY",
                    close_connection=True,
                    stream_id=stream_id,
                    reset_rate=self.reset_rate,
                )
            reset_times.append(timestamp)

            state["state"] = "resetting"
            if cleanup_done:
                self._release_stream(conn, stream_id)
                return self._ok(
                    stream_id=stream_id,
                    state="closed",
                    active_streams=conn["active_streams"],
                    quota_released=True,
                    quota_held=False,
                )
            return self._ok(
                stream_id=stream_id,
                state="resetting",
                active_streams=conn["active_streams"],
                quota_released=False,
                quota_held=True,
            )

    def close_stream(self, conn_id, stream_id):
        with self._lock:
            conn = self._connection(conn_id)
            if conn["closed"]:
                return self._connection_closed_result()

            state = conn["streams"].get(stream_id)
            if state is None:
                return self._error(
                    "H2_STREAM_NOT_OPEN",
                    error="PROTOCOL_ERROR",
                    stream_id=stream_id,
                )
            if state["state"] == "closed":
                return self._error(
                    "H2_STREAM_CLOSED",
                    error="STREAM_CLOSED",
                    stream_id=stream_id,
                )
            if state["state"] == "resetting":
                return self._ok(
                    stream_id=stream_id,
                    state="resetting",
                    active_streams=conn["active_streams"],
                    quota_released=False,
                    quota_held=True,
                )

            self._release_stream(conn, stream_id)
            return self._ok(
                stream_id=stream_id,
                state="closed",
                active_streams=conn["active_streams"],
                quota_released=True,
                quota_held=False,
            )

    def check_headers(self, conn_id, stream_id, header_block):
        with self._lock:
            conn = self._connection(conn_id)
            if conn["closed"]:
                return self._connection_closed_result()
            if not isinstance(header_block, dict):
                return self._error(
                    "H2_HEADER_BLOCK_INVALID",
                    error="PROTOCOL_ERROR",
                    action="RST_STREAM",
                    rst_stream=True,
                    stream_id=stream_id,
                )

            size = max(0, self._int_value(header_block.get("size", 0)))
            header_list_size = max(
                0, self._int_value(header_block.get("header_list_size", 0))
            )
            push_promises = max(
                0, self._int_value(header_block.get("push_promises", 0))
            )
            continuation = bool(header_block.get("continuation", False))

            block_state = conn["header_blocks"].get(stream_id)
            if block_state is None or not continuation:
                block_state = {"size": 0, "frames": 0, "list_size": 0,
                               "push_promises": 0}
                conn["header_blocks"][stream_id] = block_state

            block_state["size"] += size
            block_state["list_size"] = max(block_state["list_size"],
                                           header_list_size)
            block_state["push_promises"] = max(block_state["push_promises"],
                                               push_promises)
            if continuation:
                block_state["frames"] += 1

            too_many_frames = (
                continuation
                and block_state["frames"] > self.header_block_limit
            )
            if (block_state["size"] > self.header_block_limit
                    or too_many_frames):
                self._mark_for_reset(conn, stream_id)
                conn["header_blocks"].pop(stream_id, None)
                return self._error(
                    "H2_HEADER_BLOCK_OVERSIZE",
                    error="PROTOCOL_ERROR",
                    action="RST_STREAM",
                    rst_stream=True,
                    stream_id=stream_id,
                    header_block_size=block_state["size"],
                )

            if block_state["list_size"] > self.header_list_limit:
                self._mark_for_reset(conn, stream_id)
                conn["header_blocks"].pop(stream_id, None)
                return self._error(
                    "H2_HEADER_LIST_SIZE",
                    error="ENHANCE_YOUR_CALM",
                    action="RST_STREAM",
                    rst_stream=True,
                    stream_id=stream_id,
                    header_list_size=block_state["list_size"],
                )

            if block_state["push_promises"] > self.push_limit:
                self._mark_for_reset(conn, stream_id)
                conn["header_blocks"].pop(stream_id, None)
                return self._error(
                    "H2_PUSH_LIMIT",
                    error="PROTOCOL_ERROR",
                    action="RST_STREAM",
                    rst_stream=True,
                    stream_id=stream_id,
                    push_promises=block_state["push_promises"],
                    push_limit=self.push_limit,
                )

            if not continuation:
                conn["header_blocks"].pop(stream_id, None)
                return self._ok(stream_id=stream_id, action="END_HEADERS")
            return self._ok(stream_id=stream_id, action="CONTINUE")

    @staticmethod
    def _int_value(value):
        if isinstance(value, bool):
            return int(value)
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    def goaway(self, conn_id):
        with self._lock:
            conn = self._connection(conn_id)
            needed = conn["goaway_needed"]
            conn["goaway_needed"] = False
            conn["goaway_sent"] = True
            result = self._ok(
                needed=needed,
                last_stream_id=conn["last_stream_id"],
                action="GOAWAY",
            )
            if needed:
                result["code"] = "H2_GOAWAY"
                result["error"] = "ENHANCE_YOUR_CALM"
            return result

    def set_priority(self, conn_id, stream_id, depends_on):
        with self._lock:
            conn = self._connection(conn_id)
            if conn["closed"]:
                return self._connection_closed_result()
            if (not self._is_stream_id(stream_id)
                    or not isinstance(depends_on, int)
                    or isinstance(depends_on, bool)
                    or depends_on < 0):
                return self._error("H2_STREAM_ID_INVALID", error="PROTOCOL_ERROR")
            if depends_on == stream_id:
                return self._error(
                    "H2_PRIORITY_CYCLE",
                    error="PROTOCOL_ERROR",
                    stream_id=stream_id,
                    depends_on=depends_on,
                )

            priorities = conn["priorities"]
            current = depends_on
            visited = set()
            while current != 0 and current not in visited:
                if current == stream_id:
                    return self._error(
                        "H2_PRIORITY_CYCLE",
                        error="PROTOCOL_ERROR",
                        stream_id=stream_id,
                        depends_on=depends_on,
                    )
                visited.add(current)
                current = priorities.get(current, 0)

            if depends_on == 0:
                priorities.pop(stream_id, None)
            else:
                priorities[stream_id] = depends_on
            return self._ok(stream_id=stream_id, depends_on=depends_on)

    def window_update(self, conn_id, delta):
        with self._lock:
            conn = self._connection(conn_id)
            if conn["closed"]:
                return self._connection_closed_result()
            if (not isinstance(delta, int) or isinstance(delta, bool)
                    or delta <= 0):
                conn["closed"] = True
                conn["goaway_needed"] = True
                return self._error(
                    "H2_FLOW_CONTROL_ERROR",
                    error="PROTOCOL_ERROR",
                    close_connection=True,
                    delta=delta,
                )

            current = conn["window"]
            if current > self.MAX_WINDOW_SIZE - delta:
                conn["closed"] = True
                conn["goaway_needed"] = True
                return self._error(
                    "H2_FLOW_CONTROL_ERROR",
                    error="FLOW_CONTROL_ERROR",
                    close_connection=True,
                    delta=delta,
                    window=current,
                )

            conn["window"] = current + delta
            return self._ok(window=conn["window"], delta=delta)

    def upgrade(self, conn_id, scheme):
        with self._lock:
            conn = self._connection(conn_id)
            if conn["closed"]:
                return self._connection_closed_result()

            normalized = str(scheme).strip().lower() if scheme is not None else ""
            if self.tls_required and normalized not in {"https", "h2", "tls"}:
                return self._error(
                    "H2_PLAINTEXT_DENIED",
                    error="INADEQUATE_SECURITY",
                    close_connection=True,
                    scheme=normalized,
                )

            conn["scheme"] = normalized
            return self._ok(scheme=normalized)
