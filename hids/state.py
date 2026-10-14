from __future__ import annotations

import json
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path

from hids.models import ConnectionRecord
from hids.parser import is_public_ip


def _restore_connection_keys(
    raw_entries: object,
) -> set[tuple[int, str, str, int | None, str, int | None, str]]:
    """Rebuild connection keys written by :meth:`DetectionState.to_dict`.

    JSON turns the tuples into lists and loses the int/None distinction, so each
    field is coerced back to the shape ``ConnectionRecord.connection_key`` uses.
    """
    restored: set[tuple[int, str, str, int | None, str, int | None, str]] = set()
    if not isinstance(raw_entries, list):
        return restored

    for entry in raw_entries:
        if not isinstance(entry, (list, tuple)) or len(entry) != 7:
            continue
        try:
            restored.add(
                (
                    int(entry[0]),
                    str(entry[1]),
                    str(entry[2]),
                    None if entry[3] is None else int(entry[3]),
                    str(entry[4]),
                    None if entry[5] is None else int(entry[5]),
                    str(entry[6]),
                )
            )
        except (TypeError, ValueError):
            continue
    return restored


class DetectionState:
    def __init__(self, max_history: int = 20) -> None:
        self._max_history = max_history
        self._previous_connections: set[tuple[int, str, str, int | None, str, int | None, str]] = set()
        self._beacon_history: dict[tuple[int, str, str, int | None], deque[float]] = defaultdict(
            lambda: deque(maxlen=max_history)
        )

    def record_scan(
        self,
        connections: list[ConnectionRecord],
        observed_at: datetime,
    ) -> set[tuple[int, str, str, int | None]]:
        active_keys = {connection.connection_key for connection in connections}
        new_events: set[tuple[int, str, str, int | None]] = set()
        timestamp = observed_at.timestamp()

        for connection in connections:
            if connection.connection_key in self._previous_connections:
                continue
            if connection.direction != "OUTBOUND":
                continue
            if not connection.remote_ip or not is_public_ip(connection.remote_ip):
                continue

            behavior_key = connection.behavior_key
            if behavior_key in new_events:
                # Concurrent sockets to the same endpoint are one observation, not
                # several. Appending once per connection would stack identical
                # timestamps and make any multi-socket client look perfectly periodic.
                continue
            self._beacon_history[behavior_key].append(timestamp)
            new_events.add(behavior_key)

        self._previous_connections = active_keys
        return new_events

    def get_beacon_history(self, connection: ConnectionRecord) -> list[float]:
        return list(self._beacon_history.get(connection.behavior_key, ()))

    def to_dict(self) -> dict[str, object]:
        beacon_history = []
        for (pid, process_name, remote_ip, remote_port), timestamps in self._beacon_history.items():
            if not timestamps:
                continue
            beacon_history.append(
                {
                    "pid": pid,
                    "process_name": process_name,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "timestamps": list(timestamps),
                }
            )

        return {
            "max_history": self._max_history,
            "beacon_history": beacon_history,
            "previous_connections": [list(key) for key in sorted(self._previous_connections, key=repr)],
        }

    def save(self, path: Path | None) -> None:
        if path is None:
            return

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def from_dict(cls, payload: dict[str, object], max_history: int | None = None) -> "DetectionState":
        history_limit = max_history or int(payload.get("max_history", 20))
        state = cls(max_history=history_limit)

        for entry in payload.get("beacon_history", []):
            if not isinstance(entry, dict):
                continue
            key = (
                int(entry.get("pid", -1)),
                str(entry.get("process_name", "")).lower(),
                str(entry.get("remote_ip", "")),
                entry.get("remote_port"),
            )
            timestamps = entry.get("timestamps", [])
            if not isinstance(timestamps, list):
                continue

            state._beacon_history[key] = deque(
                (float(timestamp) for timestamp in timestamps),
                maxlen=history_limit,
            )

        state._previous_connections = _restore_connection_keys(payload.get("previous_connections", []))

        return state

    @classmethod
    def load(cls, path: Path | None, max_history: int = 20) -> "DetectionState":
        if path is None or not path.exists():
            return cls(max_history=max_history)

        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, ValueError):
            return cls(max_history=max_history)

        if not isinstance(payload, dict):
            return cls(max_history=max_history)

        return cls.from_dict(payload, max_history=max_history)
