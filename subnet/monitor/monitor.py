import requests
import threading
from typing import List

from subnet.shared import logging as sv
from subnet.monitor.monitor_constants import MONITOR_URL, LOGGING_NAME, LOGGING_DELTA


class Monitor(threading.Thread):
    def __init__(self):
        super().__init__()
        self.stop_flag = threading.Event()
        self._lock = threading.Lock()
        self._data = {}

        self.last_modified = None
        self.show_not_found = True
        self.hash = None

    def get_suspicious_uids(self) -> List[int]:
        with self._lock:
            suspicious = self._data.get("suspicious") or []
            return list(suspicious)

    def run(self):
        try:
            while not self.stop_flag.is_set():
                response = requests.get(MONITOR_URL)
                if response.status_code != 200:
                    if response.status_code == 404 and not self.show_not_found:
                        continue

                    self.show_not_found = response.status_code != 404
                    sv.logging.warn(
                        f"[{LOGGING_NAME}] Could not get the monitored file {response.status_code}: {response.reason}",
                        silence_period=LOGGING_DELTA,
                    )
                    continue

                # Load the data
                data = response.json()

                # Check if data changed
                if data == self._data:
                    continue

                # Update the list
                with self._lock:
                    self._data = data

                sv.logging.success(
                    f"[{LOGGING_NAME}] Monitored file proceed successfully",
                    silence_period=LOGGING_DELTA,
                )
        except Exception as err:
            sv.logging.error(
                f"[{LOGGING_NAME}] An error during monitoring: {err} {type(err)}",
            )
