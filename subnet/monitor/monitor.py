import csv
import requests
import threading
from typing import List
from io import StringIO

from subnet.shared import logging as sv
from subnet.monitor.monitor_constants import MONITOR_URL, LOGGING_NAME, LOGGING_DELTA


class Monitor:
    def __init__(self):
        super().__init__()
        self._lock = threading.Lock()
        self._list = []

        self.last_modified = None

    def get_monitored_uids(self) -> List[int]:
        with self._lock:
            return list(self._list)

    def run(self):
        response = requests.get(MONITOR_URL)
        if response.status_code != 200:
            sv.logging.warn(
                f"[{LOGGING_NAME}] Could not get the monitored file {response.status_code}: {response.reason}",
                silence_period=LOGGING_DELTA,
            )
            return

        last_modified = response.headers.get("Last-Modified")
        if self.last_modified == last_modified:
            return

        # Store tag for future comparaison
        self.last_modified = last_modified

        # Create a CSV reader object
        reader = csv.reader(StringIO(response.text))

        # Read and process each row
        miners = []
        for row in reader:
            miners.append(int(row[0]))

        # Update the list
        with self._lock:
            self._list = list(miners)

        sv.logging.success(
            f"[{LOGGING_NAME}] Monitored file proceed successfully",
            silence_period=LOGGING_DELTA,
        )
