import time
import copy
import requests
import threading
import bittensor as bt
from datetime import datetime
from typing import List

from subnet.country.country_constants import (
    COUNTRY_URL,
    LOGGING_NAME,
    COUNTRY_SLEEP,
)


class CountryService(threading.Thread):
    def __init__(self):
        super().__init__()
        self.stop_flag = threading.Event()
        self._lock = threading.Lock()
        self._countries = {}

        self.last_modified = None
        self.show_not_found = True
        self.first_try = True

        # Allow us to not display multiple time the same errors
        self.error_message = None

    def get_locations(self) -> List[str]:
        with self._lock:
            countries = self._countries or {}
            return copy.deepcopy(countries)

    def wait(self):
        """
        Wait until we have execute the run method at least one
        """
        attempt = 0
        while self.first_try or attempt > 5:
            time.sleep(1)
            attempt += 1

    def start(self):
        super().start()
        bt.logging.debug(f"Country started")

    def stop(self):
        self.stop_flag.set()
        super().join()
        bt.logging.debug(f"Country stopped")

    def run(self):
        while not self.stop_flag.is_set():
            response = None
            try:
                # Sleep before requesting again
                if not self.first_try:
                    time.sleep(COUNTRY_SLEEP)
                else:
                    self.first_try = True

                response = requests.get(COUNTRY_URL)
                if response.status_code != 200:
                    if response.status_code == 404 and not self.show_not_found:
                        continue

                    self.show_not_found = response.status_code != 404

                    error_message = f"[{LOGGING_NAME}] Could not get the country file {response.status_code}: {response.reason}"
                    if error_message != self.error_message:
                        bt.logging.warning(error_message)
                        self.error_message = error_message

                    continue

                # Load the data
                data = response.json() or {}

                # Check is date can be retrieved
                remote_last_modified = data.get("last-modified")
                if remote_last_modified is None:
                    continue

                # Check if data changed
                last_modified = datetime.strptime(
                    remote_last_modified, "%Y-%m-%d %H:%M:%S.%f"
                )
                if self.last_modified and last_modified <= self.last_modified:
                    continue

                self.last_modified = last_modified

                # Update the list
                with self._lock:
                    self._countries = data.get("countries")

                bt.logging.success(
                    f"[{LOGGING_NAME}] Country file proceed successfully",
                )
                self.error_message = None
            except Exception as err:
                content = response.content if response else ""
                error_message = f"[{LOGGING_NAME}] An error during country file processing: {err} {type(err)} {content}"
                if error_message != self.error_message:
                    bt.logging.error(error_message)
                    self.error_message = error_message
