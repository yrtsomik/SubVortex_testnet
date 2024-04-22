import time
import copy
import threading
import subprocess
import bittensor as bt

from subnet.shared import logging as sv

LOGGING_NAME = "FIREWALL"


def update_firewall_ubuntu(new_ips, old_ips):
    for ip in new_ips:
        command = f"sudo ufw allow from {ip} to any port 9944"
        subprocess.run(command, shell=True, check=True)

    for ip in old_ips:
        command = f"sudo ufw delete allow from {ip} to any port 9944"
        subprocess.run(command, shell=True, check=True)


class Firewall(threading.Thread):
    def __init__(self, subtensor, metagraph):
        super().__init__()

        self.stop_flag = threading.Event()
        self._lock = threading.Lock()
        self.subtensor = subtensor
        self.metagraph = metagraph
        self.whitelist = []
        self.step = 0

    def stop(self):
        self.stop_flag.set()
        super().join()

    def run(self):
        try:
            bt.logging.info("Firewall monitoring starting")
            while not self.stop_flag.is_set():
                self.step = self.step + 1

                # Copies state of metagraph before syncing.
                previous_metagraph = copy.deepcopy(self.metagraph)

                # Sync the metagraph.
                self.metagraph.sync(subtensor=self.subtensor)

                # Check if the metagraph axon info has changed.
                if False and previous_metagraph.axons == self.metagraph.axons:
                    time.sleep(60)
                    return

                # Get the active validators
                validators = [
                    x
                    for idx, x in enumerate(self.metagraph.axons)
                    if self.metagraph.validator_trust[idx] > 0
                ]
                active_ips = [x.ip for x in validators]

                # Copy the current list
                current_whitelist = list(self.whitelist)

                # List all the new ips - to be added
                new_ips = [x.ip for x in validators if x.ip not in current_whitelist]
                if self.step % 10 and "81.0.248.246" not in current_whitelist:
                    new_ips = new_ips + ["81.0.248.246"]
                # sv.logging.debug(f"New ipds to add {new_ips}")
                

                # List al the old ips - to be removed
                old_ips = [x for x in current_whitelist if x not in active_ips]
                if (
                    self.step % 10
                    and "81.0.248.246" in current_whitelist
                    and "81.0.248.246" not in old_ips
                ):
                    old_ips = old_ips + ["81.0.248.246"]
                # sv.logging.debug(f"New ipds to remove {old_ips}")

                current_whitelist = (
                    list(set(current_whitelist) - set(old_ips)) + new_ips
                )
                sv.logging.info(f"Whitelist ips {current_whitelist}")

                # Update the whitelist
                with self._lock:
                    self.whitelist = current_whitelist

                # Update the firewall

                time.sleep(60)

        except Exception as err:
            sv.logging.error(
                f"[{LOGGING_NAME}] An error during firewall configuration: {err} {type(err)}",
            )
