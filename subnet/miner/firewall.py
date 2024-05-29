import time
import threading
import bittensor as bt
from typing import List
from collections import defaultdict
from dataclasses import dataclass
from scapy.all import sniff, TCP, IP, Packet, send


@dataclass
class FirewallOptions:
    ddos_time_window: int = 30
    """
    Time window, in seconds, used to detect DDoS attacks.
    """

    ddos_packet_threshold: int = 100
    """
    Maximum number of packets allowed from a single IP within the DDoS time window.
    """

    rate_limit_time_window: int = 5
    """
    Time window, in seconds, used to monitor for rate limit violations.
    """

    rate_limit_packet_threshold: int = 20
    """
    Maximum number of packets allowed from a single IP within the rate limit time window.
    """


class Firewall(threading.Thread):
    def __init__(
        self,
        interface: str,
        ports_to_sniff: List[int] = [],
        ports_to_forward: List[int] = [],
        options: dict[FirewallOptions] = None,
    ):
        super().__init__()

        self.stop_flag = threading.Event()
        self.packet_counts = defaultdict(list)
        self.packet_rate = defaultdict(list)

        self.ports_to_sniff = ports_to_sniff
        self.ports_to_forward = list(set(ports_to_forward + ports_to_sniff))
        self.interface = interface

        self.options = options or {p: FirewallOptions() for p in ports_to_sniff}

    def start(self):
        super().start()
        bt.logging.debug(f"Firewall started")

    def stop(self):
        self.stop_flag.set()
        super().join()
        bt.logging.debug(f"Firewall stopped")

    def detect_attacks(self, option: FirewallOptions):
        attacks_detected = []

        # Get the current time
        current_time = time.time()

        # Detect Ddos attacks
        for ip, timestamps in self.packet_counts.items():
            recent_timestamps = [
                t for t in timestamps if current_time - t < option.ddos_time_window
            ]
            self.packet_counts[ip] = recent_timestamps
            if len(recent_timestamps) > option.ddos_packet_threshold:
                # Add the attack
                attacks_detected.append((ip, "DDoS", len(recent_timestamps)))

                # Reset counter
                self.packet_counts[ip] = []

        # Detect rate limit violations
        for ip, timestamps in self.packet_rate.items():
            recent_timestamps = [
                t for t in timestamps if current_time - t < option.rate_limit_time_window
            ]
            self.packet_rate[ip] = recent_timestamps
            if len(recent_timestamps) > option.rate_limit_packet_threshold:
                # Add the attack
                attacks_detected.append(
                    (ip, "Rate limit violation", len(recent_timestamps))
                )

                # Reset counter
                self.packet_rate[ip] = []

        return attacks_detected

    def packet_callback(self, packet: Packet):
        if TCP not in packet:
            # Drop the packet
            return

        if IP not in packet:
            # Drop the packet
            return

        if packet[TCP].dport not in self.ports_to_forward:
            # Drop the packet
            return

        if packet[TCP].dport not in self.ports_to_sniff:
            # Port to forward but not to sniff
            send(packet)
            return

        # Get the source ip of the packet
        ip_src = packet[IP].src
        port_dest = packet[TCP].dport

        # Increment the number of packet for the ip
        self.packet_counts[ip_src].append(time.time())

        # Add the time of reception of the packet
        self.packet_rate[ip_src].append(time.time())

        # Detect attacks
        option = self.options.get(port_dest) or FirewallOptions()
        attacks = self.detect_attacks(option)

        # Check if there are any attacks
        if any(ip_src == attack[0] for attack in attacks):
            # Drop the packet
            bt.logging.debug(f"Attack detected: {attacks}")
            return
        else:
            # Forward the packet
            send(packet)

    def run(self):
        # Start sniffing with the filter
        sniff(iface=self.interface, prn=self.packet_callback)
