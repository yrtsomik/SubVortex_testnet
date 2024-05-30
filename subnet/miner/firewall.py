import os
import json
import time
import logging
import threading
import bittensor as bt
from typing import List
from collections import defaultdict
from dataclasses import dataclass
from scapy.all import sniff, TCP, IP, Raw, Packet, send

# Disalbe scapy logging
logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)


@dataclass
class FirewallOptions:

    def __init__(self, dictionary):
        for key, value in dictionary.items():
            if isinstance(value, dict):
                value = FirewallOptions(value)
            self.__dict__[key] = value

    ddos_time_window: int = 30
    """
    Time window, in seconds, used to detect DDoS attacks.
    """

    ddos_packet_threshold: int = 100
    """
    Maximum number of packets allowed from a single IP within the DDoS time window.
    """

    dos_time_window: int = 5

    dos_packet_threshold: int = 20


class Firewall(threading.Thread):

    def __init__(
        self,
        interface: str,
        rules: dict[FirewallOptions] = [],
    ):
        super().__init__(daemon=True)

        self.stop_flag = threading.Event()
        self.packet_counts = defaultdict(lambda: defaultdict(int))
        self.packet_timestamps = defaultdict(lambda: defaultdict(list))

        self.interface = interface
        self.ips_blocked = []

        self.rules = rules

    def start(self):
        super().start()
        bt.logging.debug(f"Firewall started")

    def stop(self):
        self.stop_flag.set()
        super().join()
        bt.logging.debug(f"Firewall stopped")

    def block_ip(self, ip, port, reason):
        ip_blocked = next(
            (x for x in self.ips_blocked if x["ip"] == ip and x["port"] == port), None
        )
        if not ip_blocked:
            ip_blocked = {"ip": ip, "port": port, "reason": reason}
            self.ips_blocked.append(ip_blocked)

        with open("ips_blocked.txt", "a") as file:
            file.write(json.dumps(ip_blocked) + "\n")

    def unblock_ip(self, ip, port):
        ips_blocked = [
            x for x in self.ips_blocked if x["ip"] != ip or x["port"] != port
        ]

        with open("ips_blocked.txt", "w") as file:
            file.write(json.dumps(ips_blocked))

    def detect_dos(self, ip, port, option: FirewallOptions):
        """
        Detect Denial of Service attack which is an attack from a single source that overwhelms a target with requests,
        """
        current_time = time.time()

        self.packet_counts[ip][port] += 1
        self.packet_timestamps[ip][port].append(current_time)

        recent_packets = [
            t
            for t in self.packet_timestamps[ip][port]
            if current_time - t < option.dos_time_window
        ]
        self.packet_timestamps[ip][port] = recent_packets

        if len(recent_packets) > option.dos_packet_threshold:
            if False:
                bt.logging.warning(f"DoS attack detected from IP {ip} on port {port}")
            self.block_ip(
                ip,
                port,
                f"DoS attack detected: {len(recent_packets)} packets in {option.dos_time_window} seconds",
            )
            return True

        return False

    def detect_ddos(self, ip, port, option: FirewallOptions):
        """
        Detect Distributed Denial of Service which is an attack from multiple sources that overwhelms a target with requests,
        """
        current_time = time.time()

        self.packet_timestamps[ip][port].append(current_time)

        all_timestamps = [t for ts in self.packet_timestamps.values() for t in ts[port]]
        recent_timestamps = [
            t for t in all_timestamps if current_time - t < option.ddos_time_window
        ]

        if len(recent_timestamps) > option.ddos_packet_threshold:
            if False:
                bt.logging.warning(f"DDoS attack detected on port {port}")
            self.block_ip(
                ip,
                port,
                f"DDoS attack detected: {len(recent_timestamps)} packets in {option.ddos_time_window} seconds",
            )
            return True

        return False

    def detect_specific_body(self, packet, port, config):
        if Raw not in packet:
            return False

        if config.specific_body_content and Raw in packet:
            if config.specific_body_content in packet[Raw].load:
                ip_src = packet[IP].src
                if False:
                    bt.logging.warning(
                        f"Specific content detected in packet from IP {ip_src} on port {port}"
                    )
                self.block_ip(
                    ip_src,
                    port,
                    f"Specific content detected in packet: {config.specific_body_content}",
                )
                return True

        return False

    def get_rule(self, rules, type, ip, port):
        filtered_rules = [r for r in rules if r.get("type") == type]
        rule = next(
            (r for r in filtered_rules if r.get("ip") == ip and r.get("port") == port),
            None,
        )
        rule = rule or next(
            (r for r in filtered_rules if ip is not None and r.get("ip") == ip), None
        )
        rule = rule or next(
            (r for r in filtered_rules if port is not None and r.get("port") == port),
            None,
        )
        return rule

    def packet_callback(self, packet):
        if TCP not in packet:
            return

        if IP not in packet:
            return

        ip_src = packet[IP].src
        port_dest = packet[TCP].dport

        # Get all rules related to the ip/port
        rules = [
            r for r in self.rules if r.get("ip") == ip_src or r.get("port") == port_dest
        ]

        # Check if a forward rule exists
        rule = self.get_rule(rules=rules, type="forward", ip=ip_src, port=port_dest)

        block_packet = rule is None

        # Check if a block rule exists
        rule = self.get_rule(rules=rules, type="block", ip=ip_src, port=port_dest)
        if rule:
            if ip_src == "158.220.82.181":
                bt.logging.warning(f"IP {ip_src} has been blocked")
            self.block_ip(ip_src, port_dest, f"Block ip {ip_src}")
            return

        # Check if a DoS rule exist
        rule = self.get_rule(rules=rules, type="detect-dos", ip=ip_src, port=port_dest)
        block_packet |= rule is not None and self.detect_dos(
            ip_src, port_dest, FirewallOptions(rule.get("configuration"))
        )

        # Check if a DDoS rule exist
        rule = self.get_rule(rules=rules, type="detect-ddos", ip=ip_src, port=port_dest)
        block_packet |= rule is not None and self.detect_ddos(
            ip_src, port_dest, FirewallOptions(rule.get("configuration"))
        )

        # Check is body rule exist
        # attacks_detected |= self.detect_specific_body(packet, port_dest, options)

        if block_packet:
            self.block_ip(ip_src, port_dest, f"Block ip {ip_src}")
            return

        # Unblock the ip/port
        self.unblock_ip(ip_src, port_dest)

        if ip_src == "158.220.82.181":
            bt.logging.warning(f"IP {ip_src} has been forwarded")

        # Forward the packet to its target
        send(packet, verbose=False)

    def run(self):
        # Reload the previous ips blocked
        if os.path.exists("ips_blocked.json"):
            with open("ips_blocked.json", "r") as file:
                self.ips_blocked = json.load(file) or []
        bt.logging.debug(f"Loaded {len(self.ips_blocked)} blocked ip")

        # Start sniffing with the filter
        sniff(iface=self.interface, prn=self.packet_callback)
