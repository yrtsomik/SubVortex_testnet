import os
import json
import time
import logging
import threading
import bittensor as bt
from collections import defaultdict
from dataclasses import dataclass
from scapy.all import sniff, TCP, UDP, IP, Raw, Packet

from subnet.miner.iptables import (
    deny_traffic_from_ip,
    deny_traffic_on_port,
    deny_traffic_from_ip_and_port,
    allow_traffic_from_ip,
    allow_traffic_on_port,
    allow_traffic_from_ip_and_port,
    remove_deny_traffic_from_ip_and_port,
)

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

    def block_ip(self, ip, port, protocol, reason):
        ip_blocked = next(
            (x for x in self.ips_blocked if x["ip"] == ip and x["port"] == port and x["protocol"] == protocol), None
        )
        if ip_blocked:
            return

        # Update the ip tables
        deny_traffic_from_ip_and_port(ip, port, protocol)

        # Update the block ips
        ip_blocked = {"ip": ip, "port": port, "protocol": protocol, "reason": reason}
        self.ips_blocked.append(ip_blocked)

        # Update the local file
        with open("ips_blocked.json", "w") as file:
            file.write(json.dumps(ip_blocked))

        bt.logging.warning(f"Blocking {protocol.upper()} {ip}/{port}: {reason}")

    def unblock_ip(self, ip, port, protocol):
        ip_blocked = next(
            (x for x in self.ips_blocked if x["ip"] == ip and x["port"] == port and x['protocol'] == protocol), None
        )
        if not ip_blocked:
            return

        # Update the ip tables
        remove_deny_traffic_from_ip_and_port(ip, port, protocol)

        # Update the block ips
        self.ips_blocked = [
            x for x in self.ips_blocked if x["ip"] != ip or x["port"] != port or x["protocol"] != protocol
        ]

        # Update the local file
        with open("ips_blocked.json", "w") as file:
            file.write(json.dumps(self.ips_blocked))

        bt.logging.warning(f"Unblocking {protocol.upper()} {ip}/{port}")


    def detect_dos(self, ip, port, protocol, option: FirewallOptions):
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
            self.block_ip(
                ip,
                port,
                protocol,
                f"DoS attack detected: {len(recent_packets)} packets in {option.dos_time_window} seconds",
            )
            return True

        return False

    def detect_ddos(self, ip, port, protocol, option: FirewallOptions):
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
            self.block_ip(
                ip,
                port,
                protocol,
                f"DDoS attack detected: {len(recent_timestamps)} packets in {option.ddos_time_window} seconds",
            )
            return True

        return False

    def get_rule(self, rules, type, ip, port, protocol):
        filtered_rules = [r for r in rules if r.get("type") == type]

        # Ip/Port rule
        rule = next(
            (r for r in filtered_rules if r.get("ip") == ip and r.get("port") == port and r.get("protocol") == protocol),
            None,
        )

        # Ip rule
        rule = rule or next(
            (r for r in filtered_rules if ip is not None and r.get("ip") == ip), None
        )

        # Port rule
        rule = rule or next(
            (r for r in filtered_rules if port is not None and r.get("port") == port and r.get("protocol") == protocol),
            None,
        )

        return rule

    def packet_callback(self, packet: Packet):
        ip_src = packet[IP].src if IP in packet else None
        protocol = "tcp" if TCP in packet else "udp" if UDP in packet else None
        port_dest = (
            packet[TCP].dport
            if TCP in packet
            else packet[UDP].dport if UDP in packet else None
        )

        if ip_src is None:
            return

        # Get all rules related to the ip/port
        rules = [
            r for r in self.rules if r.get("ip") == ip_src or r.get("port") == port_dest
        ]

        # Check if a forward rule exists
        # rule = self.get_rule(rules=rules, type="allow", ip=ip_src, port=port_dest, protocol=protocol)

        # block_packet = rule is None
        block_packet = False

        # # Check if a block rule exists
        # rule = self.get_rule(rules=rules, type="deny", ip=ip_src, port=port_dest, protocol=protocol)
        # if rule:
        #     self.block_ip(ip_src, port_dest, protocol, f"Block ip {ip_src}")
        #     return

        # Check if a DoS rule exist
        rule = self.get_rule(rules=rules, type="detect-dos", ip=ip_src, port=port_dest, protocol=protocol)
        block_packet |= rule is not None and self.detect_dos(
            ip_src, port_dest, protocol, FirewallOptions(rule.get("configuration"))
        )

        # Check if a DDoS rule exist
        rule = self.get_rule(rules=rules, type="detect-ddos", ip=ip_src, port=port_dest, protocol=protocol)
        block_packet |= rule is not None and self.detect_ddos(
            ip_src, port_dest, protocol, FirewallOptions(rule.get("configuration"))
        )

        if block_packet:
            self.block_ip(ip_src, port_dest, protocol, f"Block ip {ip_src}")
            return

        # Unblock the ip/port
        self.unblock_ip(ip_src, port_dest, protocol)

    def run(self):
        # Reload the previous ips blocked
        bt.logging.debug("Loading blocked ips")
        if os.path.exists("ips_blocked.json"):
            with open("ips_blocked.json", "r") as file:
                self.ips_blocked = json.load(file) or []

        bt.logging.debug(f"Applying allow/deny rules")
        for rule in self.rules:
            if rule.get("type") not in ["allow", "deny"]:
                continue

            ip = rule.get("ip")
            port = rule.get("port")
            protocol = rule.get("protocol")
            type = rule.get("type")

            if type == "allow":
                if ip and port:
                    allow_traffic_from_ip_and_port(ip, port, protocol)
                elif ip:
                    allow_traffic_from_ip(ip)
                elif port:
                    allow_traffic_on_port(port, protocol)
            else:
                if ip and port:
                    deny_traffic_from_ip_and_port(ip, port, protocol)
                elif ip:
                    deny_traffic_from_ip(ip)
                elif port:
                    deny_traffic_on_port(port, protocol)

        # Start sniffing with the filter
        sniff(
            iface=self.interface,
            prn=self.packet_callback,
            store=False,
            stop_filter=self.stop_flag.set(),
        )
