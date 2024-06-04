import time
import unittest
import subprocess
import bittensor as bt
from functools import partial
from scapy.all import IP, TCP, UDP, Packet
from unittest.mock import patch

from subnet.miner.firewall import Firewall, FirewallOptions


def is_sublist(sublist, main_list):
    sublist_len = len(sublist)
    main_list_len = len(main_list)

    for i in range(main_list_len - sublist_len + 1):
        if main_list[i : i + sublist_len] == sublist:
            return True
    return False


def mock_check_rule(mock_run, returncode, cmd):
    if is_sublist(["sudo", "iptables", "-C", "INPUT"], cmd):
        return subprocess.CompletedProcess(args=cmd, returncode=returncode)
    else:
        return mock_run


class TestFirewall(unittest.TestCase):
    def setUp(self):
        bt.logging.on()

    def tearDown(self):
        bt.logging.off()

    def assert_not_called_with(self, mock, *args, **kwargs):
        """
        Custom assertion to check that the mock was not called with the specified arguments.
        """
        if any(
            call == unittest.mock.call(*args, **kwargs) for call in mock.call_args_list
        ):
            raise AssertionError(
                f"Mock was called with arguments {args} and keyword arguments {kwargs}"
            )

    def assert_blocked(self, firewall, ip, port, process_run):
        block = next(
            (
                x
                for x in firewall.ips_blocked
                if x.get("ip") == ip and x.get("port") == port
            ),
            None,
        )
        assert block is not None
        assert process_run.call_count == 2
        assert process_run.call_args_list[0][0] == (
            [
                "sudo",
                "iptables",
                "-C",
                "INPUT",
                "-s",
                ip,
                "-p",
                "tcp",
                "--dport",
                str(port),
                "-j",
                "DROP",
            ],
        )
        assert process_run.call_args_list[1][0] == (
            [
                "sudo",
                "iptables",
                "-A",
                "INPUT",
                "-s",
                ip,
                "-p",
                "tcp",
                "--dport",
                str(port),
                "-j",
                "DROP",
            ],
        )

    def assert_unblocked(self, firewall, ip, port, process_run):
        block = next(
            (
                x
                for x in firewall.ips_blocked
                if x.get("ip") == ip and x.get("port") == port
            ),
            None,
        )
        assert block is None
        assert process_run.call_count == 2
        assert process_run.call_args_list[0][0] == (
            [
                "sudo",
                "iptables",
                "-C",
                "INPUT",
                "-s",
                ip,
                "-p",
                "tcp",
                "--dport",
                str(port),
                "-j",
                "DROP",
            ],
        )
        assert process_run.call_args_list[1][0] == (
            [
                "sudo",
                "iptables",
                "-D",
                "INPUT",
                "-s",
                ip,
                "-p",
                "tcp",
                "--dport",
                str(port),
                "-j",
                "DROP",
            ],
        )

    def set_time(self, mock_time, second=0):
        specific_time = time.struct_time((2024, 5, 28, 12, 0, second, 0, 0, -1))
        mock_time.return_value = time.mktime(specific_time)

    @patch("subprocess.run")
    @patch("time.time")
    def test_when_a_packet_with_no_ip_is_received_should_not_forward_the_packet(
        self, mock_time, mock_run
    ):
        # Arrange
        firewall = Firewall("eth0")
        packet = TCP()

        # Action
        self.set_time(mock_time)
        firewall.packet_callback(packet)

        # Assets
        assert 0 == len(firewall.ips_blocked)
        mock_run.assert_not_called()

    @patch("subprocess.run")
    @patch("time.time")
    def test_when_a_packet_not_tcp_is_received_should_not_forward_the_packet(
        self, mock_time, mock_run
    ):
        # Arrange
        firewall = Firewall("eth0")
        packet = UDP() / IP(src="192.168.0.1")

        # Action
        self.set_time(mock_time)
        firewall.packet_callback(packet)

        # Assets
        self.assert_blocked(firewall, "192.168.0.1", 53, mock_run)

    @patch("subprocess.run")
    @patch("time.time")
    def test_given_no_ports_configured_when_a_packet_is_received_should_not_forward_the_packet(
        self, mock_time, mock_run
    ):
        # Arrange
        firewall = Firewall("eth0")
        packet = TCP(dport=8091) / IP(src="192.168.0.1")

        # Action
        self.set_time(mock_time)
        firewall.packet_callback(packet)

        # Assets
        self.assert_blocked(firewall, "192.168.0.1", 8091, mock_run)

    @patch("subprocess.run")
    @patch("time.time")
    def test_given_a_port_forward_when_a_packet_on_that_port_is_received_should_forward_the_packet(
        self, mock_time, mock_run
    ):
        # Arrange
        rules = [{"port": 8091, "type": "allow"}]
        firewall = Firewall("eth0", rules=rules)
        packet = TCP(dport=8091) / IP(src="192.168.0.1")

        # Action
        self.set_time(mock_time)
        firewall.packet_callback(packet)

        # Assets
        assert 0 == len(firewall.ips_blocked)
        mock_run.assert_not_called()

    @patch("subprocess.run")
    @patch("time.time")
    def test_given_a_port_forward_when_a_packet_on_different_port_is_received_should_not_forward_the_packet(
        self, mock_time, mock_run
    ):
        # Arrange
        rules = [{"port": 8091, "type": "allow"}]
        firewall = Firewall("eth0", rules=rules)
        packet = TCP(dport=8092) / IP(src="192.168.0.1")

        # Action
        self.set_time(mock_time)
        firewall.packet_callback(packet)

        # Assets
        self.assert_blocked(firewall, "192.168.0.1", 8092, mock_run)

    @patch("subprocess.run")
    @patch("time.time")
    def test_given_a_port_sniff_when_a_packet_on_that_port_is_received_and_no_attacks_is_detected_should_forward_the_packet(
        self, mock_time, mock_run
    ):
        # Arrange
        rules = [
            {"port": 8091, "type": "allow"},
            {
                "port": 8091,
                "type": "detect-dos",
                "configuration": {
                    "dos_time_window": 30,
                    "dos_packet_threshold": 1,
                },
            },
        ]
        firewall = Firewall("eth0", rules=rules)
        packet = TCP(dport=8091) / IP(src="192.168.0.1")

        # Action
        self.set_time(mock_time)
        firewall.packet_callback(packet)

        # Assets
        assert 0 == len(firewall.ips_blocked)
        mock_run.assert_not_called()

    @patch("subprocess.run")
    @patch("time.time")
    def test_given_a_port_sniff_when_a_packet_on_that_port_is_received_and_dos_attack_is_detected_should_not_forward_the_packet(
        self, mock_time, mock_run
    ):
        # Arrange
        rules = [
            {"port": 8091, "type": "allow"},
            {
                "port": 8091,
                "type": "detect-dos",
                "configuration": {
                    "dos_time_window": 30,
                    "dos_packet_threshold": 1,
                },
            },
        ]
        firewall = Firewall("eth0", rules=rules)

        # Action
        packet: Packet = TCP(dport=8091) / IP(src="192.168.0.1")

        self.set_time(mock_time)
        firewall.packet_callback(packet)

        self.set_time(mock_time, 29)
        firewall.packet_callback(packet)

        # Assets
        self.assert_blocked(firewall, "192.168.0.1", 8091, mock_run)

    @patch("subprocess.run")
    @patch("time.time")
    def test_given_a_port_sniff_when_a_packet_on_that_port_is_received_and_dos_attack_is_not_detected_should_forward_the_packet(
        self, mock_time, mock_run
    ):
        # Arrange
        rules = [
            {"port": 8091, "type": "allow"},
            {
                "port": 8091,
                "type": "detect-dos",
                "configuration": {
                    "dos_time_window": 30,
                    "dos_packet_threshold": 1,
                },
            },
        ]
        firewall = Firewall("eth0", rules=rules)

        # Action
        packet: Packet = TCP(dport=8091) / IP(src="192.168.0.1")

        self.set_time(mock_time)
        firewall.packet_callback(packet)

        self.set_time(mock_time, 30)
        firewall.packet_callback(packet)

        # Assets
        assert 0 == len(firewall.ips_blocked)
        mock_run.assert_not_called()

    @patch("subprocess.run")
    @patch("time.time")
    def test_given_a_port_sniff_when_a_packet_on_that_port_is_received_and_ddos_attack_is_detected_should_not_forward_the_packet(
        self, mock_time, mock_run
    ):
        # Arrange
        rules = [
            {"port": 8091, "type": "allow"},
            {
                "port": 8091,
                "type": "detect-ddos",
                "configuration": {
                    "ddos_time_window": 30,
                    "ddos_packet_threshold": 1,
                },
            },
        ]
        firewall = Firewall("eth0", rules=rules)

        # Action
        packet: Packet = TCP(dport=8091) / IP(src="192.168.0.1")

        self.set_time(mock_time)
        firewall.packet_callback(packet)

        self.set_time(mock_time, 29)
        firewall.packet_callback(packet)

        # Assets
        self.assert_blocked(firewall, "192.168.0.1", 8091, mock_run)

    @patch("subprocess.run")
    @patch("time.time")
    def test_given_a_port_sniff_when_a_packet_on_that_port_is_received_and_ddos_attack_is_not_detected_should_forward_the_packet(
        self, mock_time, mock_run
    ):
        # Arrange
        rules = [
            {"port": 8091, "type": "allow"},
            {
                "port": 8091,
                "type": "detect-ddos",
                "configuration": {
                    "ddos_time_window": 30,
                    "ddos_packet_threshold": 1,
                },
            },
        ]
        firewall = Firewall("eth0", rules=rules)

        # Action
        packet: Packet = TCP(dport=8091) / IP(src="192.168.0.1")

        self.set_time(mock_time)
        firewall.packet_callback(packet)

        self.set_time(mock_time, 30)
        firewall.packet_callback(packet)

        # Assets
        assert 0 == len(firewall.ips_blocked)
        mock_run.assert_not_called()

    @patch("subprocess.run")
    @patch("time.time")
    def test_given_a_blocked_ip_when_a_packet_from_that_ip_is_received_should_not_forward_the_packet(
        self, mock_time, mock_run
    ):
        # Arrange
        rules = [
            {
                "ip": "192.168.0.1",
                "type": "deny",
            }
        ]
        firewall = Firewall("eth0", rules=rules)

        # Action
        packet: Packet = TCP(dport=8091) / IP(src="192.168.0.1")

        self.set_time(mock_time)
        firewall.packet_callback(packet)

        # Assets
        self.assert_blocked(firewall, "192.168.0.1", 8091, mock_run)

    @patch("subprocess.run")
    @patch("time.time")
    def test_given_a_blocked_ip_when_a_packet_from_a_different_ip_is_received_should_not_forward_the_packet(
        self, mock_time, mock_run
    ):
        # Arrange
        rules = [
            {
                "ip": "192.168.0.1",
                "type": "deny",
            }
        ]
        firewall = Firewall("eth0", rules=rules)

        # Action
        packet: Packet = TCP(dport=8091) / IP(src="192.168.0.2")

        self.set_time(mock_time)
        firewall.packet_callback(packet)

        # Assets
        self.assert_blocked(firewall, "192.168.0.2", 8091, mock_run)

    @patch("subprocess.run")
    @patch("time.time")
    def test_given_a_blocked_ip_and_a_port_forward_when_a_packet_from_a_different_ip_is_received_should_forward_the_packet(
        self, mock_time, mock_run
    ):
        # Arrange
        rules = [
            {
                "ip": "192.168.0.1",
                "type": "deny",
            },
            {
                "port": 8091,
                "type": "allow",
            },
        ]
        firewall = Firewall("eth0", rules=rules)

        # Action
        packet: Packet = TCP(dport=8091) / IP(src="192.168.0.2")

        self.set_time(mock_time)
        firewall.packet_callback(packet)

        # Assets
        assert 0 == len(firewall.ips_blocked)
        mock_run.assert_not_called()

    @patch("subprocess.run")
    @patch("time.time")
    def test_a_pcket_is_blocked_and_then_blocked_again(self, mock_time, mock_run):
        # Arrange
        rules = [
            {"port": 8091, "type": "allow"},
            {
                "port": 8091,
                "type": "detect-dos",
                "configuration": {
                    "dos_time_window": 30,
                    "dos_packet_threshold": 1,
                },
            },
        ]
        firewall = Firewall("eth0", rules=rules)

        packet: Packet = TCP(dport=8091) / IP(src="192.168.0.1")

        # Action
        self.set_time(mock_time)
        firewall.packet_callback(packet)

        self.set_time(mock_time, 29)
        firewall.packet_callback(packet)

        # Assets
        self.assert_blocked(firewall, "192.168.0.1", 8091, mock_run)

        # Arrange
        mock_run.reset_mock()

        # Action
        self.set_time(mock_time, 58)
        firewall.packet_callback(packet)

        # Assets
        assert 1 == len(firewall.ips_blocked)
        mock_run.assert_not_called()

    @patch("subprocess.run")
    @patch("time.time")
    def test_a_packet_is_blocked_and_then_unblocked(self, mock_time, mock_run):
        # Arrange
        rules = [
            {"port": 8091, "type": "allow"},
            {
                "port": 8091,
                "type": "detect-dos",
                "configuration": {
                    "dos_time_window": 30,
                    "dos_packet_threshold": 1,
                },
            },
        ]
        firewall = Firewall("eth0", rules=rules)

        packet: Packet = TCP(dport=8091) / IP(src="192.168.0.1")

        # Action
        self.set_time(mock_time)
        firewall.packet_callback(packet)

        self.set_time(mock_time, 29)
        firewall.packet_callback(packet)

        # Assets
        self.assert_blocked(firewall, "192.168.0.1", 8091, mock_run)

        # Arrange
        mock_run.reset_mock()
        mock_run.side_effect = partial(mock_check_rule, mock_run, 0)

        # Action
        self.set_time(mock_time, 60)
        firewall.packet_callback(packet)

        # Assets
        self.assert_unblocked(firewall, "192.168.0.1", 8091, mock_run)
