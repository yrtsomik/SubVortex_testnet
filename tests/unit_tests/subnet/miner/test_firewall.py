import time
import unittest
import bittensor as bt
from scapy.all import IP, TCP, UDP, Packet
from unittest.mock import patch

from subnet.miner.firewall import Firewall, FirewallOptions


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

    def set_time(self, mock_time, second=0):
        specific_time = time.struct_time((2024, 5, 28, 12, 0, second, 0, 0, -1))
        mock_time.return_value = time.mktime(specific_time)

    @patch("time.time")
    @patch("subnet.miner.firewall.bt.logging.debug")
    @patch("scapy.all.send")
    def test_when_a_packet_with_no_ip_is_received_should_not_forward_the_packet(
        self, mock_send, mock_debug, mock_time
    ):
        # Arrange
        firewall = Firewall("eth0")
        packet = TCP()

        # Action
        self.set_time(mock_time)
        firewall.packet_callback(packet)

        # Assets
        mock_send.assert_not_called()
        mock_debug.assert_not_called()

    @patch("time.time")
    @patch("subnet.miner.firewall.bt.logging.debug")
    @patch("scapy.all.send")
    def test_when_a_packet_not_tcp_is_received_should_not_forward_the_packet(
        self, mock_send, mock_debug, mock_time
    ):
        # Arrange
        firewall = Firewall("eth0")
        packet = UDP() / IP(src="192.168.0.1")

        # Action
        self.set_time(mock_time)
        firewall.packet_callback(packet)

        # Assets
        mock_send.assert_not_called()
        mock_debug.assert_not_called()

    @patch("time.time")
    @patch("subnet.miner.firewall.bt.logging.debug")
    @patch("scapy.all.send")
    def test_given_no_ports_configured_when_a_packet_is_received_should_not_forward_the_packet(
        self, mock_send, mock_debug, mock_time
    ):
        # Arrange
        firewall = Firewall("eth0")
        packet = TCP() / IP(src="192.168.0.1")

        # Action
        self.set_time(mock_time)
        firewall.packet_callback(packet)

        # Assets
        mock_send.assert_not_called()
        mock_debug.assert_not_called()

    @patch("time.time")
    @patch("subnet.miner.firewall.bt.logging.debug")
    @patch("subnet.miner.firewall.send")
    def test_given_a_port_forward_when_a_packet_on_that_port_is_received_should_forward_the_packet(
        self, mock_send, mock_debug, mock_time
    ):
        # Arrange
        firewall = Firewall("eth0", ports_to_forward=[8091])
        packet = TCP(dport=8091) / IP(src="192.168.0.1")

        # Action
        self.set_time(mock_time)
        firewall.packet_callback(packet)

        # Assets
        mock_send.assert_called_once_with(packet)
        mock_debug.assert_not_called()

    @patch("time.time")
    @patch("subnet.miner.firewall.bt.logging.debug")
    @patch("subnet.miner.firewall.send")
    def test_given_a_port_forward_when_a_packet_on_different_port_is_received_should_not_forward_the_packet(
        self, mock_send, mock_debug, mock_time
    ):
        # Arrange
        firewall = Firewall("eth0", ports_to_forward=[8091])
        packet = TCP(dport=8092) / IP(src="192.168.0.1")

        # Action
        self.set_time(mock_time)
        firewall.packet_callback(packet)

        # Assets
        mock_send.assert_not_called()
        mock_debug.assert_not_called()

    @patch("time.time")
    @patch("subnet.miner.firewall.bt.logging.debug")
    @patch("subnet.miner.firewall.send")
    def test_given_a_port_sniff_when_a_packet_on_that_port_is_received_and_no_attacks_is_detected_should_forward_the_packet(
        self, mock_send, mock_debug, mock_time
    ):
        # Arrange
        firewall = Firewall("eth0", ports_to_sniff=[8091])
        packet = TCP(dport=8091) / IP(src="192.168.0.1")

        # Action
        self.set_time(mock_time)
        firewall.packet_callback(packet)

        # Assets
        mock_send.assert_called_once_with(packet)
        mock_debug.assert_not_called()

    @patch("time.time")
    @patch("subnet.miner.firewall.bt.logging.debug")
    @patch("subnet.miner.firewall.send")
    def test_given_a_port_sniff_when_a_packet_on_that_port_is_received_and_ddos_attack_is_detected_should_not_forward_the_packet(
        self, mock_send, mock_debug, mock_time
    ):
        # Arrange
        options = FirewallOptions(ddos_packet_threshold=1)
        firewall = Firewall("eth0", ports_to_sniff=[8091], options={8091: options})

        # Action
        packet: Packet = TCP(dport=8091) / IP(src="192.168.0.1")
        
        self.set_time(mock_time)
        firewall.packet_callback(packet)

        self.set_time(mock_time, options.ddos_time_window - 1)
        firewall.packet_callback(packet)

        # Assets
        mock_send.assert_called_once_with(packet)
        mock_debug.assert_called_once_with("Attack detected: [('192.168.0.1', 'DDoS', 2)]")
        assert 0 == len(firewall.packet_counts["192.168.0.1"])

    @patch("time.time")
    @patch("subnet.miner.firewall.bt.logging.debug")
    @patch("subnet.miner.firewall.send")
    def test_given_a_port_sniff_when_a_packet_on_that_port_is_received_and_ddos_attack_is_not_detected_should_not_forward_the_packet(
        self, mock_send, mock_debug, mock_time
    ):
        # Arrange
        options = FirewallOptions(ddos_packet_threshold=1)
        firewall = Firewall("eth0", ports_to_sniff=[8091], options={8091: options})

        # Action
        packet: Packet = TCP(dport=8091) / IP(src="192.168.0.1")
        
        self.set_time(mock_time)
        firewall.packet_callback(packet)

        self.set_time(mock_time, options.ddos_time_window)
        firewall.packet_callback(packet)

        # Assets
        self.assertEqual(mock_send.call_count, 2)
        mock_send.assert_called_with(packet)
        mock_debug.assert_not_called()
        assert 1 == len(firewall.packet_counts["192.168.0.1"])

    @patch("time.time")
    @patch("subnet.miner.firewall.bt.logging.debug")
    @patch("subnet.miner.firewall.send")
    def test_given_a_port_sniff_when_a_packet_on_that_port_is_received_and_rate_limit_attack_is_detected_should_not_forward_the_packet(
        self, mock_send, mock_debug, mock_time
    ):
        # Arrange
        options = FirewallOptions(rate_limit_time_window=5, rate_limit_packet_threshold=1)
        firewall = Firewall("eth0", ports_to_sniff=[8091], options={8091: options})

        # Action
        packet: Packet = TCP(dport=8091) / IP(src="192.168.0.1")

        self.set_time(mock_time)
        firewall.packet_callback(packet)

        self.set_time(mock_time, options.rate_limit_time_window - 1)
        firewall.packet_callback(packet)

        # Assets
        mock_send.assert_called_once_with(packet)
        mock_debug.assert_called_once_with(
            "Attack detected: [('192.168.0.1', 'Rate limit violation', 2)]"
        )
        assert 0 == len(firewall.packet_rate["192.168.0.1"])

    @patch("time.time")
    @patch("subnet.miner.firewall.bt.logging.debug")
    @patch("subnet.miner.firewall.send")
    def test_given_a_port_sniff_when_a_packet_on_that_port_is_received_and_rate_limit_attack_is_not_detected_should_orward_the_packet(
        self, mock_send, mock_debug, mock_time
    ):
        # Arrange
        options = FirewallOptions(rate_limit_time_window=5, rate_limit_packet_threshold=1)
        firewall = Firewall("eth0", ports_to_sniff=[8091], options={8091: options})

        # Action
        packet: Packet = TCP(dport=8091) / IP(src="192.168.0.1")

        self.set_time(mock_time)
        firewall.packet_callback(packet)

        self.set_time(mock_time, options.rate_limit_time_window)
        firewall.packet_callback(packet)

        # Assets
        self.assertEqual(mock_send.call_count, 2)
        mock_send.assert_called_with(packet)
        mock_debug.assert_not_called()
        assert 1 == len(firewall.packet_rate["192.168.0.1"])
