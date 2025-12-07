import unittest
from io import StringIO
import sys
import scapy.all as scapy
from sniffer import packet_callback


class TestPacketCallback(unittest.TestCase):

    def capture_output(self, packet):
        captured = StringIO()
        sys.stdout = captured
        packet_callback(packet)
        sys.stdout = sys.__stdout__
        return captured.getvalue()

    def test_ip_packet(self):
        packet = scapy.IP(src='192.168.1.1', dst='8.8.8.8')
        output = self.capture_output(packet)
        self.assertIn("Source IP: 192.168.1.1", output)
        self.assertIn("Destination IP: 8.8.8.8", output)

    def test_tcp_layer(self):
        packet = scapy.IP(src='1.1.1.1', dst='8.8.8.8') / scapy.TCP(sport=1234, dport=80)
        output = self.capture_output(packet)
        self.assertIn("Protocol: TCP", output)
        self.assertIn("Source Port: 1234", output)

    def test_udp_layer(self):
        packet = scapy.IP(src='1.1.1.1', dst='8.8.8.8') / scapy.UDP(sport=5000, dport=53)
        output = self.capture_output(packet)
        self.assertIn("Protocol: UDP", output)

    def test_dns_query(self):
        packet = scapy.IP(src="1.1.1.1", dst="8.8.8.8") / scapy.UDP(sport=5000, dport=53) / \
                 scapy.DNS(rd=1, qd=scapy.DNSQR(qname="example.com"))
        output = self.capture_output(packet)
        self.assertIn("DNS Query: example.com", output)

    def test_dns_response(self):
        packet = scapy.IP(src="1.1.1.1", dst="8.8.8.8") / scapy.UDP() / \
                 scapy.DNS(qr=1, an=scapy.DNSRR(rrname="example.com", rdata="1.2.3.4"))
        output = self.capture_output(packet)
        self.assertIn("DNS Response: example.com -> 1.2.3.4", output)

    def test_packet_without_ip(self):
        packet = scapy.TCP(sport=1234, dport=80)
        output = self.capture_output(packet)
        self.assertEqual(output, "")


if __name__ == "__main__":
    unittest.main()
