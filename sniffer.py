from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, DNSRR

def packet_callback(packet):
    if not packet.haslayer(IP):
        return

    ip_layer = packet[IP]
    print(f"\n===== Packet Captured @ {datetime.now()} =====")
    print(f"Source IP: {ip_layer.src}")
    print(f"Destination IP: {ip_layer.dst}")

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        print("Protocol: TCP")
        print(f"Source Port: {tcp.sport}, Destination Port: {tcp.dport}")

    if packet.haslayer(UDP):
        udp = packet[UDP]
        print("Protocol: UDP")
        print(f"Source Port: {udp.sport}, Destination Port: {udp.dport}")

    if packet.haslayer(DNS):
        dns = packet[DNS]

        if dns.qr == 0 and dns.qd is not None:
            print(f"DNS Query: {dns.qd.qname.decode()}")

        if dns.qr == 1 and dns.an is not None:
            print(f"DNS Response: {dns.an.rrname.decode()} -> {dns.an.rdata}")

    if packet.haslayer(IP) and not (
        packet.haslayer(TCP) or 
        packet.haslayer(UDP) or 
        packet.haslayer(DNS)
    ):
        print(f"Protocol: Unknown ({packet[IP].proto})")


def start_sniffer():
    print("Starting network sniffer... (press Ctrl+C to stop)")
    sniff(prn=packet_callback, store=False)


if __name__ == "__main__":
    start_sniffer()
