from main import handle_packet, summary

from scapy.all import IP, TCP, UDP, ARP, Ether

# Fake TCP packet hitting port 80
fake_tcp = IP(src="10.0.0.5", dst="10.0.0.1") / TCP(sport=4444, dport=80)
handle_packet(fake_tcp)

# Fake ARP request
fake_arp = ARP(psrc="10.0.0.5", pdst="10.0.0.1", op=1)
handle_packet(fake_arp)

# Simulate port scan: same source IP, many destination ports
for port in range(1, 20):
    handle_packet(IP(src="10.0.0.99", dst="10.0.0.1") / TCP(sport=1234, dport=port))