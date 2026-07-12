########################################
# INDEPENDANT NETWORK TRAFFIC ANALYZER 
# GOALS: 
#       - Implement OSI layer knowledge to analyze packets
#           travelling accross my home network.
#       - Gain a better understanding of Network protocols
#       - Identify suspicious activity
#
# METHODOLOGY:
#       - Learn Scapy using combination of Claude Sonnet 5
#           and Scapy documentation
#       - Make use of Sonnet 5 for debugging and topic clarification
#       - Avoid vibe coding by restricting prompts to descriptive 
#           assistance only
#       - Verify results using Wireshark
########################################


import argparse
import sys
from collections import Counter, defaultdict
from datetime import datetime

from scapy.all import sniff, wrpcap, IP, UDP, TCP, ARP

captured_packets = []
protocol_count = Counter()
talkers = Counter()
port_scan_tracker = defaultdict(set)
startTime = datetime.now()



def handle_packet(packet):
    # Handle ARP packets
    if packet.haslayer(ARP):
        protocol_count["Arp"] += 1
        arp = packet[ARP]
        op = 'request' if arp.op == '1' else 'reply'
        print(f"[ARP] {arp.psrc} --> {arp.pdst}    ({op})")
        return

    if not packet.haslayer(IP):
        protocol_counts['Other'] += 1
        return

    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst

    talkers[src_ip] +=1

    if packet.haslayer(TCP):
        prot_name = 'TCP'
        tcp_layer = packet[TCP]
        src_port, dst_port  = tcp_layer.sport, tcp_layer.dport
        port_scan_tracker[src_ip].add(dst_port)
    pass

def summary():
    '''Print summary of traffic analysis'''
    elapsed = (datetime.now() - start_time).total_seconds()
    pass


def main():
    global startTime
    pass

if __name__ == "__main__":
    main()