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

        if len(port_scan_tracker[src_ip]) == 15:
            print(f"Possible port scan from {src_ip}"
                f" {len(port_scan_tracker[src_ip])} different ports so far" )
        
        note = ""
        if src_port == 80 or dst_port == 80:
            note = "   (HTTP -- Unencrypted)"
        elif src_port == 21 or dst_port == 21:
            note = "   (FTP -- Unencrypted, avoid on nontrusted networks)"
        elif src_port == 23 or dst_port == 23:
            note = "   (Telnet -- Unencrypted, intentionally insecure)"

        print( f"[TCP]   {src_ip}:{src_port}  ->  {dst_ip}:{dst_port} {note}")

    elif packet.haslayer(UDP):
        prot_name = 'UDP'
        udp_layer = packet[UDP]
        print(f"[UDP]   {src_ip}:{udp_layer.sport}  ->  {dst_ip}:{udp_layer.dport}")v
    
    else:
        prot_name = 'IP-OTHER'
        print(f"[IP]   {src_ip}  ->  {dst_ip} (protocol #{ip_layer.proto})")
    
    protocol_count[prot_name] += 1


def print_summary():
    '''Print summary of traffic analysis'''
    elapsed = (datetime.now() - start_time).total_seconds()

    print("\n" + "-" * 50)
    print("CAPTURE SUMMARY")
    print("-" * 50)
    print(f"Duration:        {elapsed:.1f} seconds")
    print(f"Total packets:   {len(captured_packets)}")

    print("\nPacket Breakdown:")
    for protocol, count in protocol_counts.most_common():
        print(f"    {protocol:<10}  {count}")
    
    print("\nTop 5 talkers (by source IP)")
    for ip, count in talkers.most_common(5):
        print(f"    {ip:<16}  {count} packets")

    scanners = {ip: ports for ip, ports in port_scan_tracker.items() if len(ports) >= 15}
    
    pass


def main():
    global startTime

    parser = argparse.ArgumentParser(
        description="Network traffic analyzer (Scapy-based).")

    parser.addargument("-i", "--interface", default=None,
        help="Network interface to sniff on (e.g. eth0, wlan0, en0). "
             "Default: Scapy picks automatically.")
    pass

if __name__ == "__main__":
    main()