
from scapy.all import IP, TCP, Raw
from src.analyzer import analyze_packet

# Create a sample TCP packet
packet = (
    IP(src="192.168.1.10", dst="142.250.183.14")
    / TCP(sport=51524, dport=443)
    / Raw(load=b"Hello Network Sniffer!")
)

# Analyze the packet
analyze_packet(packet, 1)
