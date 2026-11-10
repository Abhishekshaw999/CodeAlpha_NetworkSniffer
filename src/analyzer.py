
from datetime import datetime
from scapy.all import IP, IPv6, TCP, UDP, ICMP, DNS, Raw


def analyze_packet(packet, packet_number):

    print("\n" + "=" * 60)
    print(f"PACKET #{packet_number}")
    print("=" * 60)

    # Capture timestamp
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Packet size
    print(f"Packet Length: {len(packet)} bytes")

    # Identify IP addresses
    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        print(f"Source IP: {source_ip}")
        print(f"Destination IP: {destination_ip}")

    elif IPv6 in packet:
        source_ip = packet[IPv6].src
        destination_ip = packet[IPv6].dst
        print(f"Source IPv6: {source_ip}")
        print(f"Destination IPv6: {destination_ip}")

    else:
        print("No IP layer detected.")

    # Identify transport protocol
    if TCP in packet:
        print("Protocol: TCP")
        print(f"Source Port: {packet[TCP].sport}")
        print(f"Destination Port: {packet[TCP].dport}")

    elif UDP in packet:
        print("Protocol: UDP")
        print(f"Source Port: {packet[UDP].sport}")
        print(f"Destination Port: {packet[UDP].dport}")

    elif ICMP in packet:
        print("Protocol: ICMP")
        print(f"ICMP Type: {packet[ICMP].type}")
        print(f"ICMP Code: {packet[ICMP].code}")

    else:
        print("Protocol: Other")

    # DNS information
    if DNS in packet and packet[DNS].qd:
        try:
            domain = packet[DNS].qd.qname.decode(
                "utf-8", errors="replace"
            ).rstrip(".")
            print(f"DNS Query: {domain}")
        except Exception:
            print("DNS Query: Unable to decode")

    # Inspect a small payload preview
    if Raw in packet:
        payload = bytes(packet[Raw].load)
        preview = payload[:48]

        print(f"Payload Size: {len(payload)} bytes")
        print(f"Payload Preview (Hex): {preview.hex()}")

    else:
        print("Payload: No raw payload detected.")

    print("=" * 60)
