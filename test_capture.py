
from scapy.all import sniff

WIFI_INTERFACE = r"\Device\NPF_{CF8C18C9-5FC8-41D4-B625-AE1B5D0555C9}"

packet_count = 0


def display_packet(packet):
    global packet_count
    packet_count += 1

    print("\n" + "-" * 50)
    print(f"PACKET #{packet_count}")
    print(f"Length: {len(packet)} bytes")
    print(packet.summary())


print("Starting live capture...")
print("Generate some network activity by opening a website.")
print("Capturing a maximum of 10 packets...\n")

sniff(
    iface=WIFI_INTERFACE,
    filter="ip or ip6",
    prn=display_packet,
    count=10,
    store=False
)

print("\nCapture completed!")
print(f"Total packets captured: {packet_count}")
