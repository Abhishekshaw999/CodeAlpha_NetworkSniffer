
from scapy.all import sniff, get_if_list


def list_interfaces():
    """
    Display available network interfaces.
    """
    interfaces = get_if_list()

    print("\nAVAILABLE NETWORK INTERFACES")
    print("-" * 60)

    for index, interface in enumerate(interfaces):
        print(f"[{index}] {interface}")

    return interfaces


def start_capture(
    interface,
    callback,
    packet_filter="ip or ip6",
    count=10
):
    """
    Capture packets from the selected network interface.
    """

    print("\n" + "=" * 60)
    print("NETWORK PACKET CAPTURE STARTED")
    print("=" * 60)

    print(f"Interface: {interface}")
    print(f"Filter: {packet_filter}")
    print(f"Packet Limit: {count if count else 'Unlimited'}")
    print("\nPress CTRL+C to stop capturing.\n")

    sniff(
        iface=interface,
        filter=packet_filter,
        prn=callback,
        count=count,
        store=False
    )

    print("\nPacket capture completed.")
