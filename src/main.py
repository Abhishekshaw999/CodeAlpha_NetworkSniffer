
from collections import Counter

from scapy.all import IP, IPv6, TCP, UDP, ICMP

from capture import list_interfaces, start_capture
from analyzer import analyze_packet


packet_counter = 0
protocol_counts = Counter()


def process_packet(packet):
    global packet_counter

    packet_counter += 1

    # Analyze the captured packet
    analyze_packet(packet, packet_counter)

    # Count protocols
    if TCP in packet:
        protocol_counts["TCP"] += 1

    elif UDP in packet:
        protocol_counts["UDP"] += 1

    elif ICMP in packet:
        protocol_counts["ICMP"] += 1

    elif IP in packet or IPv6 in packet:
        protocol_counts["Other IP"] += 1

    else:
        protocol_counts["Other"] += 1


def main():

    print("\n" + "=" * 60)
    print("          CODEALPHA - NETWORK PACKET SNIFFER")
    print("=" * 60)

    # Display available interfaces
    interfaces = list_interfaces()

    if not interfaces:
        print("No network interfaces found.")
        return

    # Select network interface
    print("\nSelect a network interface.")

    for index, interface in enumerate(interfaces):
        print(f"[{index}] {interface}")

    try:
        choice = int(input("\nEnter interface number: "))

        if choice < 0 or choice >= len(interfaces):
            print("Invalid interface selection.")
            return

        selected_interface = interfaces[choice]

        # Select packet filter
        print("\nAvailable filters:")
        print("1. All IP traffic (default)")
        print("2. TCP")
        print("3. UDP")
        print("4. ICMP")

        filter_choice = input("\nChoose filter [1]: ").strip()

        filters = {
            "1": "ip or ip6",
            "2": "tcp",
            "3": "udp",
            "4": "icmp"
        }

        packet_filter = filters.get(filter_choice, "ip or ip6")

        # Select packet count
        count_input = input(
            "\nNumber of packets to capture [10, 0 = unlimited]: "
        ).strip()

        packet_limit = int(count_input) if count_input else 10

        if packet_limit < 0:
            print("Packet count cannot be negative.")
            return

        # Start packet capture
        start_capture(
            interface=selected_interface,
            callback=process_packet,
            packet_filter=packet_filter,
            count=packet_limit
        )

    except ValueError:
        print("\nInvalid input. Please enter a valid number.")

    except KeyboardInterrupt:
        print("\n\nCapture stopped by user.")

    finally:
        # Display statistics
        print("\n" + "=" * 60)
        print("             CAPTURE STATISTICS")
        print("=" * 60)

        print(f"Total packets analyzed: {packet_counter}")

        if protocol_counts:
            for protocol, total in protocol_counts.items():
                print(f"{protocol}: {total}")

        else:
            print("No packets were analyzed.")

        print("=" * 60)


if __name__ == "__main__":
    main()
