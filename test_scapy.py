
from scapy.all import IP, ICMP, sr1

print("================================")
print("     SCAPY NETWORK TEST")
print("================================")

print("Scapy is successfully installed!")

packet = IP(dst="1.1.1.1") / ICMP()

print("\nGenerated packet:")
packet.show()

print("\nTesting packet transmission...")

response = sr1(packet, timeout=3, verbose=0)

if response:
    print("\nResponse received!")
    response.show()
else:
    print("\nNo response received.")
    print("This may be caused by firewall or network restrictions.")
