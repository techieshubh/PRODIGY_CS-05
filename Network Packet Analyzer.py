from scapy.all import *

def packet_analysis(packet):
    # Check if packet is IPv4
    if packet.haslayer(IP):
        # Get source and destination IP addresses
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        # Get protocol
        protocol = packet[IP].proto

        # Protocol mapping for better readability
        protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        protocol_name = protocol_map.get(protocol, str(protocol))

        # Check if Raw layer exists
        if packet.haslayer(Raw):
            payload = packet[Raw].load
        else:
            payload = b""  # Set payload to an empty byte string if not present

        # Print packet information
        print(f"Source IP: {source_ip}")
        print(f"Destination IP: {destination_ip}")
        print(f"Protocol: {protocol_name}")
        print(f"Payload: {payload}")
        print("-" * 32)

# Start sniffing
print("Starting packet sniffer...")
try:
    sniff(filter="ip", prn=packet_analysis)
except PermissionError:
    print("You need to run this script with administrative privileges.")
