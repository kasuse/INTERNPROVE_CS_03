from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Packet callback function to analyze packets
def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        print(f"Source IP: {ip_src}, Destination IP: {ip_dst}", end=", ")

        # Check for TCP
        if packet.haslayer(TCP):
            print(f"Protocol: TCP, Source Port: {packet[TCP].sport}, Destination Port: {packet[TCP].dport}")
        # Check for UDP
        elif packet.haslayer(UDP):
            print(f"Protocol: UDP, Source Port: {packet[UDP].sport}, Destination Port: {packet[UDP].dport}")
        # Check for ICMP
        elif packet.haslayer(ICMP):
            print(f"Protocol: ICMP")
        else:
            print("Protocol: Other")
            
        # Display payload if available
        if packet[IP].payload:
            print(f"Payload: {bytes(packet[IP].payload).hex()[:32]}...")  # Displaying a portion of payload
        else:
            print("No payload available")

# Sniffing function to capture packets
def start_sniffing(interface="eth0"):
    print(f"Sniffing on {interface}... Press Ctrl+C to stop.")
    sniff(iface=interface, prn=packet_callback, store=False)

if __name__ == "__main__":
    # Run the sniffer on the specified network interface (e.g., eth0, wlan0)
    start_sniffing(interface="Wi-Fi")
