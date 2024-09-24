from scapy.all import sniff

def packet_callback(packet):
    # Extracting IP layer information
    if packet.haslayer("IP"):
        ip_layer = packet["IP"]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto

        # Extracting payload data (if available)
        payload = str(packet.payload) if packet.payload else "No payload"

        # Displaying captured information
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}, Payload: {payload}")

def start_sniffing():
    print("Starting packet sniffing...")
    # Sniffing packets
    sniff(prn=packet_callback, store=0)  # store=0 avoids storing packets in memory

if __name__ == "__main__":
    start_sniffing()
