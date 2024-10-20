from scapy.all import IP, UDP, Raw, send

def send_udp_packet(interface, src_ip, src_port, dest_ip, dest_port, payload):
    """
    Sends a spoofed UDP packet using scapy from a specific source IP and port.

    :param interface: The WireGuard interface (e.g., 'wg0').
    :param src_ip: The source IP address (can be spoofed).
    :param src_port: The source UDP port to send from.
    :param dest_ip: The destination IP address.
    :param dest_port: The destination UDP port.
    :param payload: The data payload to send (as bytes).
    """
    try:
        # Construct the IP and UDP layers
        ip_layer = IP(src=src_ip, dst=dest_ip)
        udp_layer = UDP(sport=src_port, dport=dest_port)
        data = Raw(load=payload)

        # Build the packet
        packet = ip_layer / udp_layer / data

        # Send the packet on the specified interface
        send(packet, iface=interface, verbose=False)
        # print(f"Sent spoofed packet from {src_ip}:{src_port} to {dest_ip}:{dest_port} over interface {interface}")

    except Exception as e:
        print(f"Error: {e}")