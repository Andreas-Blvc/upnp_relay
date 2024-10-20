import re
import threading
import socket
from scapy.all import sniff, UDP, IP, Raw

from send_udp_packet import *

# Define SSDP multicast details
SSDP_PORT = 1900
SSDP_MULTICAST_ADDR = "239.255.255.250"

# List of interfaces to listen for responses (adjust based on your setup)
interfaces_to_listen = ["eth0"]

# Function to handle and forward SSDP M-SEARCH packets
def ssdp_packet(packet):
    if packet.haslayer(UDP) and packet[UDP].dport == SSDP_PORT:
        if packet.haslayer(Raw):  # Check if the packet has raw data (SSDP content)
            data = packet[Raw].load.decode(errors='ignore')
            if re.search(r"M-SEARCH", data):  # Detect M-SEARCH request
                # print(f"Captured SSDP M-SEARCH from {packet[IP].src} on wg0 -> {packet[IP].dst}")
                # print(data)
                # print("=" * 80)

                # Forward the SSDP M-SEARCH request to wlan0
                send_udp_packet('eth0', '10.12.2.118', packet[UDP].sport, SSDP_MULTICAST_ADDR, SSDP_PORT, packet[Raw].load)
                print(f"Forwarded SSDP M-SEARCH: {packet[IP].src}:{packet[UDP].sport}, wg0 --> {SSDP_MULTICAST_ADDR}:{SSDP_PORT}, eth0")

                # Start listening for SSDP responses asynchronously after forwarding
                start_async_response_listener(packet[IP].src, packet[UDP].sport)

# Function to handle SSDP responses
def ssdp_response(packet, src_ip):
    data = packet[Raw].load.decode(errors='ignore')
    send_udp_packet('wg0', packet[IP].src, packet[UDP].sport, src_ip, packet[UDP].dport, packet[Raw].load)
    # print(f"Forwarded UDP Dial reponse: {packet[IP].src}:{packet[UDP].sport}, eth0 (replaced by {packet[IP].dst}:{packet[UDP].dport}) --> {src_ip}:{packet[UDP].dport}, wg0 ")

# Asynchronous listener function for SSDP responses
def listen_for_responses(iface, src_ip, src_port):
    print(f"Listening for SSDP responses on {iface} dst port {src_port}...")
    sniff(iface=iface, filter=f"udp and dst port {src_port}", prn=lambda packet: ssdp_response(packet, src_ip), store=0)

def listen_for_requests(iface):
    print(f"Listening for REQUESTS on interface {iface}...")
    sniff(iface="wg0", filter=f"udp and dst {SSDP_MULTICAST_ADDR} and port {SSDP_PORT}", prn=ssdp_packet, store=0)


# Function to start response listeners asynchronously on multiple interfaces
def start_async_response_listener(src_ip, src_port):
    for iface in interfaces_to_listen:
        # Create a new thread to listen for SSDP responses on each interface
        listener_thread = threading.Thread(target=listen_for_responses, args=(iface, src_ip, src_port))
        listener_thread.start()


if __name__ == '__main__':
    listen_for_requests('wg0')
    
