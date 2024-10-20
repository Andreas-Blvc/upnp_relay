import re
from threading import Thread
from scapy.all import sniff, UDP, IP, Raw

from upnp_relay.send_udp_packet import *
from upnp_relay.get_ip_address import *
from upnp_relay.ansi_codes import *

# Define SSDP multicast details
SSDP_PORT = 1900
SSDP_MULTICAST_ADDR = "239.255.255.250"

# Network interfaces for services and clients
services_network_interface = "eth0"
clients_network_interface = "wg0"

# Get the IP address associated with the services network interface
service_interface_ip = get_ip_address(services_network_interface)


def forward_response_to_client(response_packet, client_ip):
    """
    Forwards the received SSDP response to the requesting client by spoofing the source IP and port.
    """
    # Colorful print statement before sending the UDP packet
    print(f"{COLOR_GREEN}Forwarding response to client:{COLOR_RESET}")
    print(f"{COLOR_YELLOW}  From (spoofed IP): {response_packet[IP].src}:{response_packet[UDP].sport}{COLOR_RESET}")
    print(f"{COLOR_CYAN}  To: {client_ip}:{response_packet[UDP].dport}{COLOR_RESET}")
    
    send_udp_packet(
        interface=clients_network_interface,
        src_ip=response_packet[IP].src,  # Spoofed source IP
        src_port=response_packet[UDP].sport,  # Spoofed source port
        dest_ip=client_ip,  # Destination: Requesting client's IP
        dest_port=response_packet[UDP].dport,  # Destination port on client
        payload=response_packet[Raw].load  # Forwarding the original payload
    )

def listen_for_ssdp_responses(interface, client_ip, client_port):
    """
    Listens for SSDP responses on the specified interface and forwards them to the client.
    """
    print(f"{COLOR_BLUE}Listening for SSDP RESPONSES on {interface} for destination port {client_port}...{COLOR_RESET}")
    sniff(
        iface=interface, 
        filter=f"udp and dst port {client_port}", 
        prn=lambda packet: forward_response_to_client(packet, client_ip), 
        store=0
    )

def handle_ssdp_request(request_packet):
    """
    Handles incoming SSDP M-SEARCH requests and relays them to the SSDP multicast address.
    """
    if not request_packet.haslayer(Raw): 
        return
    
    request_data = request_packet[Raw].load.decode(errors='ignore')
    
    if re.search(r"M-SEARCH", request_data):  # Detect M-SEARCH request
        # Colorful print statement before sending the UDP packet
        print(f"{COLOR_GREEN}Relaying M-SEARCH request:{COLOR_RESET}")
        print(f"{COLOR_YELLOW}  From: {request_packet[IP].src}:{request_packet[UDP].sport}{COLOR_RESET}")
        print(f"{COLOR_CYAN}  To SSDP Multicast: {SSDP_MULTICAST_ADDR}:{SSDP_PORT}{COLOR_RESET}")
        
        send_udp_packet(
            interface=services_network_interface,
            src_ip=service_interface_ip,  # Source: Service interface IP
            src_port=request_packet[UDP].sport,  # Forward original source port
            dest_ip=SSDP_MULTICAST_ADDR,  # Multicast address for SSDP
            dest_port=SSDP_PORT,  # SSDP port
            payload=request_packet[Raw].load  # Forward original payload
        )
        
        # Start a thread to listen for responses and forward them to the client
        Thread(
            target=listen_for_ssdp_responses, 
            args=(clients_network_interface, request_packet[IP].src, request_packet[UDP].sport)
        ).start()

def listen_for_ssdp_requests():
    """
    Listens for incoming SSDP M-SEARCH requests on the clients' network interface.
    """
    print(f"{COLOR_BLUE}Listening for SSDP REQUESTS on {clients_network_interface}...{COLOR_RESET}")
    sniff(
        iface=clients_network_interface,
        filter=f"udp and dst {SSDP_MULTICAST_ADDR} and port {SSDP_PORT}",
        prn=handle_ssdp_request,
        store=0
    )

if __name__ == '__main__':
    listen_for_ssdp_requests()
