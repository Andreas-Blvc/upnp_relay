import netifaces

def get_ip_address(interface):
    try:
        # Get addresses of the specified interface
        addresses = netifaces.ifaddresses(interface)
        # IPv4 addresses are under the AF_INET family
        ip_info = addresses[netifaces.AF_INET][0]
        return ip_info['addr']
    except KeyError:
        return f"No IPv4 address found for interface {interface}"
    except ValueError:
        return f"Invalid interface: {interface}"
    except Exception as e:
        return f"Error: {e}"
