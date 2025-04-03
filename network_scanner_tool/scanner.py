# scanner.py

import ipaddress
import subprocess
import platform
import socket
import concurrent.futures

def generate_ip_list(ip_range_input):
    """
    Generate a list of usable IP addresses from the given range input.
    Supports two formats:
      - CIDR notation (e.g., '192.168.1.0/24')
      - Start-end format (e.g., '192.168.1.1-192.168.1.254')
    
    Returns:
        list: A list of IP addresses as strings.
    """
    ip_list = []
    
    if "/" in ip_range_input:
        try:
            network = ipaddress.ip_network(ip_range_input, strict=False)
            ip_list = [str(ip) for ip in network.hosts()]
        except ValueError as e:
            print(f"Invalid CIDR notation: {ip_range_input}. Error: {e}")
    
    elif "-" in ip_range_input:
        try:
            start_ip_str, end_ip_str = ip_range_input.split("-")
            start_ip = ipaddress.IPv4Address(start_ip_str.strip())
            end_ip = ipaddress.IPv4Address(end_ip_str.strip())
            
            if int(start_ip) > int(end_ip):
                print("Error: Start IP must be less than or equal to End IP.")
            else:
                for ip_int in range(int(start_ip), int(end_ip) + 1):
                    ip_list.append(str(ipaddress.IPv4Address(ip_int)))
        except ValueError as e:
            print(f"Invalid start-end format: {ip_range_input}. Error: {e}")
    else:
        print("Invalid IP range format. Please provide CIDR (e.g., 192.168.1.0/24) or start-end (e.g., 192.168.1.1-192.168.1.254).")
    
    return ip_list

def _ping_host(ip):
    """
    Helper function to ping a single host.
    Returns the IP if alive, else None.
    """
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ["ping", param, "1", ip]
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            return ip
    except Exception as e:
        print(f"Error pinging {ip}: {e}")
    return None

def ping_sweep(ip_list):
    """
    Ping each IP in the provided list concurrently to detect live hosts.
    
    Returns:
        list: A list of IP addresses (as strings) that responded to the ping.
    """
    live_hosts = []
    max_workers = min(100, len(ip_list)) if ip_list else 1
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_ping_host, ip): ip for ip in ip_list}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result is not None:
                live_hosts.append(result)
    return live_hosts

def scan_network(ip_range):
    """
    Combine IP list generation and ping sweep.
    
    Args:
        ip_range (str): The IP range in CIDR or start-end format.
    
    Returns:
        list: A list of live host IP addresses.
    """
    ip_list = generate_ip_list(ip_range)
    return ping_sweep(ip_list)

def grab_banner(ip, port):
    """
    Attempt to grab a banner from an open port.
    
    Returns:
        str or None: The banner text if retrieved, otherwise None.
    """
    try:
        with socket.socket() as s:
            s.settimeout(1)
            s.connect((ip, port))
            banner = s.recv(1024).decode(errors="ignore")
            return banner.strip()
    except Exception:
        return None

def _check_port(target, port, common_ports):
    """
    Helper function to check a single port on a target.
    Returns a tuple (port, service, banner) if open, otherwise None.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        result = s.connect_ex((target, port))
        if result == 0:
            service = common_ports.get(port, "Unknown Service")
            banner = grab_banner(target, port)
            return port, service, banner
    return None

def port_scan(target, start_port=20, end_port=1024):
    """
    Scan a target host for open ports within the specified range concurrently.
    
    Args:
        target (str): The target IP address or hostname.
        start_port (int): The starting port number (default: 20).
        end_port (int): The ending port number (default: 1024).
    
    Returns:
        dict: A dictionary where keys are open port numbers and values are (service, banner) tuples.
    """
    open_ports = {}
    common_ports = {
        20: 'FTP Data',
        21: 'FTP Control',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        67: 'DHCP',
        68: 'DHCP',
        69: 'TFTP',
        80: 'HTTP',
        110: 'POP3',
        119: 'NNTP',
        123: 'NTP',
        143: 'IMAP',
        161: 'SNMP',
        194: 'IRC',
        443: 'HTTPS',
        465: 'SMTPS',
        993: 'IMAPS',
        995: 'POP3S'
    }
    
    ports_to_scan = range(start_port, end_port + 1)
    num_ports = end_port - start_port + 1
    max_workers = min(100, num_ports)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_check_port, target, port, common_ports): port for port in ports_to_scan}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result is not None:
                port_number, service, banner = result
                open_ports[port_number] = (service, banner)
    return open_ports

if __name__ == "__main__":
    # --- Test network scanning ---
    test_ip_range = "192.168.1.0/30"  # Change as needed
    print("Testing network scan:")
    ips = generate_ip_list(test_ip_range)
    print("Usable IPs:", ips)
    live_hosts = ping_sweep(ips)
    print("Live hosts:", live_hosts)
    
    # --- Test port scanning with banner grabbing ---
    target_host = "192.168.1.1"  # Replace with target IP/hostname
    print(f"\nScanning {target_host} for open ports:")
    open_ports = port_scan(target_host)
    if open_ports:
        print("{:<10} {:<20} {:<40}".format("Port", "Service", "Banner"))
        print("-" * 70)
        for port, (service, banner) in open_ports.items():
            print("{:<10} {:<20} {:<40}".format(port, service, banner if banner else "No Banner"))
    else:
        print("No open ports found in the specified range.")
