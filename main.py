import os
import csv
from datetime import datetime
from network_scanner_tool.scanner import scan_network, port_scan
from network_scanner_tool.utils import get_geoip_info, shodan_lookup

def save_results_to_csv(results):
    """
    Save the scan results to a CSV file inside a /logs folder.
    
    Args:
        results (list): A list of dictionaries with keys 'IP', 'Open Ports', 'GeoIP Info', and 'Timestamp'.
    """
    logs_folder = 'logs'
    if not os.path.exists(logs_folder):
        os.makedirs(logs_folder)
    
    timestamp_for_filename = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(logs_folder, f"scan_results_{timestamp_for_filename}.csv")
    
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['IP', 'Open Ports', 'GeoIP Info', 'Timestamp']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow(result)
    print(f"\nResults saved to {filename}")

def main():
    ip_range = input("Enter IP range (CIDR e.g., 192.168.1.0/24 or start-end e.g., 192.168.1.1-192.168.1.254): ").strip()
    port_range_input = input("Enter port range (e.g., 20-1024): ").strip()
    
    try:
        start_port, end_port = map(int, port_range_input.split('-'))
    except ValueError:
        print("Invalid port range format. Using default range 20-1024.")
        start_port, end_port = 20, 1024

    print("\nScanning network for live hosts...")
    live_hosts = scan_network(ip_range)
    if not live_hosts:
        print("No live hosts found in the specified IP range.")
        return

    results = []
    print("\nLive hosts detected:")
    for host in live_hosts:
        print(f"\nHost: {host}")
        
        # GeoIP lookup
        geo_info = get_geoip_info(host)
        if geo_info:
            print("Location Info:")
            print(f"  Country: {geo_info.get('country')}")
            print(f"  City: {geo_info.get('city')}")
            print(f"  Organization: {geo_info.get('org')}")
        else:
            print("No GeoIP information available.")
        
        # Shodan lookup
        shodan_info = shodan_lookup(host)
        if shodan_info:
            print(" Shodan Info:")
            print(f"  Org: {shodan_info.get('org')}")
            print(f"  Hostnames: {', '.join(shodan_info.get('hostnames', []))}")
            print(f"  Open Ports: {shodan_info.get('open_ports')}")

            if shodan_info.get("open_ports"):
                print("This host appears to be publicly exposed on the internet!\n")
        else:
            print("Shodan data not available.")
        
        print(f"\nScanning ports on {host} (ports {start_port} to {end_port}):")
        open_ports = port_scan(host, start_port, end_port)
        if open_ports:
            print("{:<10} {:<20} {:<40}".format("Port", "Service", "Banner"))
            print("-" * 70)
            for port, (service, banner) in open_ports.items():
                banner_text = banner if banner else "No Banner"
                print("{:<10} {:<20} {:<40}".format(port, service, banner_text))
        else:
            print("No open ports found.")
        
        results.append({
            'IP': host,
            'Open Ports': "; ".join(f"{port}:{service} [{banner if banner else 'No Banner'}]" 
                                      for port, (service, banner) in open_ports.items()) if open_ports else "None",
            'GeoIP Info': f"{geo_info.get('country')}, {geo_info.get('city')}, {geo_info.get('org')}" if geo_info else "None",
            'Timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })

    save_results_to_csv(results)

if __name__ == "__main__":
    main()
