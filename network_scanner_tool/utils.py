import os
from dotenv import load_dotenv
load_dotenv()  # Load environment variables from the .env file

import requests
import shodan  # Ensure you have installed shodan: pip install shodan
import ipaddress

def get_geoip_info(ip):
    """
    Look up geographic info about the given IP using ip-api.com.
    
    Returns:
        dict or None: A dictionary containing 'country', 'city', 'org' or None on failure.
    """
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = response.json()
        return {
            "country": data.get("country"),
            "city": data.get("city"),
            "org": data.get("org")
        }
    except Exception:
        return None

def shodan_lookup(ip):
    """
    Query the Shodan API for information about the given IP.
    
    Returns:
        dict or None: A dictionary containing 'org', 'hostnames', 'open_ports' or None on failure.
    """
    # Skip private/internal IPs that Shodan cannot look up
    try:
        if ipaddress.ip_address(ip).is_private:
            print(f"ℹ️ Skipping Shodan lookup for private IP: {ip}")
            return None
    except ValueError:
        print(f"⚠️ Invalid IP address: {ip}")
        return None

    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
    if not SHODAN_API_KEY:
        print("❌ Shodan API key not found in environment.")
        return None

    api = shodan.Shodan(SHODAN_API_KEY)

    try:
        host = api.host(ip)
        return {
            "org": host.get("org"),
            "hostnames": host.get("hostnames"),
            "open_ports": host.get("ports")
        }
    except Exception as e:
        print(f"Shodan lookup failed for {ip}: {e}")
        return None
