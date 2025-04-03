# utils.py

import requests
# Optional: Uncomment and set your Shodan API key if you want to use Shodan lookups.
# import shodan
# SHODAN_API_KEY = "your_api_key_here"
# api = shodan.Shodan(SHODAN_API_KEY)

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

# Optional Shodan lookup function
# def shodan_lookup(ip):
#     """
#     Query the Shodan API for information about the given IP.
#     
#     Returns:
#         dict or None: A dictionary containing 'org', 'hostnames', 'open_ports' or None on failure.
#     """
#     try:
#         host = api.host(ip)
#         return {
#             "org": host.get("org"),
#             "hostnames": host.get("hostnames"),
#             "open_ports": host.get("ports")
#         }
#     except Exception:
#         return None
