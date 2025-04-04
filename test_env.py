from dotenv import load_dotenv
import os
import shodan

load_dotenv()
api = shodan.Shodan(os.getenv("SHODAN_API_KEY"))

try:
    host = api.host("8.8.8.8")  # Google's public DNS
    print("IP:", host['ip_str'])
    print("Org:", host.get('org'))
    print("Open Ports:", host.get('ports'))
except Exception as e:
    print("Shodan lookup failed:", e)
