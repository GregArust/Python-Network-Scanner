# Network Scanner Tool

A Python-based network scanner tool that detects live hosts, scans open ports with banner grabbing, performs GeoIP lookups, and logs/export results to CSV.

## Features

- **IP Range Scanning:**  
  Supports both CIDR notation (e.g., `192.168.1.0/24`) and start-end format (e.g., `192.168.1.1-192.168.1.254`) for flexible network scanning.

- **Ping Sweep:**  
  Detects live hosts using a multithreaded ping sweep across the specified range.

- **Port Scanning & Banner Grabbing:**  
  Scans ports (default 20–1024) on live hosts using multithreading, attempts to grab banners to identify running services, and labels known ports.

- **GeoIP Lookup:**  
  Uses a free API (ip-api.com) to obtain geographic information (country, city, organization) for each live host.

- **Logging & Export:**  
  Saves scan results (IP, open ports with banners, GeoIP info, and timestamp) to a CSV file in a `/logs` folder.

- **Future GUI:**  
  A graphical user interface (GUI) is planned for future releases. (See **Future Work** below for details.)

## Requirements

- Python 3.6+
- See [requirements.txt](requirements.txt) for Python package dependencies.

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/yourusername/network_scanner_tool.git
   cd network_scanner_tool
