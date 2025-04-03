import customtkinter as ctk
from scanner import scan_network, port_scan  # Make sure these are real in scanner.py

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

app = ctk.CTk()
app.title("Network Scanner Tool")
app.geometry("700x600")

# --- Input Fields ---

ip_label = ctk.CTkLabel(app, text="Enter IP range (CIDR or start-end):")
ip_label.pack(pady=(20, 5))

ip_entry = ctk.CTkEntry(app, placeholder_text="e.g., 192.168.1.0/24 or 192.168.1.1-192.168.1.254")
ip_entry.pack(pady=(0, 20), padx=20, fill="x")

port_label = ctk.CTkLabel(app, text="Enter Port range (e.g., 20-1024):")
port_label.pack(pady=(0, 5))

port_entry = ctk.CTkEntry(app, placeholder_text="e.g., 20-1024")
port_entry.pack(pady=(0, 20), padx=20, fill="x")

# --- Results Box ---
results_box = ctk.CTkTextbox(app, width=600, height=300)
results_box.pack(pady=(10, 20), padx=20)

# --- Scan Button Logic ---
def start_scan():
    ip_range = ip_entry.get()
    port_range = port_entry.get()

    # Clear old results
    results_box.delete("1.0", "end")

    # Validate port input
    try:
        start_port, end_port = map(int, port_range.split("-"))
        ports = list(range(start_port, end_port + 1))
    except:
        results_box.insert("end", "❌ Invalid port range.\n")
        return

    results_box.insert("end", f"🔍 Scanning IPs in {ip_range}...\n")
    live_hosts = scan_network(ip_range)

    if not live_hosts:
        results_box.insert("end", "⚠️ No live hosts found.\n")
        return

    for host in live_hosts:
        results_box.insert("end", f"\n✅ {host} is online\n")
        open_ports = port_scan(host, start_port, end_port)
        if open_ports:
            for port, service in open_ports:
                results_box.insert("end", f"  - Open Port {port} ({service})\n")
        else:
            results_box.insert("end", "  No open ports found.\n")

scan_button = ctk.CTkButton(app, text="Start Scan", command=start_scan)
scan_button.pack(pady=(0, 20))

app.mainloop()
