# gui.py

import customtkinter as ctk

# Debug print to confirm the file is running
print("Starting GUI...")

# Set appearance mode and color theme
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# Create the main window
app = ctk.CTk()
app.title("Network Scanner Tool")
app.geometry("600x500")

# Debug label to confirm window creation
debug_label = ctk.CTkLabel(app, text="GUI Initialized!")
debug_label.pack(pady=(10, 10))

# IP Range Label and Entry
ip_label = ctk.CTkLabel(app, text="Enter IP range (CIDR e.g., 192.168.1.0/24 or start-end e.g., 192.168.1.1-192.168.1.254):")
ip_label.pack(pady=(20, 5))

ip_entry = ctk.CTkEntry(app, placeholder_text="e.g., 192.168.1.0/24 or 192.168.1.1-192.168.1.254")
ip_entry.pack(pady=(0, 20), padx=20, fill="x")

# Port Range Label and Entry
port_label = ctk.CTkLabel(app, text="Enter Port range (e.g., 20-1024):")
port_label.pack(pady=(0, 5))

port_entry = ctk.CTkEntry(app, placeholder_text="e.g., 20-1024")
port_entry.pack(pady=(0, 20), padx=20, fill="x")

# Button to start the scan with a debug callback
def start_scan():
    ip_range = ip_entry.get()
    port_range = port_entry.get()
    print("Start Scan button pressed.")
    print("IP Range:", ip_range)
    print("Port Range:", port_range)
    # Here you can later integrate your scanning functions
    # For example:
    # live_hosts = scan_network(ip_range)
    # And update the GUI with the results

scan_button = ctk.CTkButton(app, text="Start Scan", command=start_scan)
scan_button.pack(pady=(0, 20))

# Debug print before launching the main loop
print("Launching GUI main loop...")

# Start the GUI event loop
app.mainloop()

# Debug print after the main loop (note: this line usually won't execute until the window is closed)
print("GUI has been closed.")
