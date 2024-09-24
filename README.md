# WireFish
## What is this?
This is a packet sniffer that also provides Reverse DNS lookup and saves it in a JSON cache (basically making your computer a DNS server). Made using Scapy and Tkinter in python. 
#### Educational purposes only. Make sure you have permission to sniff a network before using this.
## Documentation

### Imports and Dependencies

tkinter for the GUI.

scapy for packet sniffing.

threading for running the sniffer in a separate thread.

socket and ipaddress for DNS lookups.

### PacketSniffer Class
This is the main class that encapsulates the entire application.
Initialization (__init__ method)

Sets up the main window and configures its properties (title, size, etc.)
Creates a scrollable text area for displaying packet information
Sets up color tags for different parts of the packet information (source IP, destination IP, protocols)
Creates "Start Sniffing" and "Stop Sniffing" buttons
Initializes the sniffing state and DNS cache

### DNS Lookup (get_domain_name method)

Performs a reverse DNS lookup for a given IP address
Uses a cache to store previous lookups for efficiency
Handles private and global IP addresses differently

### Packet Processing (packet_callback method)

Called for each captured packet
Extracts source IP, destination IP, and protocol information
Performs reverse DNS lookups for source and destination IPs
Displays packet information in the text area with color coding

### Sniffing Control Methods

start_sniffing: Starts the packet sniffing process in a separate thread
stop_sniffing: Stops the packet sniffing process
sniff_packets: Uses Scapy's sniff function to capture packets

Application Closure (close_app method)

Saves the DNS cache to a JSON file when the application is closed

### Key Features

Real-time Packet Display: Captures and displays network packets in real-time.

DNS Caching: Implements a DNS cache to reduce repeated lookups and improve performance.

Threaded Sniffing: Runs the packet sniffing in a separate thread to keep the GUI responsive.

Start/Stop Functionality: Allows users to start and stop the sniffing process.


### Usage
To use this packet sniffer:

Run the script (Note: It may require root/administrator privileges for packet capture)
Click "Start Sniffing" to begin capturing packets
The captured packets will be displayed in the text area with color-coded information
Click "Stop Sniffing" to halt the packet capture process

## Note
This script provides a basic packet sniffing functionality and should be used responsibly and only on networks you have permission to monitor. It's primarily designed for educational purposes and network debugging.
