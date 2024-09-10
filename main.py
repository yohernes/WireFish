import tkinter as tk
from tkinter import scrolledtext, font
from scapy.all import sniff
from scapy.layers.inet import IP
import threading
import socket
import ipaddress


class PacketSniffer:
    def __init__(self, master):
        self.master = master
        master.title("Simple Packet Sniffer")

        # Set initial window size and minimum size
        master.geometry("800x600")  # Initial size: 800x600 pixels
        master.minsize(400, 300)  # Minimum size: 400x300 pixels

        # Configure the main window to be resizable
        # Weight of 1 means this row/column will expand to fill extra space
        master.grid_rowconfigure(0, weight=1)
        master.grid_columnconfigure(0, weight=1)

        # Create main frame to hold all widgets
        main_frame = tk.Frame(master)
        main_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        main_frame.grid_rowconfigure(0, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)

        # Create a custom font for better readability
        custom_font = font.Font(family="Courier", size=10)

        # Create scrollable text area for displaying packet information
        self.text_area = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, font=custom_font)
        self.text_area.grid(row=0, column=0, sticky="nsew")

        # Configure color tags for different parts of the packet information
        self.text_area.tag_configure("src_ip", foreground="blue")
        self.text_area.tag_configure("dst_ip", foreground="green")
        self.text_area.tag_configure("proto_tcp", foreground="red")
        self.text_area.tag_configure("proto_udp", foreground="purple")
        self.text_area.tag_configure("proto_other", foreground="orange")

        # Create a frame for buttons
        button_frame = tk.Frame(main_frame)
        button_frame.grid(row=1, column=0, sticky="ew", pady=10)

        # Create Start and Stop buttons
        self.start_button = tk.Button(button_frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = tk.Button(button_frame, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        # Initialize sniffing state and DNS cache
        self.is_sniffing = False
        self.dns_cache: dict[str, str] = {}

    def get_domain_name(self, ip: str) -> str:
        """
        Perform a reverse DNS lookup for the given IP address.
        Uses a cache to store previous lookups for efficiency.
        """
        domain_name = ""
        address = ipaddress.ip_address(ip)
        if ip in self.dns_cache:
            return self.dns_cache[ip]
        try:
            domain_name = socket.gethostbyaddr(ip)[0]
            self.dns_cache[ip] = domain_name
            return domain_name
        except socket.herror:
            # If reverse DNS lookup fails, use the IP address as the domain name
            return "unknown"

    def packet_callback(self, packet) -> None:
        """
        Process each captured packet and display its information.
        This function is called for each packet sniffed.
        """
        if IP in packet:
            # Extract IP layer information
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            proto = packet[IP].proto

            # Determine protocol and assign color tag
            if proto == 6:
                proto_name = "TCP"
                proto_tag = "proto_tcp"
            elif proto == 17:
                proto_name = "UDP"
                proto_tag = "proto_udp"
            else:
                proto_name = "Other"
                proto_tag = "proto_other"

            # Perform reverse DNS lookups
            src_domain = self.get_domain_name(ip_src)
            dst_domain = self.get_domain_name(ip_dst)

            # Display packet information with color coding
            self.text_area.insert(tk.END, "IP Packet: ", "")
            self.text_area.insert(tk.END, f"{ip_src} ({src_domain}) ", "src_ip")
            self.text_area.insert(tk.END, "-> ", "")
            self.text_area.insert(tk.END, f"{ip_dst} ({dst_domain}) ", "dst_ip")
            self.text_area.insert(tk.END, "Proto: ", "")
            self.text_area.insert(tk.END, f"{proto_name}\n", proto_tag)

            # Autoscroll to the bottom of the text area
            self.text_area.see(tk.END)

    def start_sniffing(self) -> None:
        """
        Start the packet sniffing process in a separate thread.
        """
        self.is_sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.sniff_thread = threading.Thread(target=self.sniff_packets)
        self.sniff_thread.start()

    def stop_sniffing(self) -> None:
        """
        Stop the packet sniffing process.
        """
        self.is_sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def sniff_packets(self) -> None:
        """
        Use scapy's sniff function to capture packets.
        This function runs in a separate thread to keep the GUI responsive.
        """
        sniff(prn=self.packet_callback, store=0, stop_filter=lambda x: not self.is_sniffing)


# Create the main window and start the application
root = tk.Tk()
sniffer = PacketSniffer(root)
root.mainloop()