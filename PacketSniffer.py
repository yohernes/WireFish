import tkinter as tk
from tkinter import scrolledtext, font, ttk
from scapy.all import sniff
from scapy.layers.inet import IP
import threading
import socket
import ipaddress
from MemoryManager import *


class PacketSniffer:
    def __init__(self, master):

        self.sniff_thread = None
        self.master: tk.Widget = master
        master.title("WireFish")

        # Set initial window size and minimum size
        master.geometry("1000x700")  # Increased initial size
        master.minsize(600, 400)  # Increased minimum size

        # Configure the main window to be resizable
        master.grid_rowconfigure(0, weight=1)
        master.grid_columnconfigure(0, weight=1)

        # Create main frame to hold all widgets
        main_frame = tk.Frame(master)
        main_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        main_frame.grid_rowconfigure(0, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)

        # Create a custom font for better readability
        custom_font = font.Font(family="Courier", size=10)


        #TO FIX
        self.nav_bar = tk.Frame(master)
        self.nav_bar.grid(padx=10, pady=10)




        # Create a PanedWindow to separate packet list and content
        self.paned_window = ttk.PanedWindow(main_frame, orient=tk.VERTICAL)
        self.paned_window.grid(row=0, column=0, sticky="nsew")

        # Create a frame for the packet list
        packet_list_frame = ttk.Frame(self.paned_window)
        self.paned_window.add(packet_list_frame, weight=1)

        # Create a Treeview widget for displaying packet information
        self.packet_tree = ttk.Treeview(packet_list_frame, columns=("Source", "Destination", "Protocol"),
                                        show="headings")
        self.packet_tree.heading("Source", text="Source")
        self.packet_tree.heading("Destination", text="Destination")
        self.packet_tree.heading("Protocol", text="Protocol")
        self.packet_tree.grid(row=0, column=0, sticky="nsew")
        packet_list_frame.grid_rowconfigure(0, weight=1)
        packet_list_frame.grid_columnconfigure(0, weight=1)

        # Add scrollbar to the Treeview
        tree_scrollbar = ttk.Scrollbar(packet_list_frame, orient="vertical", command=self.packet_tree.yview)
        tree_scrollbar.grid(row=0, column=1, sticky="ns")
        self.packet_tree.configure(yscrollcommand=tree_scrollbar.set)

        # Bind click event to the Treeview
        self.packet_tree.bind("<ButtonRelease-1>", self.on_packet_click)

        # Create a frame for packet content
        packet_content_frame = ttk.Frame(self.paned_window)
        self.paned_window.add(packet_content_frame, weight=1)

        # Create scrollable text area for displaying packet content
        self.content_area = scrolledtext.ScrolledText(packet_content_frame, wrap=tk.WORD, font=custom_font)
        self.content_area.grid(row=0, column=0, sticky="nsew")
        packet_content_frame.grid_rowconfigure(0, weight=1)
        packet_content_frame.grid_columnconfigure(0, weight=1)

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
        self.global_dns_cache: dict[str, str] = load_dictionary_from_json("app_memory/global_DNS_cache.json")
        self.local_dns_cache: dict[str, str] = load_dictionary_from_json("app_memory/local_DNS_cache.json")
        self.packets = []  # Store captured packets

        create_memory_dir()

    def get_domain_name(self, ip: str) -> str:
        """
        Perform a reverse DNS lookup for the given IP address.
        Uses a cache to store previous lookups for efficiency.
        """
        domain_name = ""
        address = ipaddress.ip_address(ip)
        if address.is_private:
            if ip in self.local_dns_cache:
                return self.local_dns_cache[ip]
            try:
                domain_name = socket.gethostbyaddr(ip)[0]
            except socket.herror:
                domain_name = "unknown local"
            self.local_dns_cache[ip] = domain_name

        elif address.is_global:
            if ip in self.global_dns_cache:
                return self.global_dns_cache[ip]
            try:
                domain_name = socket.gethostbyaddr(ip)[0]
            except socket.herror:
                domain_name = "unknown"
            self.global_dns_cache[ip] = domain_name

        return domain_name
        # known IPs to do

    def start_sniffing(self) -> None:
        """
        Start the packet sniffing process in a separate thread.
        """
        self.is_sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.sniff_thread = threading.Thread(target=self.sniff_packets, daemon=True)
        self.sniff_thread.start()

    def stop_sniffing(self) -> None:
        """
        Stop the packet sniffing process.
        """

        self.is_sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def sniff_packets(self) -> None:
        sniff(prn=self.packet_callback, store=0, stop_filter=lambda x: not self.is_sniffing)

    def packet_callback(self, packet) -> None:
        if IP in packet:
            # Extract IP layer information
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            proto = packet[IP].proto

            # Determine protocol
            if proto == 6:
                proto_name = "TCP"
            elif proto == 17:
                proto_name = "UDP"
            else:
                proto_name = "Other"

            # Perform reverse DNS lookups
            src_domain = self.get_domain_name(ip_src)
            dst_domain = self.get_domain_name(ip_dst)

            # Add packet to the Treeview
            packet_id = self.packet_tree.insert("", "end", values=(
                                                f"{ip_src} ({src_domain})", f"{ip_dst} ({dst_domain})", proto_name))

            # Store the packet for later viewing
            self.packets.append((packet_id, packet))

            # Ensure the latest packet is visible
            self.packet_tree.see(packet_id)

    def on_packet_click(self, event) -> None:
        item = self.packet_tree.selection()[0]
        packet_index = self.packet_tree.index(item)
        if 0 <= packet_index < len(self.packets):
            _, packet = self.packets[packet_index]
            self.display_packet_content(packet)

    def display_packet_content(self, packet) -> None:
        # Clear previous content
        self.content_area.delete(1.0, tk.END)

        # Display packet summary
        self.content_area.insert(tk.END, packet.summary() + "\n\n")

        # Display detailed packet information
        self.content_area.insert(tk.END, packet.show(dump=True))

    def close_app(self) -> None:
        save_dictionary_to_json(self.global_dns_cache, "app_memory/global_DNS_cache.json")
        save_dictionary_to_json(self.local_dns_cache, "app_memory/local_DNS_cache.json")
        self.is_sniffing = False
