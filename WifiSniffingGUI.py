import tkinter as tk
from tkinter import scrolledtext, font, ttk
from scapy.layers.inet import IP, TCP, UDP, ICMP
import threading
from MemoryManager import *
from typing import List, Any
import PacketSniffer
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP
from tkinter import messagebox

class MainWindow:
    def __init__(self, master: tk.Toplevel):
        self.memory = Memory()

        self.settings_visible = False
        self.setting_panel = None
        self.stop_button = None
        self.button_frame = None
        self.nav_bar = None
        self.start_button = None
        self.settings_image = None
        self.setting_button = None
        self.content_area = None
        self.tree_scrollbar = None
        self.packet_tree = None
        self.packet_list_frame = None
        self.paned_window = None
        self.master = master
        self.sniff_thread: threading.Thread | None = None

        self.configure_window()
        self.setup_nav_bar()
        self.setup_main_frame()
        self.setup_settings_panel()

        self.is_sniffing: bool = False
        self.packets: List[Any] = []  # Store captured packets

        master.iconbitmap("app_images/logoICO.ico")

    def configure_window(self):
        self.master.title("WireFish")
        self.master.geometry("1000x700")
        self.master.minsize(600, 400)
        self.master.grid_rowconfigure(0, weight=0)
        self.master.grid_rowconfigure(1, weight=1)  # Main content row
        self.master.grid_columnconfigure(0, weight=1)

    def setup_settings_panel(self):
        self.setting_panel = ttk.Frame(self.master, width=1000, style="Settings.TFrame")
        self.setting_panel.grid(row=0, column=1, rowspan=2, sticky="nsew")
        self.setting_panel.grid_remove()  # Hide initially

        # Prevent the settings panel from shrinking
        self.setting_panel.grid_propagate(False)

        # Add some sample content to the settings panel
        ttk.Label(self.setting_panel, text="Settings", font=("Arial", 16)).pack(pady=10, padx=40)
        ttk.Button(self.setting_panel, text="clear local DNS cache",
                   command=lambda: self.memory.delete_local_cache()).pack(pady=5)
        ttk.Button(self.setting_panel, text="clear global DNS cache",
                   command=lambda: self.memory.delete_global_cache()).pack(pady=5)
        ttk.Button(self.setting_panel, text="Option 3").pack(pady=5)

        # Create a style for the settings frame
        style = ttk.Style()
        style.configure("Settings.TFrame", background="#f0f0f0")

    def setup_nav_bar(self):
        self.nav_bar = ttk.Frame(self.master)
        self.nav_bar.grid(row=0, column=0, sticky="ew", padx=10, pady=5)

        self.button_frame = ttk.Frame(self.nav_bar)
        self.button_frame.pack(side=tk.LEFT)

        self.start_button = ttk.Button(self.button_frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(self.button_frame,
                                      text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        self.settings_image = tk.PhotoImage(file="app_images/settings_icon.png")
        self.setting_button = ttk.Button(self.button_frame, image=self.settings_image, command=self.settings_click)
        self.setting_button.pack(side=tk.RIGHT)

    def setup_main_frame(self):
        main_frame = ttk.Frame(self.master)
        main_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)
        main_frame.grid_rowconfigure(0, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)

        custom_font = font.Font(family="Courier", size=10)

        self.paned_window = ttk.PanedWindow(main_frame, orient=tk.VERTICAL)
        self.paned_window.grid(row=0, column=0, sticky="nsew")

        self.setup_packet_list_frame()
        self.setup_packet_content_frame(custom_font)

    def settings_click(self):
        if self.settings_visible:
            self.setting_panel.grid_remove()
            self.settings_visible = False
        else:
            self.setting_panel.grid()
            self.settings_visible = True
            self.setting_panel.pack_propagate(False)

    def setup_packet_list_frame(self):
        self.packet_list_frame = ttk.Frame(self.paned_window)
        self.paned_window.add(self.packet_list_frame, weight=1)

        self.packet_tree = ttk.Treeview(self.packet_list_frame,
                                        columns=("Source", "Destination", "Protocol"), show="headings")
        self.packet_tree.heading("Source", text="Source")
        self.packet_tree.heading("Destination", text="Destination")
        self.packet_tree.heading("Protocol", text="Protocol")
        # self.packet_tree.heading("Info", text="Info")
        self.packet_tree.grid(row=0, column=0, sticky="nsew")
        self.packet_list_frame.grid_rowconfigure(0, weight=1)
        self.packet_list_frame.grid_columnconfigure(0, weight=1)

        self.tree_scrollbar = ttk.Scrollbar(self.packet_list_frame, orient="vertical", command=self.packet_tree.yview)
        self.tree_scrollbar.grid(row=0, column=1, sticky="ns")
        self.packet_tree.configure(yscrollcommand=self.tree_scrollbar.set)

        self.packet_tree.bind("<ButtonRelease-1>", self.on_packet_click)

    def setup_packet_content_frame(self, custom_font):
        packet_content_frame = ttk.Frame(self.paned_window)
        self.paned_window.add(packet_content_frame, weight=1)

        self.content_area = scrolledtext.ScrolledText(packet_content_frame, wrap=tk.WORD, font=custom_font)
        self.content_area.grid(row=0, column=0, sticky="nsew")
        packet_content_frame.grid_rowconfigure(0, weight=1)
        packet_content_frame.grid_columnconfigure(0, weight=1)

    def start_sniffing(self) -> None:
        """
        Start the packet sniffing process in a separate thread.
        """
        self.is_sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.sniff_thread = threading.Thread(target=lambda: PacketSniffer.sniff_packets(self), daemon=True)
        self.sniff_thread.start()

    def stop_sniffing(self) -> None:
        """
        Stop the packet sniffing process.
        """

        self.is_sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

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
            src_domain = PacketSniffer.get_domain_name(self.memory, ip_src)
            dst_domain = PacketSniffer.get_domain_name(self.memory, ip_dst)

            # Add packet to the Treeview
            packet_id = self.packet_tree.insert("", "end", values=(
                                                f"{ip_src} ({src_domain})",
                                                f"{ip_dst} ({dst_domain})", proto_name))

            # Store the packet for later viewing
            self.packets.append((packet_id, packet))

            # Ensure the latest packet is visible
            self.packet_tree.see(packet_id)

    def packet_callback1(self, packet):
        # Initialize variables
        source = destination = info = ""

        if ARP in packet:
            source = packet[ARP].hwsrc
            destination = packet[ARP].hwdst
            protocol = "ARP"
            if packet[ARP].op == 1:  # ARP request
                info = f"Who has {packet[ARP].pdst}? Tell {packet[ARP].psrc}"
            elif packet[ARP].op == 2:  # ARP reply
                info = f"{packet[ARP].psrc} is at {packet[ARP].hwsrc}"
        elif IP in packet:
            source = packet[IP].src
            destination = packet[IP].dst
            if TCP in packet:
                protocol = "TCP"
                sport, dport = packet[TCP].sport, packet[TCP].dport
                flags = packet[TCP].flags
                info = f"{sport} → {dport} "
                if flags.S and not flags.A:
                    info += "[SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM=1 TSval=2037676640 TSecr=0 WS=128"
                elif flags.S and flags.A:
                    info += "[SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1460"
                elif flags.A and not flags.P:
                    info += "[ACK] Seq=1 Ack=1 Win=65535 Len=0"
                elif flags.P and flags.A:
                    info += (f"[PSH, ACK] Seq={packet[TCP].seq} Ack={packet[TCP].ack} "
                             f"Win=65535 Len={len(packet[TCP].payload)}")
                elif flags.F:
                    info += "[FIN, ACK] Seq=1 Ack=1 Win=65535 Len=0"
                else:
                    info += f"[{flags}] {len(packet[TCP].payload)} bytes"
            elif UDP in packet:
                protocol = "UDP"
                sport, dport = packet[UDP].sport, packet[UDP].dport
                info = f"{sport} → {dport} Len={len(packet[UDP].payload)}"
            elif ICMP in packet:
                protocol = "ICMP"
                icmp_type = packet[ICMP].type
                icmp_code = packet[ICMP].code
                if icmp_type == 8:
                    info = "Echo (ping) request"
                elif icmp_type == 0:
                    info = "Echo (ping) reply"
                else:
                    info = f"Type={icmp_type}, Code={icmp_code}"
            else:
                protocol = "Other IP"
                info = f"Protocol={packet[IP].proto}"
        else:
            protocol = packet.name
            info = packet.summary()

        # Add packet to the Treeview
        packet_id = self.packet_tree.insert("", "end", values=(source, destination, protocol, info))

        # Store the packet for later viewing
        self.packets.append((packet_id, packet))

        # Ensure the latest packet is visible
        self.packet_tree.see(packet_id)

    def packet_callback2(self, packet):
        # Initialize variables
        source = destination = protocol = info = ""

        # Ethernet handling
        if Ether in packet:
            """protocol = "Ethernet"
            source = packet[Ether].src
            destination = packet[Ether].dst
            info = f"Type: {packet[Ether].type}"""

        # ARP handling
        if ARP in packet:
            protocol = "ARP"
            source = packet[ARP].hwsrc
            destination = packet[ARP].hwdst
            if packet[ARP].op == 1:  # ARP request
                info = f"Who has {packet[ARP].pdst}? Tell {packet[ARP].psrc}"
            elif packet[ARP].op == 2:  # ARP reply
                info = f"{packet[ARP].psrc} is at {packet[ARP].hwsrc}"

        # IP handling (IPv4 and IPv6)
        ip_layer = None
        if IP in packet:
            ip_layer = IP
        elif IPv6 in packet:
            ip_layer = IPv6

        if ip_layer:
            source = packet[ip_layer].src
            destination = packet[ip_layer].dst

            # Resolve domain names
            src_domain = PacketSniffer.get_domain_name(self.memory, source)
            dst_domain = PacketSniffer.get_domain_name(self.memory, destination)

            source = f"{source} ({src_domain})" if src_domain else source
            destination = f"{destination} ({dst_domain})" if dst_domain else destination

            # TCP handling
            if TCP in packet:
                sport, dport = packet[TCP].sport, packet[TCP].dport
                flags = packet[TCP].flags
                protocol = "TCP"
                info = f"{sport} → {dport} "

                # Determine application layer protocol
                if dport == 443 or sport == 443:
                    protocol = "HTTPS-TCP"
                elif dport == 80 or sport == 80:
                    protocol = "HTTP-TCP"

                # Flag information
                if flags.S and not flags.A:
                    info += "[SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM=1 TSval=2037676640 TSecr=0 WS=128"
                elif flags.S and flags.A:
                    info += "[SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1460"
                elif flags.A and not flags.P:
                    info += "[ACK] Seq=1 Ack=1 Win=65535 Len=0"
                elif flags.P and flags.A:
                    info += (f"[PSH, ACK] Seq={packet[TCP].seq} Ack={packet[TCP].ack}"
                             f" Win=65535 Len={len(packet[TCP].payload)}")
                elif flags.F:
                    info += "[FIN, ACK] Seq=1 Ack=1 Win=65535 Len=0"
                else:
                    info += f"[{flags}] {len(packet[TCP].payload)} bytes"

            # UDP handling
            elif UDP in packet:
                sport, dport = packet[UDP].sport, packet[UDP].dport
                protocol = "UDP"
                info = f"{sport} → {dport} Len={len(packet[UDP].payload)}"

                # Determine application layer protocol
                if dport == 53 or sport == 53:
                    protocol = "DNS-UDP"

            # ICMP handling
            elif ICMP in packet:
                protocol = "ICMP"
                icmp_type = packet[ICMP].type
                icmp_code = packet[ICMP].code
                if icmp_type == 8:
                    info = "Echo (ping) request"
                elif icmp_type == 0:
                    info = "Echo (ping) reply"
                else:
                    info = f"Type={icmp_type}, Code={icmp_code}"

            # Other IP protocols
            else:
                protocol = f"Other IP (proto={packet[ip_layer].proto})"
                info = (f"Next Header: "
                        f"{packet[ip_layer].nh}") if ip_layer == IPv6 else (f"Protocol: "
                                                                            f"{packet[ip_layer].proto}")

        # Non-IP packets
        else:
            protocol = packet.name
            info = packet.summary()

        # Add packet to the Treeview
        packet_id = self.packet_tree.insert("", "end", values=(source, destination, protocol, info))

        # Store the packet for later viewing
        self.packets.append((packet_id, packet))

        # Ensure the latest packet is visible
        self.packet_tree.see(packet_id)

    def on_packet_click(self, event) -> None:
        region = self.packet_tree.identify("region", event.x, event.y)
        if region == "heading":
            return

        selection = self.packet_tree.selection()
        if not selection:
            # just to be sure
            return

        item = selection[0]
        packet_index = self.packet_tree.index(item)

        if 0 <= packet_index < len(self.packets):
            _, packet = self.packets[packet_index]
            self.display_packet_content(packet)
        else:
            print(f"Packet index {packet_index} out of range")

    def display_packet_content(self, packet) -> None:
        # Clear previous content
        self.content_area.delete(1.0, tk.END)

        # Display packet summary
        self.content_area.insert(tk.END, packet.summary() + "\n\n")

        # Display detailed packet information
        self.content_area.insert(tk.END, packet.show(dump=True))

    def close_app(self) -> None:
        self.memory.save_dns_memory()
        self.is_sniffing = False
        if messagebox.askokcancel("Quit", "Do you want to close this window?"):
            self.master.destroy()  # Close the Toplevel window