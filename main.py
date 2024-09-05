import tkinter as tk
from tkinter import scrolledtext
from scapy.all import *
import threading

class PacketSniffer:
    def __init__(self, master):
        self.master = master
        master.title("Simple Packet Sniffer")

        self.text_area = scrolledtext.ScrolledText(master, wrap=tk.WORD, width=80, height=20)
        self.text_area.pack(padx=10, pady=10)

        self.start_button = tk.Button(master, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(pady=5)

        self.stop_button = tk.Button(master, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(pady=5)

        self.is_sniffing = False

    def packet_callback(self, packet):
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            proto = packet[IP].proto

            if proto == 6:
                proto_name = "TCP"
            elif proto == 17:
                proto_name = "UDP"
            else:
                proto_name = "Other"

            info = f"IP Packet: {ip_src} -> {ip_dst}, Proto: {proto_name}\n"
            self.text_area.insert(tk.END, info)
            self.text_area.see(tk.END)

    def start_sniffing(self):
        self.is_sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.sniff_thread = threading.Thread(target=self.sniff_packets)
        self.sniff_thread.start()

    def stop_sniffing(self):
        self.is_sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def sniff_packets(self):
        sniff(prn=self.packet_callback, store=0, stop_filter=lambda x: not self.is_sniffing)


root = tk.Tk()
sniffer = PacketSniffer(root)
root.mainloop()