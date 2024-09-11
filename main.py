import tkinter as tk
from tkinter import scrolledtext, font
from scapy.all import sniff
from scapy.layers.inet import IP
import threading
import socket
import ipaddress
from MemoryManager import *
import atexit
from PacketSniffer import PacketSniffer


# Create the main window and start the application
root = tk.Tk()
sniffer = PacketSniffer(root)
atexit.register(lambda: sniffer.close_app())
root.mainloop()
