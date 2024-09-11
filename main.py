import tkinter as tk
import atexit
from PacketSniffer import PacketSniffer


# Create the main window and start the application
root = tk.Tk()
sniffer = PacketSniffer(root)
atexit.register(lambda: sniffer.close_app())
root.mainloop()
