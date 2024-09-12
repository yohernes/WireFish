import tkinter as tk
import atexit
from PacketSniffer import PacketSniffer


def main() -> None:
    """ Create the main window and start the application"""
    root = tk.Tk()
    sniffer = PacketSniffer(root)
    atexit.register(lambda: sniffer.close_app())
    root.mainloop()


if __name__ == "__main__":
    main()

