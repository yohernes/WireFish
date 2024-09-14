import tkinter as tk
import atexit
from GUI import MainWindow


def main() -> None:
    """ Create the main window and start the application"""
    root = tk.Tk()
    sniffer = MainWindow(root)
    atexit.register(sniffer.close_app)
    root.mainloop()


if __name__ == "__main__":
    main()
