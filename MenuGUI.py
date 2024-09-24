import tkinter as tk
from tkinter import ttk
import WifiSniffingGUI


class MenuWindow:
    def __init__(self, master: tk.Tk):
        self.master = master

        self.configure_window()
        self.main_frame = tk.Frame(master=master)
        self.main_frame.pack()
        self.option_label = tk.Label(master=self.main_frame, text="options", font="Arial")
        self.option_label.grid()
        self.sniff_label = ttk.Button(master=self.main_frame, text="sniff wifi", command=self.open_new_window)
        self.sniff_label.grid()

    def configure_window(self):
        self.master.title("WireFish")
        self.master.geometry("500x350")
        self.master.minsize(60, 50)
        self.master.iconbitmap("app_images/logoICO.ico")

    def open_new_window(self) -> WifiSniffingGUI.MainWindow:
        new_window = tk.Toplevel(self.master)
        sniffer = WifiSniffingGUI.MainWindow(new_window)
        new_window.protocol("WM_DELETE_WINDOW", sniffer.close_app)
        return sniffer
