import tkinter as tk
from tkinter import ttk
import SniffingGUI


class MenuWindow:
    def __init__(self, master: tk.Tk):
        self.master = master

        self.configure_window()
        self.main_frame = tk.Frame(master=master)
        self.main_frame.pack()
        self.option_label = tk.Label(master=self.main_frame, text="options", font="Arial")
        self.option_label.grid()
        self.sniff_label = ttk.Button(master=self.main_frame, text="sniff packets", command=self.open_new_window)
        self.sniff_label.grid()

    def configure_window(self) -> None:
        self.master.title("WireFish")
        self.master.geometry("500x350")
        self.master.minsize(60, 50)
        self.master.iconbitmap("app_images/logoICO.ico")

    def open_new_window(self) -> None:
        new_window = tk.Toplevel(self.master)
        sniffer = SniffingGUI.MainWindow(new_window)
        new_window.protocol("WM_DELETE_WINDOW", sniffer.close_app)
