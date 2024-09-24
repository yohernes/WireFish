import tkinter as tk
from tkinter import scrolledtext, font, ttk
import threading
from MemoryManager import *
from typing import List, Any
import PacketSniffer
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

    def configure_window(self) -> None:
        self.master.title("WireFish")
        self.master.geometry("1000x700")
        self.master.minsize(600, 400)
        self.master.grid_rowconfigure(0, weight=0)
        self.master.grid_rowconfigure(1, weight=1)  # Main content row
        self.master.grid_columnconfigure(0, weight=1)
        self.master.iconbitmap("app_images/logoICO.ico")

    def setup_settings_panel(self) -> None:
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

    def setup_nav_bar(self) -> None:
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

    def setup_main_frame(self) -> None:
        main_frame = ttk.Frame(self.master)
        main_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)
        main_frame.grid_rowconfigure(0, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)

        custom_font = font.Font(family="Courier", size=10)

        self.paned_window = ttk.PanedWindow(main_frame, orient=tk.VERTICAL)
        self.paned_window.grid(row=0, column=0, sticky="nsew")

        self.setup_packet_list_frame()
        self.setup_packet_content_frame(custom_font)

    def settings_click(self) -> None:
        if self.settings_visible:
            self.setting_panel.grid_remove()
            self.settings_visible = False
        else:
            self.setting_panel.grid()
            self.settings_visible = True
            self.setting_panel.pack_propagate(False)

    def setup_packet_list_frame(self) -> None:
        self.packet_list_frame = ttk.Frame(self.paned_window)
        self.paned_window.add(self.packet_list_frame, weight=1)

        self.packet_tree = ttk.Treeview(self.packet_list_frame,
                                        columns=("Source", "Destination", "Protocol", "Info"), show="headings")
        self.packet_tree.heading("Source", text="Source")
        self.packet_tree.heading("Destination", text="Destination")
        self.packet_tree.heading("Protocol", text="Protocol")
        self.packet_tree.heading("Info", text="Info")
        self.packet_tree.grid(row=0, column=0, sticky="nsew")
        self.packet_list_frame.grid_rowconfigure(0, weight=1)
        self.packet_list_frame.grid_columnconfigure(0, weight=1)

        self.tree_scrollbar = ttk.Scrollbar(self.packet_list_frame, orient="vertical", command=self.packet_tree.yview)
        self.tree_scrollbar.grid(row=0, column=1, sticky="ns")
        self.packet_tree.configure(yscrollcommand=self.tree_scrollbar.set)

        self.packet_tree.bind("<ButtonRelease-1>", self.on_packet_click)

    def setup_packet_content_frame(self, custom_font) -> None:
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
        source, destination, protocol, info = PacketSniffer.dissect_packet(packet, self.memory)
        self.insert_packet_into_tree(source, destination, protocol, info, packet)

    def insert_packet_into_tree(self, source, destination, protocol, info, packet) -> None:
        try:
            packet_id = self.packet_tree.insert("", "end", values=(source, destination, protocol, info))
            self.packets.append((packet_id, packet))
            self.packet_tree.see(packet_id)
        except tk.TclError as e:
            print(f"Error inserting into Treeview: {e}")

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
        if messagebox.askokcancel("Quit", "Do you want to close this window?"):
            self.memory.save_dns_memory()
            self.is_sniffing = False
            self.master.destroy()
