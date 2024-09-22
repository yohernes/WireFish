import tkinter as tk
import atexit
import WifiSniffingGUI
import MenuGUI


def main() -> None:
    """ Create the main window and start the application"""
    root = tk.Tk()
    main_screen = MenuGUI.MenuWindow(root)
    # sniffer = WifiSniffingGUI.MainWindow(root)
    # atexit.register(sniffer.close_app)
    root.mainloop()


if __name__ == "__main__":
    main()
