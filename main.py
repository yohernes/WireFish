import tkinter as tk
import MenuGUI


def main() -> None:
    """ Create the main window and start the application"""
    root = tk.Tk()
    main_screen = MenuGUI.MenuWindow(root)
    root.mainloop()


if __name__ == "__main__":
    main()
