import tkinter as tk
from tkinter import messagebox


class Application(tk.Tk):
    USERS = {
        "roman": "3442",
        "yura": "7777",
        "tom": "1234",
        "jerry": "4321"
    }

    def __init__(self):
        super().__init__()
        self.locker = None
        self.username = ""
        self.menus = {}

        # *** init win setting ***
        self.title("Application")
        self.geometry("500x300")
        self.minsize(300, 200)
        # *** **** *** ******* ***

        # *** login_menu components ***
        self.menus["login"] = tk.Frame(self)
        self.cur_menu = "login"

        # Configure grid weights to allow centering
        self.menus["login"].grid_columnconfigure(0, weight=1)  # Left column expands
        self.menus["login"].grid_columnconfigure(2, weight=1)  # Right column expands
        self.menus["login"].grid_rowconfigure(0, weight=1)  # Top row expands
        self.menus["login"].grid_rowconfigure(4, weight=1)  # Bottom row expands

        # init components
        self.login_label = tk.Label(self.menus["login"], text="Enter yor username", font=("Arial", 20))
        self.login_entry = tk.Entry(self.menus["login"], width=30, justify="center", font=("Arial", 12))
        self.login_button = tk.Button(self.menus["login"], text="Log In", command=self.log_in,
                                      width=15, height=2, bg="#4CAF50", fg="white")

        self.show_login_menu()
        # *** ********** ********** ***

        # *** main_menu components ***
        self.menus["main"] = tk.Frame(self)

        # Configure grid weights to allow centering
        self.menus["main"].grid_columnconfigure(0, weight=1)  # Left column expands
        self.menus["main"].grid_columnconfigure(2, weight=1)  # Right column expands
        self.menus["main"].grid_rowconfigure(0, weight=1)  # Top row expands
        self.menus["main"].grid_rowconfigure(3, weight=1)  # Bottom row expands

        # init components
        self.main_label = tk.Label(self.menus["main"], text="Hello, USER", font=("Arial", 24))
        self.main_button = tk.Button(self.menus["main"], text="Log Out", command=self.lock,
                                     width=15, height=2, bg="#b8473b", fg="white")
        # *** ********* ********** ***

    # *** login processing ***
    def log_in(self):
        self.username = self.login_entry.get().strip().lower()
        if not self.username:
            messagebox.showwarning("Warning", "Please enter a username!")
        elif self.username not in self.USERS:
            messagebox.showwarning("Warning", f"Incorrect username!")
        else:
            self.open_locker()

    def open_locker(self):
        # Check if KeyLock is already open
        if self.locker is None or not self.locker.winfo_exists():
            # If not open or was closed, create a new one
            self.locker = KeyLock(self, self.USERS[self.username])

            # Make the main window wait until KeyLock is closed
            self.wait_window(self.locker)
        else:
            # If already open, just focus on it
            self.locker.focus_force()

            # Optionally flash the window to get user's attention
            self.locker.attributes('-topmost', True)
            self.locker.attributes('-topmost', False)

    def unlock(self):
        self.show_main_menu()

    def lock(self):
        self.show_login_menu()
    # *** ***** ********** ***

    # *** menus ***
    def hide_cur_menu(self):
        self.menus[self.cur_menu].pack_forget()

    def show_login_menu(self):
        self.hide_cur_menu()
        self.cur_menu = "login"

        # show login_frame
        self.menus["login"].pack(fill=tk.BOTH, expand=True)

        # place components in the middle column (1) with padding
        self.login_label.grid(row=1, column=1, pady=(10, 5))
        self.login_entry.grid(row=2, column=1, pady=5)
        self.login_button.grid(row=3, column=1, pady=(5, 10))

    def show_main_menu(self):
        self.hide_cur_menu()
        self.cur_menu = "main"

        # show main_frame
        self.menus["main"].pack(fill=tk.BOTH, expand=True)

        # place components in the middle column (1) with padding
        self.main_label.config(text=f"Hello, {self.username.capitalize()}!")
        self.main_label.grid(row=1, column=1, pady=(10, 5))
        self.main_button.grid(row=2, column=1, pady=(5, 10))
    # *** ***** ***


class KeyLock(tk.Toplevel):
    CODE_LEN = 4

    def __init__(self, master, code):
        super().__init__(master)
        self.master = master

        # init win setting
        self.title("KeyLock")
        self.resizable(width=False, height=False)

        # initial widgets
        validation = self.register(self.__validate_number)
        self.entry = tk.Entry(self, validate="key", validatecommand=(validation, "%P"), font=("Arial", 14),
                              justify="center", width=10, bd=10)
        self.entry.pack(fill="x", padx=5, pady=(5, 0))

        self.frame_keyboard = tk.Frame(self)
        self.frame_keyboard.pack(fill="both", padx=5, pady=5)

        self.create_buttons()

        # other values
        self.CORRECT_CODE = code

    def __validate_number(self, new_value):
        # Allow empty string or digits only
        if len(new_value) <= self.CODE_LEN and (new_value == "" or new_value.isdigit()):
            return True
        return False

    def create_buttons(self):
        """Create the digital buttons & control buttons"""
        for i, digit in enumerate("789456123"):
            row, col = divmod(i, 3)
            button = tk.Button(self.frame_keyboard, width=5, text=digit, command=lambda d=digit: self.handle_digit(d))
            button.grid(row=row, column=col, padx=2, pady=2)

        button_back = tk.Button(self.frame_keyboard, width=5, text="Back", bg="yellow", command=self.handle_back)
        button_back.grid(row=3, column=0, padx=2, pady=2)

        button_0 = tk.Button(self.frame_keyboard, width=5, text="0", command=lambda: self.handle_digit("0"))
        button_0.grid(row=3, column=1, padx=2, pady=2)

        button_enter = tk.Button(self.frame_keyboard, width=5, text="Enter", bg="lightgreen", command=self.handle_enter)
        button_enter.grid(row=3, column=2, padx=2, pady=2)

    def handle_digit(self, digit):
        """Process numeric input"""
        self.entry.insert(tk.END, digit)

    def handle_back(self):
        """Delete the last character"""
        self.entry.delete(len(self.entry.get()) - 1, tk.END)

    def handle_enter(self):
        """Check the code for correctness"""
        if self.entry.get() == self.CORRECT_CODE:
            self.master.unlock()
            self.destroy()
        else:
            messagebox.showwarning("Warning", f"Incorrect pin code!")


if __name__ == "__main__":
    app = Application()
    app.mainloop()
