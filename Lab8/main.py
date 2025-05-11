import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
import difflib

# Colors
LGRAY = '#343c4c'
DBLUE = '#09131c'
DAQUA = '#25465E'
# Values
ROLES = [
    "Sheriff", "Doctor", "Detective", "Bodyguard", "Mayor", "Veteran",
    "Lookout", "Spy", "Medium", "Escort", "Vigilante", "Investigator", "Tracker", "Journalist",
    "Godfather", "Mafioso", "Consigliere", "Blackmailer", "Framer", "Janitor", "Hypnotist", "Disguiser",
    "Jester", "Executioner", "Serial Killer", "Arsonist", "Witch", "Survivor", "Amnesiac", "Plaguebearer"
]
ROOM_IDS = ["123", "Y4U", "qwerty", "0123456789"]


class CustomTitleBar(tk.Frame):
    def __init__(self, toplevel, root, *args, **kwargs):
        super().__init__(toplevel, *args, pady=8, **kwargs)
        self.root = root
        self.toplevel = toplevel

        self.build_interface()

        # Прив'язка подій для перетягування
        self.bind("<Button-1>", self.start_move)
        self.bind("<B1-Motion>", self.on_motion)

        self.root.bind("<Map>", self.on_map)
        self.root.bind("<Unmap>", self.on_unmap)

    def build_interface(self):
        # --- imgs ---
        app_icon_src = Image.open("imgs\\logo.png")
        self.app_icon = ImageTk.PhotoImage(app_icon_src.resize((35, 35)))

        close_icon_src = Image.open("imgs\\x.png")
        self.close_icon = ImageTk.PhotoImage(close_icon_src.resize((20, 20)))

        minimise_icon_src = Image.open("imgs\\minus.png")
        self.minimise_icon = ImageTk.PhotoImage(minimise_icon_src.resize((20, 20)))

        # --- widgets ---
        icon = tk.Label(self, bg=DAQUA, image=self.app_icon)

        self.title = tk.Label(self, text="App Title", font=("consolas", 20), fg="white", bg=DAQUA)

        close_button = tk.Button(
            self, text=' × ', command=self.close_window,
            bg=DAQUA, padx=2, pady=2,font=("calibri", 13), bd=0, fg='white',
            highlightthickness=0, activebackground=DAQUA, image=self.close_icon
        )
        minimize_button = tk.Button(
            self, text=' 🗕 ', command=self.minimize_window,
            bg=DAQUA, padx=2, pady=2, bd=0, fg='white',font=("calibri", 13),
            highlightthickness=0, activebackground=DAQUA, image=self.minimise_icon
        )

        # --- packs ---
        icon.pack(side=tk.LEFT, padx=5)
        close_button.pack(side=tk.RIGHT, ipadx=12, ipady=8, padx=5)
        minimize_button.pack(side=tk.RIGHT, ipadx=12, ipady=8)
        self.title.pack(side=tk.TOP, anchor="center")

        # --- binds ---
        self.title.bind("<Button-1>", self.start_move)
        self.title.bind("<B1-Motion>", self.on_motion)
        icon.bind("<Button-1>", self.start_move)
        icon.bind("<B1-Motion>", self.on_motion)
        close_button.bind('<Enter>', lambda event: close_button.config(bg="red"))
        close_button.bind('<Leave>', lambda event: close_button.config(bg=DAQUA))
        minimize_button.bind('<Enter>', lambda event: minimize_button.config(bg=DBLUE))
        minimize_button.bind('<Leave>', lambda event: minimize_button.config(bg=DAQUA))

    def start_move(self, event):
        self.toplevel.x = event.x
        self.toplevel.y = event.y

    def on_motion(self, event):
        x = event.x_root - self.toplevel.x
        y = event.y_root - self.toplevel.y
        self.toplevel.geometry(f"+{x}+{y}")

    def minimize_window(self):
        self.root.iconify()

    def close_window(self):
        self.root.destroy()

    def on_map(self, event):
        self.toplevel.overrideredirect(False)
        self.toplevel.deiconify()
        self.toplevel.lift()
        self.toplevel.attributes("-topmost", True)  # тимчасово зробити завжди поверх
        self.toplevel.after(1, lambda: self.toplevel.attributes("-topmost", False))
        self.toplevel.after(1, lambda: self.toplevel.overrideredirect(True))

    def on_unmap(self, event):
        self.toplevel.overrideredirect(False)
        self.toplevel.iconify()
        self.toplevel.overrideredirect(True)

    def set_title(self, text):
        self.title.config(text=text)


class Application(tk.Toplevel):
    def __init__(self, root):
        super().__init__(root)
        self.root = root
        self.x = self.winfo_x()
        self.y = self.winfo_y()

        self.geometry("400x600")
        self.overrideredirect(True)
        self.configure(bg=DBLUE)

        self.field_params = {
            "nickname": {"vcmd": self.validate_nickname, "validate": "all", "var": tk.StringVar(), "err_var": tk.StringVar()},
            "role": {"vcmd": self.validate_role, "validate": "all", "var": tk.StringVar(), "err_var": tk.StringVar()},
            "room_id": {"vcmd": self.validate_room_id, "validate": "all", "var": tk.StringVar(), "err_var": tk.StringVar()},
            "age": {"vcmd": self.validate_age, "validate": "all", "var": tk.StringVar(), "err_var": tk.StringVar()}
        }
        self.build_interface()

    def build_interface(self):
        custom_title_bar = CustomTitleBar(toplevel=self, root=self.root, bg=DAQUA, relief="raised", bd=0, height=30)
        custom_title_bar.pack(side=tk.TOP, fill=tk.X)
        custom_title_bar.set_title("JoinForm")

        # --- App content container ---
        container = tk.Frame(self, bg=DBLUE)
        container.pack(fill=tk.BOTH, expand=True)

        # set column weights for resizing
        container.columnconfigure(0, weight=3)
        container.columnconfigure(1, weight=2)
        container.columnconfigure(2, weight=3)

        # set row weights for resizing
        for i in range(len(self.field_params) + 2):  # title , len(fields), button
            container.rowconfigure(i, weight=1)

        # --- Title ---
        title_frame = tk.Frame(container, bg=DBLUE)
        title_frame.grid(row=0, column=0, columnspan=3, sticky="s")
        title_frame.columnconfigure(0, weight=1)

        title_img_src = Image.open("imgs/title.png")
        self.title_img = ImageTk.PhotoImage(title_img_src.resize((335,80)))

        title = tk.Label(title_frame, image=self.title_img, bg=DBLUE)
        title.grid(column=0, row=0, pady=(20, 10), sticky=tk.NSEW)

        # --- Fields ---
        row = 1
        for key, params in self.field_params.items():
            field_container = tk.Frame(container, bg=DBLUE)
            field_container.grid(column=1, row=row, pady=10, sticky=tk.NSEW)
            row += 1

            label = tk.Label(field_container, text=key, font=("consolas", 15), fg="white", bg=DBLUE)
            entry = tk.Entry(
                field_container, validate="all", validatecommand=(self.root.register(params["vcmd"]), "%P"),
                textvariable=params["var"], bg=LGRAY, font=("consolas", 15), fg="white", insertbackground=DBLUE
            )
            err_label = tk.Label(
                field_container, textvariable=params["err_var"],
                bg=DBLUE, fg="red", font=("consolas", 8)
            )

            label.pack(anchor="w", fill=tk.X)
            entry.pack(anchor="w", fill=tk.X)
            err_label.pack(anchor="w", fill=tk.X)

        # --- Button ---
        button_frame = tk.Frame(container, bg=DBLUE)
        button_frame.grid(column=0, row=2, pady=20, sticky=tk.EW)

        submit_button = tk.Button(
            container, command=self.send_form,
            text="Join", font=("consolas", 12, "bold"),
            bg=LGRAY, fg="white", relief=tk.RAISED, bd=2, pady=5,
            activebackground=DAQUA,
        )
        submit_button.grid(column=1, row=len(self.field_params) + 2, ipadx=60, pady=(10, 15))

        # --- info button ---
        role_info_button = tk.Button(
            container, command=lambda: messagebox.showinfo("Role list", ", ".join(ROLES)),
            text="🛈", font=("consolas", 20, "bold"),
            fg="white", bg=DBLUE, relief=tk.FLAT, activebackground=DBLUE, activeforeground=DAQUA, borderwidth=0
        )
        role_info_button.grid(column=2, row=2)

        room_info_button = tk.Button(
            container, command=lambda: messagebox.showinfo("Room id list", ", ".join(ROOM_IDS)),
            text="🛈", font=("consolas", 20, "bold"),
            fg="white", bg=DBLUE, relief=tk.FLAT, activebackground=DBLUE, activeforeground=DAQUA, borderwidth=0
        )
        room_info_button.grid(column=2, row=3)

    def validate_nickname(self, value):
        if not value:
            self.field_params["nickname"]["err_var"].set("This field can't be empty")
        else:
            self.field_params["nickname"]["err_var"].set("")
        return True

    def validate_role(self, value):
        if not value:
            self.field_params["role"]["err_var"].set("This field can't be empty")
            return True

        if value in ROLES:
            self.field_params["role"]["err_var"].set("")
            return True

        if value.capitalize() in ROLES:
            self.field_params["role"]["err_var"].set("Enter in upper case")
            return True

        warning_message = f"Role '{value}' is not valid"

        suggestions = set(difflib.get_close_matches(value.capitalize(), ROLES, n=3, cutoff=0.6) + difflib.get_close_matches(value, ROLES, n=3, cutoff=0.6))
        if suggestions:
            warning_message += ";\nMaybe you mean: " + ", ".join(suggestions)

        self.field_params["role"]["err_var"].set(warning_message)
        return True

    def validate_room_id(self, value):
        if not value:
            self.field_params["room_id"]["err_var"].set("This field can't be empty")
            return True

        if self.varify_room_id(value):
            self.field_params["room_id"]["err_var"].set("")
            return True

        self.field_params["room_id"]["err_var"].set("This is not a valid room ID")
        return True

    def validate_age(self, value):
        if not value:
            self.field_params["age"]["err_var"].set("This field can't be empty")
            return True

        if not value.isdigit():
            self.field_params["age"]["err_var"].set("You have to enter a number")
            self.after(2000, lambda: self.field_params["age"]["err_var"].set(""))
            return False

        age = int(value)
        if 1 < age > 120:
            self.field_params["age"]["err_var"].set("Age must be between 1 and 120")
            self.after(2000, lambda: self.field_params["age"]["err_var"].set(""))
            return False
        else:
            self.field_params["age"]["err_var"].set("")

        return True

    @staticmethod
    def varify_room_id(room_id) -> bool:
        return room_id in ROOM_IDS

    def send_form(self):
        data_err = self.verify_form_data()

        if data_err:
            messagebox.showwarning("Request sending...", data_err)
            return

        data = ""
        for key, params in self.field_params.items():
            data += f"{key}: {params["var"].get()}\n"

        messagebox.showinfo("Request sending...", "Form sent successfully:\n" + data)

    def verify_form_data(self) -> str:
        for key, params in self.field_params.items():
            params["vcmd"](params["var"].get())
            err_var_text = params["err_var"].get()
            if err_var_text:
                return f"Warning:\n{err_var_text} in the '{key}' field!"

        return ""


if __name__ == "__main__":
    main_root = tk.Tk()
    main_root.attributes("-alpha", 0.0)
    app = Application(main_root)
    app.mainloop()
