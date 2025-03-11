import tkinter as tk
from tkinter import messagebox


class Application(tk.Tk):
    OBJECT_NAME = "Musical instrument"
    VALUES = ("Guitar", "Piano", "Violin")

    def __init__(self):
        super().__init__()
        self.quantity = {}
        self.menus = {
            "start": {"frame": tk.Frame(self), "widgets": []},
            "entry": {"frame": tk.Frame(self), "widgets": []},
            "radiobutton": {"frame": tk.Frame(self), "widgets": []},
            "checkbutton": {"frame": tk.Frame(self), "widgets": []},
            "spinbox": {"frame": tk.Frame(self), "widgets": []},
            "optionmenu": {"frame": tk.Frame(self), "widgets": []},
            "end": {"frame": tk.Frame(self), "widgets": []}
        }

        # variables
        self.entry_var = tk.StringVar()
        self.radiobutton_var = tk.StringVar()
        self.checkbutton_vars = [tk.BooleanVar() for _ in range(len(self.VALUES))]
        self.spinbox_var = tk.StringVar()
        self.optionmenu_var = tk.StringVar()

        # =-=-=-= initialization =-=-=-=
        # ----- start menu ----
        # Label
        self.menus["start"]["widgets"].append(
            tk.Label(self.menus["start"]["frame"],
                     text=f"Find your favorite {self.OBJECT_NAME}!",
                     font=("Arial", 16),
                     height=2)
        )
        # Button
        self.menus["start"]["widgets"].append(
            tk.Button(self.menus["start"]["frame"],
                      command=lambda: self.load_menu("entry"),
                      text="Let's Go",
                      width=15,
                      height=2,
                      bg="#4CAF50",
                      fg="white")
        )
        self.load_menu("start")

        # ----- entry menu ----
        # Label
        self.menus["entry"]["widgets"].append(
            tk.Label(self.menus["entry"]["frame"],
                     text=f"Which {self.OBJECT_NAME.lower()} do you prefer:\n{', '.join(self.VALUES).lower()}?",
                     font=("Arial", 12),
                     height=3)
        )
        # Entry
        self.menus["entry"]["widgets"].append(
            tk.Entry(self.menus["entry"]["frame"],
                     textvariable=self.entry_var,
                     bg="white")
        )
        # Frame-separator
        self.menus["entry"]["widgets"].append(
            tk.Frame(self.menus["entry"]["frame"],
                     height=10)
        )
        # Button
        self.menus["entry"]["widgets"].append(
            tk.Button(self.menus["entry"]["frame"],
                      command=self.validate_entry,
                      text="Next",
                      width=15,
                      height=2,
                      bg="#4CAF50",
                      fg="white")
        )

        # ----- radiobutton menu ----
        # LabelFrame
        radiobutton_frame = tk.LabelFrame(self.menus["radiobutton"]["frame"],
                                          text="Radiobutton",
                                          bd=1,
                                          relief="solid")
        self.menus["radiobutton"]["widgets"].append(
            radiobutton_frame
        )
        # Radiobuttons
        for value in self.VALUES:
            self.menus["radiobutton"]["widgets"].append(
                tk.Radiobutton(radiobutton_frame,
                               variable=self.radiobutton_var,
                               value=value,
                               text=value)
            )
        self.radiobutton_var.set(self.VALUES[0])
        # Frame-separator
        self.menus["radiobutton"]["widgets"].append(
            tk.Frame(self.menus["radiobutton"]["frame"],
                     height=10)
        )
        # Button
        self.menus["radiobutton"]["widgets"].append(
            tk.Button(self.menus["radiobutton"]["frame"],
                      command=lambda: self.load_menu("checkbutton"),
                      text="Next",
                      width=15,
                      height=2,
                      bg="#4CAF50",
                      fg="white")
        )

        # ----- checkbutton menu ----
        # LabelFrame
        checkbutton_frame = tk.LabelFrame(self.menus["checkbutton"]["frame"],
                                          text="Checkbutton",
                                          bd=1,
                                          relief="solid")
        self.menus["checkbutton"]["widgets"].append(
            checkbutton_frame
        )
        # Checkbutton
        for value, var in zip(self.VALUES, self.checkbutton_vars):
            self.menus["checkbutton"]["widgets"].append(
                tk.Checkbutton(checkbutton_frame,
                               variable=var,
                               onvalue=True,
                               offvalue=False,
                               text=value)
            )
        # Frame-separator
        self.menus["checkbutton"]["widgets"].append(
            tk.Frame(self.menus["checkbutton"]["frame"],
                     height=10)
        )
        # Button
        self.menus["checkbutton"]["widgets"].append(
            tk.Button(self.menus["checkbutton"]["frame"],
                      command=lambda: self.load_menu("spinbox"),
                      text="Next",
                      width=15,
                      height=2,
                      bg="#4CAF50",
                      fg="white")
        )

        # ----- spinbox menu ----
        # Spinbox
        self.menus["spinbox"]["widgets"].append(
            tk.Spinbox(self.menus["spinbox"]["frame"],
                       textvariable=self.spinbox_var,
                       values=self.VALUES,
                       state="readonly")
        )
        self.spinbox_var.set(self.VALUES[0])
        # Frame-separator
        self.menus["spinbox"]["widgets"].append(
            tk.Frame(self.menus["spinbox"]["frame"],
                     height=10)
        )
        # Button
        self.menus["spinbox"]["widgets"].append(
            tk.Button(self.menus["spinbox"]["frame"],
                      command=lambda: self.load_menu("optionmenu"),
                      text="Next",
                      width=15,
                      height=2,
                      bg="#4CAF50",
                      fg="white")
        )

        # ----- optionmenu menu ----
        # OptionMenu
        self.menus["optionmenu"]["widgets"].append(
            tk.OptionMenu(self.menus["optionmenu"]["frame"],
                          self.optionmenu_var,
                          *self.VALUES)
        )
        self.optionmenu_var.set(self.VALUES[0])
        # Frame-separator
        self.menus["optionmenu"]["widgets"].append(
            tk.Frame(self.menus["optionmenu"]["frame"],
                     height=10)
        )
        # Button
        self.menus["optionmenu"]["widgets"].append(
            tk.Button(self.menus["optionmenu"]["frame"],
                      command=lambda: self.show_result(),
                      text="Finish",
                      width=15,
                      height=2,
                      bg="#4CAF50",
                      fg="white")
        )

        # ----- end menu ----
        # Label
        self.menus["end"]["widgets"].append(
            tk.Label(self.menus["end"]["frame"],
                     text="Your favorite OBJECT_NAME is TRENDS!",
                     font=("Arial", 16),
                     height=2)
        )
        # Label
        self.menus["end"]["widgets"].append(
            tk.Label(self.menus["end"]["frame"],
                     text="RESULT",
                     font=("Arial", 16),
                     bg="white",
                     height=2)
        )
        # Frame-separator
        self.menus["end"]["widgets"].append(
            tk.Frame(self.menus["end"]["frame"],
                     height=10)
        )
        # Button
        self.menus["end"]["widgets"].append(
            tk.Button(self.menus["end"]["frame"],
                      command=lambda: self.load_menu("start"),
                      text="Try Again!",
                      width=15,
                      height=2,
                      bg="#4CAF50",
                      fg="white")
        )
        # =-=-=-= =-=-=-=-=-=-=- =-=-=-=

    def show_result(self):
        values = self.get_values()
        self.menus["end"]["widgets"][0].config(text=f"Your favorite {self.OBJECT_NAME} is {self.get_trend()}!")
        self.menus["end"]["widgets"][1].config(text=values)
        self.load_menu("end")

    def get_values(self) -> str:
        self.quantity = dict.fromkeys(self.VALUES, 0)

        if self.entry_var.get() in self.quantity:
            self.quantity[self.entry_var.get()] += 1

        self.quantity[self.radiobutton_var.get()] += 1

        for value, var in zip(self.VALUES, self.checkbutton_vars):
            if var.get():
                self.quantity[value] += 1

        self.quantity[self.spinbox_var.get()] += 1

        self.quantity[self.optionmenu_var.get()] += 1

        return ", ".join([f"{k}={v}" for k, v in self.quantity.items()])

    def get_trend(self) -> str:
        if self.quantity == {}:
            return "ERR: dict 'quantity' is empty"

        # find max values by quantity
        trend = []
        threshold = max(self.quantity.values())
        for k, v in self.quantity.items():
            if v >= threshold:
                trend.append(k)

        return ", ".join(trend)

    def validate_entry(self):
        if self.entry_var.get().strip().capitalize() in self.VALUES:
            self.load_menu("radiobutton")
        else:
            messagebox.showwarning("Warning", f"Incorrect name of the {self.OBJECT_NAME.lower()}!\nAvailable options: {', '.join(self.VALUES)}")

    def load_menu(self, menu_key_name):
        # pack frame
        for menu in self.menus.values():
            menu["frame"].pack_forget()
        self.menus[menu_key_name]["frame"].pack(fill=tk.BOTH, padx=20, pady=20)

        # pack widgets
        for widget in self.menus[menu_key_name]["widgets"]:
            widget.pack()


if __name__ == '__main__':
    app = Application()
    app.mainloop()
