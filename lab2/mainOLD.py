import tkinter as tk

VALUES = ("Guitar", "Piano", "Violin")
root = tk.Tk()

# Entry ---------------------------------------------------------------
entry_var = tk.StringVar()

entry = tk.Entry(
    bg="white",
    textvariable=entry_var
)
entry.pack()

# Radiobutton  --------------------------------------------------------
radiobutton_var = tk.StringVar()

radiobutton_frame = tk.LabelFrame(
    root,
    text="Radiobutton",
    bd=1,
    relief="solid",
)
radiobutton_frame.pack()

radiobuttons = []
for value in VALUES:
    radiobuttons.append(
        tk.Radiobutton(
            radiobutton_frame,
            variable=radiobutton_var,
            value=value,
            text=value,
        )
    )
    radiobuttons[-1].pack()

radiobutton_var.set(VALUES[0])

# Checkbutton  --------------------------------------------------------
checkbutton_vars = [tk.BooleanVar() for _ in range(len(VALUES))]

checkbutton_frame = tk.LabelFrame(
    root,
    text="Checkbutton",
    bd=1,
    relief="solid",
)
checkbutton_frame.pack()

checkbuttons = []
for value, var in zip(VALUES, checkbutton_vars):
    checkbuttons.append(
        tk.Checkbutton(
            checkbutton_frame,
            variable=var,
            onvalue=True,
            offvalue=False,
            text=value,
        )
    )
    checkbuttons[-1].pack()

# Spinbox -------------------------------------------------------------
spinbox_var = tk.StringVar()

spinbox = tk.Spinbox(
    textvariable=spinbox_var,
    values=VALUES,
    state="readonly",
)
spinbox.pack()

# OptionMenu ----------------------------------------------------------
optionmenu_var = tk.StringVar()

optionmenu = tk.OptionMenu(
    root,
    optionmenu_var,
    *VALUES,
)
optionmenu.pack()

optionmenu_var.set(VALUES[0])

# Label -------------------------------------------------------------
label = tk.Label(bg="white")
label.pack()


def get_values():
    quantity = dict.fromkeys(VALUES, 0)

    if entry_var.get() in quantity:
        quantity[entry_var.get()] += 1

    quantity[radiobutton_var.get()] += 1

    for value, var in zip(VALUES, checkbutton_vars):
        if var.get():
            quantity[value] += 1

    quantity[spinbox_var.get()] += 1

    quantity[optionmenu_var.get()] += 1

    label.config(text=", ".join([f"{k}={v}" for k, v in quantity.items()]))


button = tk.Button(
    text="Get Values",
    command=get_values,
)
button.pack()

root.mainloop()
