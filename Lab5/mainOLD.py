import tkinter as tk
import tkinter.ttk as ttk

top_level = None

root = tk.Tk()
text_var = tk.StringVar()
family_var = tk.StringVar()
size_var = tk.IntVar()
weight_var = tk.StringVar()


def handle_close():
    global top_level
    top_level.grab_release()
    top_level.destroy()
    top_level = None


def handle_ok():
    label.config(
        text=text_var.get(),
        font=(family_var.get(), int(size_var.get()), weight_var.get()),
    )
    handle_close()


def handle_cancel():
    handle_close()


def handle_adjust():
    global top_level
    if top_level is not None:
        return
    top_level = tk.Toplevel(root)
    top_level.title("Adjust")
    top_level.resizable(False, False)
    top_level.protocol("WM_DELETE_WINDOW", handle_close)

    family, size, weight = label.cget("font").split(" ")

    frame_text = tk.LabelFrame(
        top_level,
        text="Text:"
    )
    frame_text.pack()

    entry_text = tk.Entry(
        frame_text,
        textvariable=text_var,
    )
    entry_text.pack()
    text_var.set(label.cget("text"))

    frame_family = tk.LabelFrame(
        top_level,
        text="Font Family:"
    )
    frame_family.pack()

    combo_family = ttk.Combobox(
        frame_family,
        textvariable=family_var,
        values=("Arial", "Times", "Verdana"),
        width=15,
        state="readonly",
    )
    combo_family.pack()
    family_var.set(family)

    frame_size = tk.LabelFrame(
        top_level,
        text="Font Size:"
    )
    frame_size.pack()

    spin_size = tk.Spinbox(
        frame_size,
        textvariable=size_var,
        values=("8", "9", "10", "11", "12", "13", "14", "15"),
        width=15,
        state="readonly",
    )
    spin_size.pack()
    size_var.set(int(size))

    frame_weight = tk.LabelFrame(
        top_level,
        text="Font Weight:"
    )
    frame_weight.pack()

    combo_weight = ttk.Combobox(
        frame_weight,
        textvariable=weight_var,
        values=("normal", "bold"),
        width=15,
        state="readonly",
    )
    combo_weight.pack()
    weight_var.set(weight)

    button_ok = tk.Button(
        top_level,
        text="Ok",
        width=15,
        command=handle_ok,
    )
    button_ok.pack()

    button_cancel = tk.Button(
        top_level,
        text="Cancel",
        width=15,
        command=handle_cancel,
    )
    button_cancel.pack()

    top_level.grab_set()


label = tk.Label(
    bg="white",
    text="Enter text...",
    font=("Arial", 10, "normal"),
    anchor="center",
)
label.pack()

button_adjust = tk.Button(
    text="Adjust",
    width=10,
    command=handle_adjust,
)
button_adjust.pack()

root.mainloop()

