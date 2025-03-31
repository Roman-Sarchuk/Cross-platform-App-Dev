import tkinter as tk
from tkinter import ttk
import random

root = tk.Tk()
var_name = tk.StringVar()
var_price = tk.IntVar()
var_status = tk.StringVar()

frame_tree = tk.Frame()
frame_tree.pack()

scrollbar = tk.Scrollbar(
    frame_tree,
    orient="vertical",
    )
scrollbar.pack(side="right", fill="y")

tree = ttk.Treeview(
    frame_tree,
    columns=("name", "price", "status"),
    show="headings",
    selectmode="browse",
    height=10,
    yscrollcommand=scrollbar.set,
    )
tree.heading("name", text="Назва", anchor="w")
tree.heading("price", text="Ціна", anchor="w")
tree.heading("status", text="Статус", anchor="w")

tree.column("name", width=300, anchor="w", stretch=True)
tree.column("price", width=100, anchor="w", stretch=False)
tree.column("status", width=50, anchor="w", stretch=False)
tree.pack()

scrollbar.config(command=tree.yview)

for i in range(10):
    tree.insert("", "end", values=(f"Назва товару {i}", random.randint(1000, 5000), random.choice([True, False])))

tree.selection_set(tree.get_children()[0])

labelframe_entry = tk.LabelFrame()
labelframe_entry.pack()

entry_name = tk.Entry(
    labelframe_entry,
    textvariable=var_name,
    )
entry_name.pack()

scale_price = tk.Scale(
    labelframe_entry,
    variable=var_price,
    from_=0,
    to=10,
    tickinterval=5,
    resolution=1,
    orient="horizontal",
    )
scale_price.pack()

combo_status = ttk.Combobox(
    labelframe_entry,
    textvariable=var_status,
    values = ("True", "False"),
    )
combo_status.pack()

var_name.set("")
var_price.set(0)
var_status.set("False")

labelframe_button = tk.LabelFrame()
labelframe_button.pack()

def handle_insert():
    name = var_name.get()
    price = var_price.get()
    status = var_status.get()
    if name == "":
        return
    tree.insert("", "end", values=(name, price, status))
    var_name.set("")
    var_price.set(0)
    var_status.set("False")

button_insert = tk.Button(
    labelframe_button,
    text="Insert",
    command=handle_insert,
    )
button_insert.pack()

def handle_delete():
    selection = tree.selection()
    if not selection:
        return
    tree.delete(selection[0])

button_delete = tk.Button(
    labelframe_button,
    text="Delete",
    command=handle_delete,
    )
button_delete.pack()

def handle_get_item():
    selection = tree.selection()
    if not selection:
        return
    values = tree.item(selection[0]).get("values")
    var_name.set(values[0])
    var_price.set(values[1])
    var_status.set(values[2])

button_get = tk.Button(
    labelframe_button,
    text="Get",
    command=handle_get_item,
    )
button_get.pack()

def handle_set():
    selection = tree.selection()
    name = var_name.get()
    price = var_price.get()
    status = var_status.get()

    if name == "" or not selection:
        return
    tree.set(selection[0], column="name", value=name)
    tree.set(selection[0], column="price", value=price)
    tree.set(selection[0], column="status", value=status)
#   Додати налаштування ще двох стовпців

    var_name.set("")
    var_price.set(0)
    var_status.set("False")

button_set = tk.Button(
    labelframe_button,
    text="Set",
    command=handle_set,
    )
button_set.pack()

root.mainloop()
