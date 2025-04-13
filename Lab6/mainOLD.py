import tkinter as tk

root = tk.Tk()

border = tk.IntVar(value=0)
bg_color = tk.StringVar(value="white")

# Menu bar ==================================
menu_bar = tk.Menu(root)

menu_file = tk.Menu(menu_bar, tearoff=0)
menu_file.add_command(
    label="New",
    accelerator="Cntr+N",
    command=lambda: label.config(text="New")
    )
menu_file.add_separator()

menu_export = tk.Menu(menu_file, tearoff=0)
menu_export.add_command(
    label="PDF",
    command=lambda: label.config(text="PDF")
    )
menu_export.add_command(
    label="DOCX",
    command=lambda: label.config(text="DOCX")
    )
menu_file.add_cascade(
    label="Export",
    menu=menu_export
    )
menu_bar.add_cascade(
    label="File",
    menu=menu_file
    )

menu_edit = tk.Menu(menu_bar, tearoff=0)
menu_edit.add_checkbutton(
    label="Autosave",
    variable=border,
    onvalue=1,
    offvalue=0,
    command=lambda: label.config(bd=border.get())
    )
menu_bar.add_cascade(
    label="Edit",
    menu=menu_edit
    )

menu_view = tk.Menu(menu_bar, tearoff=0)
menu_view.add_radiobutton(
    label="White",
    variable=bg_color,
    value="white",
    command=lambda:label.config(bg=bg_color.get())
    )
menu_view.add_radiobutton(
    label="Light Yellow",
    variable=bg_color,
    value="lightyellow",
    command=lambda:label.config(bg=bg_color.get())
    )
menu_view.add_radiobutton(
    label="Light Blue",
    variable=bg_color,
    value="lightblue",
    command=lambda:label.config(bg=bg_color.get())
    )
menu_bar.add_cascade(
    label="View",
    menu=menu_view
    )
root.config(menu=menu_bar)

# Toolbar ===================================
frame_toolbar = tk.Frame(root, bd=1, relief="raise")
frame_toolbar.pack(anchor="w")

button_file = tk.Button(
    frame_toolbar,
    text="\U0001F4C4",
    width=2,
    height=1,
    relief="flat",
    command=lambda: label.config(text="New")
    )
button_file.pack(side="left", padx=2, pady=2)

separator = tk.Frame(
    frame_toolbar,
    width=2,
    height=20,
    bg="gray",
    )
separator.pack(side="left", padx=5, pady=2)

button_export = tk.Button(
    frame_toolbar,
    text="P",
    width=2,
    height=1,
    relief="flat",
    command=lambda: label.config(text="PDF")
    )
button_export.pack(side="left", padx=2, pady=2)

label = tk.Label(
    text="Default",
    bg="white",
    width=20,
    height=4,
    bd=0,
    relief="solid",
    )
label.pack(fill="x", expand=True, padx=5, pady=5)

root.mainloop()

