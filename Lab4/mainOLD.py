import tkinter as tk
from tkinter import ttk

root = tk.Tk()
root.title("Line Editor")

dash_var = tk.StringVar()

x1_var = tk.DoubleVar()
y1_var = tk.DoubleVar()
x2_var = tk.DoubleVar()
y2_var = tk.DoubleVar()
x3_var = tk.DoubleVar()
y3_var = tk.DoubleVar()
fill_var = tk.StringVar()
width_var = tk.StringVar()


frame = tk.Frame()
frame.pack(side="left")


frame_x1_y1 = tk.LabelFrame(
    frame,
    text="First point:",
    bd=1,
    relief="solid",
    )
frame_x1_y1.pack()

frame_x1 = tk.LabelFrame(
    frame_x1_y1,
    text="x:",
    bd=1,
    relief="solid",
    )
frame_x1.pack()

spinbox_x1 = tk.Spinbox(
    frame_x1,
    textvariable=x1_var,
    from_=0,
    to=500,
    width=5,
    )
spinbox_x1.pack(fill="x", padx=2, pady=2)

frame_y1 = tk.LabelFrame(
    frame_x1_y1,
    text="y:",
    bd=1,
    relief="solid",
    )
frame_y1.pack()

spinbox_y1 = tk.Spinbox(
    frame_y1,
    textvariable=y1_var,
    from_=0,
    to=500,
    width=5,
    )
spinbox_y1.pack()


frame_x2_y2 = tk.LabelFrame(
    frame,
    text="First point:",
    bd=1,
    relief="solid",
    )
frame_x2_y2.pack()

frame_x2 = tk.LabelFrame(
    frame_x2_y2,
    text="x:",
    bd=1,
    relief="solid",
    )
frame_x2.pack()

spinbox_x2 = tk.Spinbox(
    frame_x2,
    textvariable=x2_var,
    from_=0,
    to=500,
    width=5,
    )
spinbox_x2.pack(fill="x", padx=2, pady=2)

frame_y2 = tk.LabelFrame(
    frame_x2_y2,
    text="y:",
    bd=1,
    relief="solid",
    )
frame_y2.pack()

spinbox_y2 = tk.Spinbox(
    frame_y2,
    textvariable=y2_var,
    from_=0,
    to=500,
    width=5,
    )
spinbox_y2.pack()


frame_x3_y3 = tk.LabelFrame(
    frame,
    text="First point:",
    bd=1,
    relief="solid",
    )
frame_x3_y3.pack()

frame_x3 = tk.LabelFrame(
    frame_x3_y3,
    text="x:",
    bd=1,
    relief="solid",
    )
frame_x3.pack()

spinbox_x3 = tk.Spinbox(
    frame_x3,
    textvariable=x3_var,
    from_=0,
    to=500,
    width=5,
    )
spinbox_x3.pack(fill="x", padx=2, pady=2)

frame_y3 = tk.LabelFrame(
    frame_x3_y3,
    text="y:",
    bd=1,
    relief="solid",
    )
frame_y3.pack()

spinbox_y3 = tk.Spinbox(
    frame_y3,
    textvariable=y3_var,
    from_=0,
    to=500,
    width=5,
    )
spinbox_y3.pack()


frame_width = tk.LabelFrame(
    frame,
    text="Width:",
    bd=1,
    relief="solid",
    )
frame_width.pack()

scale_width = tk.Scale(
    frame_width,
    variable=width_var,
    from_=1,
    to=9,
    resolution=1,
    tickinterval=2,
    orient="horizontal",
    length=50,
    sliderlength=16,
    )
scale_width.pack()

frame_fill = tk.LabelFrame(
    frame,
    text="Fill color:",
    bd=1,
    relief="solid",
    )
frame_fill.pack()

combo_fill = ttk.Combobox(
    frame_fill,
    textvariable=fill_var,
    height=5,
    values=("orange", "blue", "red", "green", "yellow"),
    width=5,
    )
combo_fill.pack()


def handle_draw():
    canvas.create_line(
        x1_var.get(),
        y1_var.get(),
        x2_var.get(),
        y2_var.get(),
        width=width_var.get(),
        fill=fill_var.get(),
        )
    canvas.create_line(
        x2_var.get(),
        y2_var.get(),
        x3_var.get(),
        y3_var.get(),
        width=width_var.get(),
        fill=fill_var.get(),
    )
    canvas.create_line(
        x3_var.get(),
        y3_var.get(),
        x1_var.get(),
        y1_var.get(),
        width=width_var.get(),
        fill=fill_var.get(),
    )


button = tk.Button(
    frame,
    text="Draw",
    bg="orange",
    command=handle_draw,
    )
button.pack()

button = tk.Button(
    frame,
    text="Clear",
    command=lambda: canvas.delete("all"),
    )
button.pack(fill="x", padx=2, pady=2)

frame_canvas = tk.LabelFrame(
    text="Canvas area",
    bd=1,
    relief="solid",
    )
frame_canvas.pack(side="left")

canvas = tk.Canvas(
    frame_canvas,
    bg="white",
    width=500,
    height=500
    )
canvas.pack(
    fill="both",
    expand=True,
    )

x1_var.set(0)
y1_var.set(0)
x2_var.set(0)
y2_var.set(0)
x3_var.set(0)
y3_var.set(0)
width_var.set(1)
fill_var.set("orange")

root.mainloop()
