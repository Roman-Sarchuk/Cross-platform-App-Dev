import tkinter as tk

grid_spacing = 40
figure_x = 0
figure_y = 0

root = tk.Tk()
root.title("Фігура на сітці")
root.geometry("600x400")

canvas = tk.Canvas(root, bg="white")
canvas.pack(fill="both", expand=True)

label = tk.Label(root, anchor="w", text="Start")
label.pack(fill="x", expand=False)

figure = canvas.create_rectangle(
    1, 1,
    30, 30,
    width=0,
    outline="black",  # змініть на потрібний колір згідно із вашим варіантом
    fill="green",  # змініть на потрібний колір згідно із вашим варіантом
)


def draw_grid():
    canvas.delete("grid")
    width = canvas.winfo_width()
    height = canvas.winfo_height()
    for x in range(0, width, grid_spacing):
        canvas.create_line(
            x, 0,
            x, height,
            fill="lightgray",
            tags="grid")
    for y in range(0, height, grid_spacing):
        canvas.create_line(
            0, y,
            width, y,
            fill="lightgray",
            tags="grid")


def handle_resize(event):
    draw_grid()


def show_coords(event):
    label.config(text=f"x: {event.x}, y: {event.y}")


def handle_up(event):
    x1, y1, x2, y2 = canvas.coords(figure)
    dy = -grid_spacing if (y1 > grid_spacing) else 0
    canvas.move(figure, 0, dy)


def handle_down(event):
    x1, y1, x2, y2 = canvas.coords(figure)
    y_max = canvas.winfo_height()
    dy = grid_spacing if (y2 < y_max - grid_spacing) else 0
    canvas.move(figure, 0, dy)


# Додані функції для керування пересуванням вліво і вправо
def handle_left(event):
    x1, y1, x2, y2 = canvas.coords(figure)
    dx = -grid_spacing if (x1 > grid_spacing) else 0
    canvas.move(figure, dx, 0)


def handle_right(event):
    x1, y1, x2, y2 = canvas.coords(figure)
    x_max = canvas.winfo_width()
    dx = grid_spacing if (x2 < x_max - grid_spacing) else 0
    canvas.move(figure, dx, 0)


def handle_start_drag(event):
    global figure_x, figure_y
    figure_x = event.x
    figure_y = event.y
    canvas.itemconfig(figure, width=2)
    canvas.config(cursor="hand2")
    canvas.tag_raise(figure)


def handle_on_drag(event):
    global figure_x, figure_y
    dx = event.x - figure_x
    dy = event.y - figure_y

    # Додана перевірка умови обмеження руху в межах полотна
    x1, y1, x2, y2 = canvas.coords(figure)
    width = canvas.winfo_width()
    height = canvas.winfo_height()

    # Перевірка, чи не виходить фігура за межі полотна
    if x1 + dx < 0:
        dx = -x1
    if y1 + dy < 0:
        dy = -y1
    if x2 + dx > width:
        dx = width - x2
    if y2 + dy > height:
        dy = height - y2

    canvas.move(figure, dx, dy)
    figure_x = event.x
    figure_y = event.y


def handle_end_drag(event):
    global figure_x, figure_y

    # Додано прилипання об'єкта до центру найближчої клітинки сітки
    snap_to_grid()

    canvas.itemconfig(figure, width=0)
    canvas.config(cursor="arrow")
    figure_x = 0
    figure_y = 0


def snap_to_grid():
    x1, y1, x2, y2 = canvas.coords(figure)

    # Обчислення центру фігури
    center_x = (x1 + x2) / 2
    center_y = (y1 + y2) / 2

    # Обчислення найближчого перетину сітки
    grid_x = round(center_x / grid_spacing) * grid_spacing
    grid_y = round(center_y / grid_spacing) * grid_spacing

    # Розмір фігури
    width = x2 - x1
    height = y2 - y1

    # Нові координати для центрування фігури на сітці
    new_x1 = grid_x - width / 2
    new_y1 = grid_y - height / 2
    new_x2 = grid_x + width / 2
    new_y2 = grid_y + height / 2

    # Оновлення координат фігури
    canvas.coords(figure, new_x1, new_y1, new_x2, new_y2)


def snap_to_target():
    # Початкове розміщення фігури на сітці при запуску
    x1, y1, x2, y2 = canvas.coords(figure)
    width = x2 - x1
    height = y2 - y1

    # Розміщення в початковій клітинці сітки
    grid_x = grid_spacing
    grid_y = grid_spacing

    new_x1 = grid_x - width / 2
    new_y1 = grid_y - height / 2
    new_x2 = grid_x + width / 2
    new_y2 = grid_y + height / 2

    canvas.coords(figure, new_x1, new_y1, new_x2, new_y2)


canvas.bind("<Configure>", handle_resize)
canvas.bind("<Motion>", show_coords)

root.bind("<KeyPress-Up>", handle_up)
root.bind("<KeyPress-Down>", handle_down)
# Додані прив'язки для керування пересуванням вліво і вправо
root.bind("<KeyPress-Left>", handle_left)
root.bind("<KeyPress-Right>", handle_right)

canvas.tag_bind(figure, "<Button-1>", handle_start_drag)
canvas.tag_bind(figure, "<B1-Motion>", handle_on_drag)
canvas.tag_bind(figure, "<ButtonRelease-1>", handle_end_drag)

# Викликаємо функцію після створення всіх компонентів
root.update()
draw_grid()
snap_to_target()

root.mainloop()