import tkinter as tk

root = tk.Tk()
root.title("Кодовий замок")
root.resizable(width=False, height=False)

frame_display = tk.Frame(root)
frame_display.pack(fill="x", padx=5, pady=5)

label_display = tk.Label(frame_display, bg="white", font=("Arial", 14))
label_display.pack(fill="x", padx=2, pady=2)

frame_keyboard = tk.Frame(root)
frame_keyboard.pack(fill="both", padx=5, pady=5)

CORRECT_CODE = "1234"
code = ""


def handle_digit(digit):
    global code
    if len(code) >= 4:
        return
    code += digit
    label_display.config(text=code, fg="black")


def handle_back():
    global code
    code = code[:-1]
    label_display.config(text=code)


def handle_enter():
    global code
    if code == CORRECT_CODE:
        label_display.config(text="Вірно!", fg="green")
    else:
        label_display.config(text="Невірно!", fg="red")
    code = ""


for i, digit in enumerate("789456123"):
    row, col = divmod(i, 3)
    tk.Button(frame_keyboard, width=5, text=digit, command=lambda d=digit: handle_digit(d)).grid(row=row, column=col, padx=2, pady=2)

button_back = tk.Button(frame_keyboard, width=5, text="Back", bg="yellow", command=handle_back)
button_back.grid(row=3, column=0, padx=2, pady=2)

button_0 = tk.Button(frame_keyboard, width=5, text="0", command=lambda: handle_digit("0"))
button_0.grid(row=3, column=1, padx=2, pady=2)

button_enter = tk.Button(frame_keyboard, width=5, text="Enter", bg="lightgreen", command=handle_enter)
button_enter.grid(row=3, column=2, padx=2, pady=2)

root.mainloop()
