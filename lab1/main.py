import tkinter as tk
from tkinter import messagebox


class KeypadLock(tk.Toplevel):
    CORRECT_CODE = "3442"

    def __init__(self, master):
        super().__init__(master)
        self.master = master

        self.title("Кодовий замок")
        self.resizable(width=False, height=False)

        self.code = ""

        # Code field
        self.frame_display = tk.Frame(self)
        self.frame_display.pack(fill="x", padx=5, pady=5)

        self.label_display = tk.Label(self.frame_display, bg="white", font=("Arial", 14), height=2)
        self.label_display.pack(fill="x", padx=2, pady=2)

        # Keyboard
        self.frame_keyboard = tk.Frame(self)
        self.frame_keyboard.pack(fill="both", padx=5, pady=5)

        self.create_buttons()

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
        if len(self.code) >= 4:
            return
        self.code += digit
        self.label_display.config(text=self.code, fg="black")

    def handle_back(self):
        """Delete the last character"""
        self.code = self.code[:-1]
        self.label_display.config(text=self.code)

    def handle_enter(self):
        """Check the code for correctness"""
        if self.code == self.CORRECT_CODE:
            self.label_display.config(text="Вірно!", fg="green")
        else:
            self.label_display.config(text="Невірно!", fg="red")
        self.code = ""


class App(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Додаток")
        self.geometry("400x300")

        # Створення фреймів для різних сторінок
        self.login_frame = tk.Frame(self)
        self.main_menu_frame = tk.Frame(self)

        # Налаштування сторінки входу
        self.setup_login_page()

        # Показати сторінку входу при запуску
        self.show_login_page()

    def setup_login_page(self):
        # Очищення фрейму
        for widget in self.login_frame.winfo_children():
            widget.destroy()

        # Напис по середині
        login_label = tk.Label(
            self.login_frame,
            text="Вхід",
            font=("Arial", 16)
        )
        login_label.pack(expand=True)

        # Кнопка увійти
        login_button = tk.Button(
            self.login_frame,
            text="Увійти",
            command=self.show_main_menu
        )
        login_button.pack(expand=True)

    def setup_main_menu_page(self):
        # Очищення фрейму
        for widget in self.main_menu_frame.winfo_children():
            widget.destroy()

        # Напис головне меню
        main_menu_label = tk.Label(
            self.main_menu_frame,
            text="Головне Меню",
            font=("Arial", 16)
        )
        main_menu_label.pack(expand=True)

        # Напис з цифрами
        numbers_label = tk.Label(
            self.main_menu_frame,
            text="1 2 3 4",
            font=("Arial", 14)
        )
        numbers_label.pack(expand=True)

        # Поле для вводу
        input_entry = tk.Entry(
            self.main_menu_frame,
            width=30
        )
        input_entry.pack(expand=True)

        # Кнопка зберегти
        save_button = tk.Button(
            self.main_menu_frame,
            text="Зберегти",
            command=self.save_data
        )
        save_button.pack(expand=True)

        # Кнопка виходу
        logout_button = tk.Button(
            self.main_menu_frame,
            text="Вийти",
            command=self.show_login_page
        )
        logout_button.pack(expand=True)

    def show_login_page(self):
        # Сховати головне меню
        self.main_menu_frame.pack_forget()

        # Показати сторінку входу
        self.login_frame.pack(expand=True, fill=tk.BOTH)

    def show_main_menu(self):
        # Сховати сторінку входу
        self.login_frame.pack_forget()

        # Створити та показати головне меню
        self.setup_main_menu_page()
        self.main_menu_frame.pack(expand=True, fill=tk.BOTH)

    def save_data(self):
        # Приклад функції збереження (можна змінити)
        messagebox.showinfo("Збережено", "Дані успішно збережено!")


if __name__ == "__main__":
    app = App()
    app.mainloop()
