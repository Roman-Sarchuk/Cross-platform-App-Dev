import tkinter as tk
from tkinter import messagebox


class LockerApp(tk.Tk):
    CORRECT_CODE = "1234"  # Код доступу

    def __init__(self):
        super().__init__()

        self.title("Головне вікно")
        self.geometry("300x200")

        # Перемінна для пароля
        self.password_var = tk.StringVar(value="******")

        # Кнопка для входу в систему
        self.btn_login = tk.Button(self, text="Увійти", command=self.open_locker, width=15, height=2)
        self.btn_login.pack(pady=20)

        # Поле для відображення пароля
        self.password_label = tk.Label(self, textvariable=self.password_var, font=("Arial", 12))
        self.password_label.pack(pady=5)

        # Поле для введення нового пароля
        self.new_password_entry = tk.Entry(self, font=("Arial", 12), show="*")
        self.new_password_entry.pack(pady=5)

        # Кнопка для збереження нового пароля (спочатку прихована)
        self.btn_save_password = tk.Button(self, text="Зберегти пароль", command=self.save_new_password)
        self.btn_save_password.pack(pady=5)
        self.btn_save_password.pack_forget()  # Ховаємо кнопку до успішного входу

    def open_locker(self):
        """Відкриває вікно кодового замка"""
        self.locker_window = LockerWindow(self)

    def unlock_main_window(self):
        """Розблоковує головне вікно після введення правильного коду"""
        self.password_var.set(self.CORRECT_CODE)  # Відображає пароль
        self.btn_save_password.pack()  # Показує кнопку збереження

    def save_new_password(self):
        """Зберігає новий пароль"""
        new_password = self.new_password_entry.get()
        if new_password:
            self.CORRECT_CODE = new_password  # Оновлює пароль
            self.password_var.set("******")  # Ховає пароль
            self.new_password_entry.delete(0, tk.END)  # Очищає поле введення
            self.btn_save_password.pack_forget()  # Ховає кнопку
            messagebox.showinfo("Успіх", "Пароль змінено!")


class LockerWindow(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.master = master

        self.title("Кодовий замок")
        self.geometry("250x300")
        self.resizable(False, False)

        self.code = ""

        # Поле для вводу пароля
        self.label_display = tk.Label(self, text="", font=("Arial", 14), bg="white", height=2)
        self.label_display.pack(fill="x", padx=5, pady=5)

        # Кнопки
        self.create_buttons()

    def create_buttons(self):
        """Створює клавіатуру для введення коду"""
        frame_keyboard = tk.Frame(self)
        frame_keyboard.pack()

        for i, digit in enumerate("7894561230"):
            row, col = divmod(i, 3)
            tk.Button(frame_keyboard, text=digit, width=5, command=lambda d=digit: self.handle_digit(d)).grid(row=row, column=col, padx=2, pady=2)

        tk.Button(frame_keyboard, text="Back", width=5, bg="yellow", command=self.handle_back).grid(row=3, column=0, padx=2, pady=2)
        tk.Button(frame_keyboard, text="Enter", width=5, bg="lightgreen", command=self.handle_enter).grid(row=3, column=2, padx=2, pady=2)

    def handle_digit(self, digit):
        """Обробляє введення цифр"""
        if len(self.code) < 4:
            self.code += digit
            self.label_display.config(text="●" * len(self.code))

    def handle_back(self):
        """Видаляє останній введений символ"""
        self.code = self.code[:-1]
        self.label_display.config(text="●" * len(self.code))

    def handle_enter(self):
        """Перевіряє правильність коду"""
        if self.code == self.master.CORRECT_CODE:
            self.destroy()  # Закриває вікно локера
            self.master.unlock_main_window()  # Розблоковує головне вікно
        else:
            self.label_display.config(text="Невірно!", fg="red")
            self.code = ""


if __name__ == "__main__":
    app = LockerApp()
    app.mainloop()
