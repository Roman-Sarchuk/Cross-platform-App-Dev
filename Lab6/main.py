import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import webbrowser
import string
from enum import Enum


class Application(tk.Tk):
    class CountingType(Enum):
        CHARACTER = "Символів",
        WORD = "Слів",
        PUNCTUATION = "Знаків пунктуації",
        ENTER = "Нових рядків (\\n)",
        TAB = "Табуляцій (\\t)",
        ALL = "Все"


    def __init__(self):
        super().__init__()

        # --- data ---
        self.menu_command_data = {
            "file": [
                ("Новий", self.new_file),
                ("Відкрити", self.open_file),
                ("Зберегти", self.save_file),
                ("Зберегти як", self.save_as_file),
                (tk.SEPARATOR, None),
                ("Вихід", self.quit),
            ],
            "edit": [
                ("Скасувати", lambda: self.text_area.event_generate("<<Undo>>")),
                ("Повторити", lambda: self.text_area.event_generate("<<Redo>>")),
                (tk.SEPARATOR, None),
                ("Виділити все", self.select_all),
                ("Очистити все", self.clear_all),
                (tk.SEPARATOR, None),
                ("Вирізати", lambda: self.text_area.event_generate("<<Cut>>")),
                ("Копіювати", lambda: self.text_area.event_generate("<<Copy>>")),
                ("Вставити", lambda: self.text_area.event_generate("<<Paste>>")),
                ("Видалити", self.delete_text),
            ],
            "counting": [
                (self.CountingType.CHARACTER.value[0], lambda: self.count_text_stats(self.CountingType.CHARACTER)),
                (self.CountingType.WORD.value[0], lambda: self.count_text_stats(self.CountingType.WORD)),
                (self.CountingType.PUNCTUATION.value[0], lambda: self.count_text_stats(self.CountingType.PUNCTUATION)),
                (self.CountingType.ENTER.value[0], lambda: self.count_text_stats(self.CountingType.ENTER)),
                (self.CountingType.TAB.value[0], lambda: self.count_text_stats(self.CountingType.TAB)),
                (tk.SEPARATOR, None),
                (self.CountingType.ALL.value, lambda: self.count_text_stats(self.CountingType.ALL)),
            ],
            "background": [
                ("Скинути (білий)", lambda: self.set_bg_color("white")),
                ("Світло-сірий", lambda: self.set_bg_color("#f0f0f0")),
                ("Темний (нічний)", lambda: self.set_bg_color("#4F4F4F")),
                ("Кремовий (як папір)", lambda: self.set_bg_color("#fdf6e3")),
                ("Нічний синій", lambda: self.set_bg_color("#303087")),
                ("Оливковий", lambda: self.set_bg_color("#d8e2dc")),
            ],
            "info": [
                ("Про програму", self.show_about),
                ("Про автора", lambda: self.open_site("https://roman-sarchuk.github.io/Explic/author.html")),
                (tk.SEPARATOR, None),
                ("Сайт навчального закладу", lambda: self.open_site("https://lpnu.ua/")),
                ("Про бібліотеку Tkinter", lambda: self.open_site("https://docs.python.org/uk/3.13/library/tkinter.html")),
                ("Про Python", lambda: self.open_site("https://www.python.org/")),
            ]
        }
        self.toolbar_button_data = [
            ("🆕", self.new_file),  # Новий
            ("📂", self.open_file),  # Відкрити
            ("💾", self.save_file),  # Зберегти
            ("✂️", lambda: self.text_area.event_generate("<<Cut>>")),  # Вирізати
            ("📋", lambda: self.text_area.event_generate("<<Copy>>")),  # Копіювати
            ("📥", lambda: self.text_area.event_generate("<<Paste>>")),  # Вставити
            ("↩️", lambda: self.text_area.event_generate("<<Undo>>")),  # Скасувати
            ("↪️", lambda: self.text_area.event_generate("<<Redo>>")),  # Повторити
            ("🗑️", self.delete_text),  # Видалити
            ("🔢", lambda: self.count_text_stats(self.CountingType.ALL)),  # Підрахувати
        ]

        # --- vars ---
        self.word_wrap_var = tk.BooleanVar()
        self.font_var = tk.StringVar()

        # --- win setting ---
        self.title("Простий текстовий редактор")
        self.geometry("800x600")

        # --- build interface ---
        self.text_area = tk.Text(self, wrap='word', undo=True)
        self.text_area.pack(expand=True, fill='both')

        self.create_menu()
        self.create_toolbar()

    def __fill_menu(self, menu, menu_key):
        for (text, command) in self.menu_command_data[menu_key]:
            if text == tk.SEPARATOR:
                menu.add_separator()
            else:
                menu.add_command(label=text, command=command)

    def create_menu(self):
        menu_bar = tk.Menu(self)
        self.config(menu=menu_bar)

        # --- File ---
        file_menu = tk.Menu(menu_bar, tearoff=0)
        self.__fill_menu(file_menu, "file")
        menu_bar.add_cascade(label="Файл", menu=file_menu)

        # --- Edit ---
        edit_menu = tk.Menu(menu_bar, tearoff=0)
        self.__fill_menu(edit_menu, "edit")
        menu_bar.add_cascade(label="Редагувати", menu=edit_menu)

        # --- Format ---
        format_menu = tk.Menu(menu_bar, tearoff=0)
        format_menu.add_checkbutton(label="Переносити рядки", variable=self.word_wrap_var, command=self.toggle_wrap)

        font_menu = tk.Menu(format_menu, tearoff=0)
        self.font_var.set("Arial")
        fonts = ["Arial", "Courier", "Times", "Verdana"]
        for font in fonts:
            font_menu.add_radiobutton(label=font, variable=self.font_var, value=font, command=self.change_font)

        format_menu.add_cascade(label="Шрифт", menu=font_menu)
        menu_bar.add_cascade(label="Формат", menu=format_menu)

        # --- Background ---
        bg_menu = tk.Menu(menu_bar, tearoff=0)
        self.__fill_menu(bg_menu, "background")
        menu_bar.add_cascade(label="Теми", menu=bg_menu)

        # --- Counting ---
        counting_menu = tk.Menu(menu_bar, tearoff=0)
        self.__fill_menu(counting_menu, "counting")
        menu_bar.add_cascade(label="Підрахунок", menu=counting_menu)

        # --- Info ---
        info_menu = tk.Menu(menu_bar, tearoff=0)
        self.__fill_menu(info_menu, "info")
        menu_bar.add_cascade(label="Довідка", menu=info_menu)

    def create_toolbar(self):
        toolbar = tk.Frame(self, bd=1, relief=tk.RAISED)

        for (text, command) in self.toolbar_button_data:
            btn = ttk.Button(toolbar, text=text, command=command)
            btn.pack(side=tk.LEFT, padx=2, pady=2)

        toolbar.pack(side=tk.TOP, fill=tk.X)

    # --- commands ---
    def new_file(self):
        self.text_area.delete(1.0, tk.END)

    def open_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, "r", encoding="utf-8") as file:
                self.text_area.delete(1.0, tk.END)
                self.text_area.insert(tk.END, file.read())

    def save_file(self):
        try:
            with open(self.current_file, "w", encoding="utf-8") as file:
                file.write(self.text_area.get(1.0, tk.END))
        except AttributeError:
            self.save_as_file()

    def save_as_file(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                 filetypes=[("Text Files", "*.txt")])
        if file_path:
            self.current_file = file_path
            self.save_file()

    def delete_text(self):
        self.text_area.delete("sel.first", "sel.last")

    def toggle_wrap(self):
        self.text_area.config(wrap='word' if self.word_wrap_var.get() else 'none')

    def change_font(self):
        self.text_area.config(font=(self.font_var.get(), 12))

    @staticmethod
    def show_about():
        messagebox.showinfo("Про програму", "Додаток для створення та редагування текстів на Tkinter.\n(С) Львів 2025")

    @staticmethod
    def open_site(url):
        webbrowser.open_new_tab(url)

    def count_text_stats(self, counting_type: CountingType):
        text = self.text_area.get("1.0", "end-1c")

        switch_dict = {
            self.CountingType.CHARACTER: len(text),
            self.CountingType.WORD: len(text.split()),
            self.CountingType.PUNCTUATION: sum(1 for c in text if c in string.punctuation),
            self.CountingType.ENTER: text.count('\n'),
            self.CountingType.TAB: text.count('\t')
        }

        if counting_type == self.CountingType.ALL:
            stats_message = ""

            for key, total in switch_dict.items():
                stats_message += f"{key.value[0]}: {total}\n"
        else:
            total = switch_dict[counting_type]

            stats_message = f"{counting_type.value[0]}: {total}"

        messagebox.showinfo("Статистика тексту", stats_message)

    def select_all(self):
        self.text_area.tag_add("sel", "1.0", "end-1c")
        self.text_area.mark_set("insert", "1.0")
        self.text_area.see("insert")

    def clear_all(self):
        self.text_area.delete("1.0", "end")

    def set_bg_color(self, color):
        self.text_area.config(bg=color)


if __name__ == "__main__":
    app = Application()
    app.mainloop()
