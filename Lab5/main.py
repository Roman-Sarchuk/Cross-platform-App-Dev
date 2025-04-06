import tkinter as tk
from tkinter.font import Font


class WidgetConfigMenu(tk.Toplevel):
    def __init__(self, master, entry):
        super().__init__(master)
        self.entry = entry

        # --- root setting ---
        self.transient(master)
        self.grab_set()

        # --- build interface ---
        tk.Button(self, text="Close", command=self.destroy).pack()


class Application(tk.Tk):
    START_TEXT = "\"Help Others & Let Them Help You\""
    ENTRY_PARAMETERS = [
        [
            "Basic",
            {
                "bg": {"type": 'COLOR', "description": "Фоновий колір поля введення"},
                "fg": {"type": 'COLOR', "description": "Колір тексту"},
                "bd": {"type": int, "description": "Товщина рамки"},
                "width": {"type": int, "description": "Ширина в символах"},
                "font": {
                    "type": Font, "description": "Шрифт тексту"},
                "justify": {"type": ['left', 'center', 'right'], "description": "Вирівнювання тексту"},
                "relief": {"type": ['flat', 'raised', 'sunken', 'groove', 'ridge'], "description": "Тип рамки"},
            },
        ],
        [
            "Behavior",
            {
                "state": {"type": ['normal', 'disabled', 'readonly'], "description": "Стан поля"},
                "show": {"type": str, "description": "Символ для прихованого вводу (наприклад, паролі)"},
                "cursor": {
                    "type": ["hand2", "arrow", "circle", "clock", "cross", "dotbox", "exchange", "fleur", "heart",
                             "man", "mouse", "pirate", "plus", "shuttle", "sizing", "spider", "spraycan", "star",
                             "target", "tcross", "trek", "watch", "xterm"], "description": "Курсор при наведенні"
                },
            }
        ],
        [
            "State",
            {
                "disabledbackground": {"type": 'COLOR', "description": "Фон, коли state='disabled'"},
                "disabledforeground": {"type": 'COLOR', "description": "Текст, коли state='disabled'"},
                "readonlybackground": {"type": 'COLOR', "description": "Фон при state='readonly'"},
            }
        ],
        [
            "Focus",
            {
                "highlightbackground": {"type": 'COLOR', "description": "Колір рамки при втраті фокуса"},
                "highlightcolor": {"type": 'COLOR', "description": "Колір рамки при фокусі"},
                "highlightthickness": {"type": int, "description": "Товщина рамки фокуса"},
            }
        ],
        [
            "Cursor",
            {
                "insertbackground": {"type": 'COLOR', "description": "Колір курсору (блималки)"},
                "insertborderwidth": {"type": int, "description": "	Ширина обводки курсору"},
                "insertwidth": {"type": int, "description": "Товщина вертикального курсору"},
            }
        ],
        [
            "Selection",
            {
                "selectbackground": {"type": 'COLOR', "description": "Колір фону виділеного тексту"},
                "selectborderwidth": {"type": int, "description": "Товщина рамки навколо виділеного тексту"},
                "selectforeground": {"type": 'COLOR', "description": "Колір тексту в середині виділення"},
            }
        ]
    ]

    def __init__(self):
        super().__init__()

        # --- root setting ---
        self.title("Line Editor")
        self.geometry("350x180")
        self.minsize(300, 130)

        # --- build interface ---
        frame_main = tk.Frame(self)
        frame_main.pack(fill="both", expand=True)

        # Configure grid weights to allow centering
        frame_main.grid_columnconfigure(0, weight=1)  # Left column expands
        frame_main.grid_columnconfigure(2, weight=1)  # Right column expands
        frame_main.grid_rowconfigure(0, weight=1)  # Top row expands
        frame_main.grid_rowconfigure(3, weight=1)  # Bottom row expands

        self.entry = tk.Entry(frame_main, width=30, justify="center", font=("Arial", 12))
        self.entry.insert(tk.END, self.START_TEXT)
        self.entry.grid(row=1, column=1, padx=10, pady=10)

        button = tk.Button(
            frame_main, command=lambda: WidgetConfigMenu(self, entry=self.entry),
            text="Config", width=15, height=2, relief="groove",
            bg="#D47815", fg="white", activebackground="#EF9009")
        button.grid(row=2, column=1, padx=10, pady=10)


if __name__ == "__main__":
    app = Application()
    app.mainloop()
