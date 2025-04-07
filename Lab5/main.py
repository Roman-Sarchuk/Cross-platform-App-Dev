import tkinter as tk
from tkinter import ttk, messagebox, colorchooser, font as tkFont
from enum import Enum, auto


class InterfaceType(Enum):
    ENTRY = auto()
    COMBOBOX = auto()
    SPINBOX = auto()
    FONT = auto()
    COLOR = auto()


class ColorButton(tk.Button):
    def __init__(self, master=None, title="Choose color..", **kwargs):
        super().__init__(master, **kwargs)
        self.var = tk.StringVar()
        self.var.trace_add("write", self.__on_change_var)
        self.colorchooser_title = title

        self.config(command=self.__choose_color, text="")
        self.var.set("#000000")

    def __choose_color(self):
        color = colorchooser.askcolor(title=self.colorchooser_title)
        if color[1]:  # color[1] — HEX-cod
            self.var.set(color[1])

    def __on_change_var(self, *args):
        self.config(bg=self.var.get())

    def set(self, color: str):
        self.var.set(color)

    def get(self) -> str:
        return self.var.get()


class FontConfig(tk.Frame):
    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)
        # --- vars ---
        self.family_var = tk.StringVar()
        self.size_var = tk.StringVar()
        # weight -> ["normal", "bold"]
        # slant -> ["roman" (звичайний), "italic"]
        self.boolean_vars = {
            "bold": tk.BooleanVar(), "italic": tk.BooleanVar(),
            "underline": tk.BooleanVar(), "overstrike": tk.BooleanVar(),
        }

        # --- build interface ---
        # main frame
        self.config(padx=5, pady=5)

        # Families
        label_family = tk.Label(self, text="Family:")
        label_family.pack(fill=tk.X)

        combobox_family = ttk.Combobox(
            self,
            textvariable=self.family_var,
            values=sorted(tkFont.families()),
            state="readonly",
        )
        combobox_family.pack(fill=tk.X)

        # Size
        frame_size = tk.Frame(self)
        frame_size.pack(fill=tk.X, expand=True, pady=5)

        frame_size_container = tk.Frame(frame_size)
        frame_size_container.pack()

        label_family = tk.Label(frame_size_container, text="Size:")
        label_family.grid(row=0, column=0)

        spinbox_size = tk.Spinbox(
            frame_size_container,
            textvariable=self.size_var,
            from_=1, to=100,
            state="readonly",
            justify="center",
            width=5,
        )
        spinbox_size.grid(row=0, column=1)

        # Others
        frame_other = tk.Frame(self)
        frame_other.pack(fill=tk.X)
        for key, var in self.boolean_vars.items():
            frame = tk.Frame(frame_other)
            frame.pack()

            lb = tk.Label(frame, text=f"{key.capitalize()}:")
            lb.grid(row=0, column=0)

            cb = tk.Checkbutton(frame, variable=var)
            cb.grid(row=0, column=1)

    def get(self) -> tkFont.Font:
        # font = self.family_var.get() + ' ' + self.size_var.get()
        # for key in self.boolean_vars:
        #     if self.boolean_vars[key].get():
        #         font += ' ' + key
        # return font
        font = tkFont.Font(
            family=self.family_var.get(),
            size=int(self.size_var.get()),
            weight="bold" if self.boolean_vars["bold"].get() else "normal",
            slant="italic" if self.boolean_vars["italic"].get() else "roman",
            underline=self.boolean_vars["underline"].get(),
            overstrike=self.boolean_vars["overstrike"].get(),
        )
        return font

    def set(self, font: str):
        if font.startswith("font"):
            font = tkFont.Font(font=font)

            self.family_var.set(font.actual("family"))
            self.size_var.set(font.actual("size"))

            self.boolean_vars["bold"].set(font.actual("weight") == "bold")
            self.boolean_vars["italic"].set(font.actual("slant") == "italic")
            self.boolean_vars["underline"].set(font.actual("underline"))
            self.boolean_vars["overstrike"].set(font.actual("overstrike"))
        else:
            font_parameters = font.split(" ")

            # family
            if font_parameters:
                self.family_var.set(font_parameters.pop(0))
            # size
            if font_parameters:
                self.size_var.set(font_parameters.pop(0))

            # bool, italic, underline, overstrike
            for key in self.boolean_vars.keys():
                self.boolean_vars[key].set(False)
            if font_parameters:
                for param in font_parameters:
                    self.boolean_vars[param].set(True)


class WidgetConfigMenu(tk.Toplevel):
    CANVAS_SIZE = (200, 350)
    def __init__(self, master: tk.Tk, widget: tk.Widget, parameters):
        super().__init__(master)
        self.widget = widget
        self.start_options = {}
        self.option_interfaces = {}

        # Validate the parameters
        errs = []
        for parameter_section in parameters:
            for key in parameter_section[1].keys():
                try:
                    self.start_options[key] = self.widget.cget(key)
                except:
                    errs.append(f"* widget '{self.widget.widgetName}' doesn't have the option '{key}'")
        if errs:
            self.destroy()
            raise ValueError("The provided 'parameters' contain the following invalid options:\n" + "\n".join(errs))

        # --- win setting ---
        self.title(f"{self.widget.widgetName.capitalize()} Config")
        self.transient(master)
        self.grab_set()

        # ----- build interface -----
        # --- frames ---
        # main
        frame_main = tk.Frame(self)
        frame_main.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # parameters (with scrolling)
        scrollable_frame = tk.LabelFrame(frame_main)
        scrollable_frame.pack()

        canvas = tk.Canvas(scrollable_frame, width=self.CANVAS_SIZE[0], height=self.CANVAS_SIZE[1])
        canvas.pack(side="left", expand=True)

        scrollbar = ttk.Scrollbar(scrollable_frame, orient="vertical", command=canvas.yview)
        scrollbar.pack(side="right", fill="y")

        canvas.configure(yscrollcommand=scrollbar.set)

        scrollable_frame = tk.Frame(canvas)

        window_id = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")

        __on_canvas_configure = lambda event: canvas.itemconfig(window_id, width=event.width)
        canvas.bind("<Configure>", __on_canvas_configure)

        __on_frame_configure = lambda event: canvas.configure(scrollregion=canvas.bbox("all"))
        scrollable_frame.bind("<Configure>", __on_frame_configure)

        __on_mousewheel = lambda event: canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        canvas.bind_all("<MouseWheel>", __on_mousewheel)

        frame_parameters = tk.Frame(scrollable_frame)
        frame_parameters.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.after(200, lambda: frame_parameters.config(width=200))

        frame_sections = {}

        # buttons
        frame_buttons = tk.Frame(frame_main)
        frame_buttons.pack(pady=(8, 5))

        # --- parameters ---
        for parameter_section in parameters:
            for key, value in parameter_section[1].items():
                if parameter_section[0] not in frame_sections:
                    frame_sections[parameter_section[0]] = tk.LabelFrame(
                        frame_parameters, text=parameter_section[0].upper(),
                        padx=5, pady=5
                    )
                    frame_sections[parameter_section[0]].pack(pady=5)
                self.__build_option_interface(frame_sections[parameter_section[0]], key, value)

        # --- buttons ---
        button_apply = tk.Button(
            frame_buttons, text="Apply", command=self.__on_apply,
        bg = "#438643", fg = "white"
        )
        button_apply.grid(row=0, column=0, padx=6)
        button_reset = tk.Button(
            frame_buttons, text="Reset", command=self.__on_reset,
        bg = "#992626", fg = "white"
        )
        button_reset.grid(row=0, column=1, padx=6)
        button_cancel = tk.Button(
            frame_buttons, text="Close", command=self.destroy,
        bg = "#997B14", fg = "white"
        )
        button_cancel.grid(row=0, column=2, padx=6)
        # ----- ----- --------- -----

    def __build_option_interface(self, master: tk.LabelFrame, option: str, data: dict):
        frame = tk.LabelFrame(master, text=option)
        frame.pack()
        widget = None

        if data["type"] == InterfaceType.COLOR:
            widget = ColorButton(frame, title=option, width=10)
            widget.set(self.start_options[option])
            widget.pack()
        elif data["type"] == InterfaceType.COMBOBOX:
            widget = ttk.Combobox(
                frame,
                values=data["values"],
                state="readonly",
            )
            widget.set(self.start_options[option])
            widget.pack(fill=tk.X)
        elif data["type"] == InterfaceType.SPINBOX:
            var = tk.StringVar()
            widget = tk.Spinbox(
                frame, textvariable=var,
                from_=1, to=40,
                state="readonly",
            )
            var.set(self.start_options[option])
            widget.pack(fill=tk.X)
            widget = var
        elif data["type"] == InterfaceType.ENTRY:
            var = tk.StringVar()
            widget = tk.Entry(frame)
            var.set(self.start_options[option])
            widget.pack(fill=tk.X)
            widget = var
        elif data["type"] == InterfaceType.FONT:
            widget = FontConfig(frame)
            widget.set(self.start_options[option])
            widget.pack()

        if widget:
            self.option_interfaces[option] = widget

    def __on_apply(self):
        for key in self.option_interfaces.keys():
            self.widget.config(**{key: self.option_interfaces[key].get()})

    def __on_reset(self):
        for key in self.option_interfaces.keys():
            self.option_interfaces[key].set(self.start_options[key])
        self.__on_apply()


class Application(tk.Tk):
    START_TEXT = "\"Help Others & Let Them Help You\""
    ENTRY_PARAMETERS = [
        [
            "Basic",
            {
                "background": {"type": InterfaceType.COLOR, "description": "Фоновий колір поля введення"},
                "font": {"type": InterfaceType.FONT, "description": "Шрифт тексту"},
                "foreground": {"type": InterfaceType.COLOR, "description": "Колір тексту"},
                "justify": {"type": InterfaceType.COMBOBOX, "values": ['left', 'center', 'right'], "description": "Вирівнювання тексту"},
                "relief": {"type": InterfaceType.COMBOBOX, "values": ['flat', 'raised', 'sunken', 'groove', 'ridge'], "description": "Тип рамки"},
                "borderwidth": {"type": InterfaceType.SPINBOX, "description": "Товщина рамки"},
                "width": {"type": InterfaceType.SPINBOX, "description": "Ширина в символах"},
            },
        ],
        [
            "Behavior",
            {
                "show": {"type": InterfaceType.ENTRY, "description": "Символ для прихованого вводу (наприклад, паролі)"},
                "state": {"type": InterfaceType.COMBOBOX, "values": ['normal', 'disabled', 'readonly'], "description": "Стан поля"},
                "cursor": {
                    "type": InterfaceType.COMBOBOX, "values": ["hand2", "arrow", "circle", "clock", "cross", "dotbox", "exchange", "fleur", "heart",
                             "man", "mouse", "pirate", "plus", "shuttle", "sizing", "spider", "spraycan", "star",
                             "target", "tcross", "trek", "watch", "xterm"], "description": "Курсор при наведенні"
                },
            }
        ],
        [
            "State Parameters",
            {
                "disabledbackground": {"type": InterfaceType.COLOR, "description": "Фон, коли state='disabled'"},
                "disabledforeground": {"type": InterfaceType.COLOR, "description": "Текст, коли state='disabled'"},
                "readonlybackground": {"type": InterfaceType.COLOR, "description": "Фон при state='readonly'"},
            }
        ],
        [
            "Focus",
            {
                "highlightbackground": {"type": InterfaceType.COLOR, "description": "Колір рамки при втраті фокуса"},
                "highlightcolor": {"type": InterfaceType.COLOR, "description": "Колір рамки при фокусі"},
                "highlightthickness": {"type": InterfaceType.SPINBOX, "description": "Товщина рамки фокуса"},
            }
        ],
        [
            "Cursor",
            {
                "insertbackground": {"type": InterfaceType.COLOR, "description": "Колір курсору (блималки)"},
                "insertborderwidth": {"type": InterfaceType.SPINBOX, "description": "	Ширина обводки курсору"},
                "insertwidth": {"type": InterfaceType.SPINBOX, "description": "Товщина вертикального курсору"},
            }
        ],
        [
            "Selection",
            {
                "selectbackground": {"type": InterfaceType.COLOR, "description": "Колір фону виділеного тексту"},
                "selectborderwidth": {"type": InterfaceType.SPINBOX, "description": "Товщина рамки навколо виділеного тексту"},
                "selectforeground": {"type": InterfaceType.COLOR, "description": "Колір тексту в середині виділення"},
            }
        ]
    ]

    def __init__(self):
        super().__init__()

        # --- win setting ---
        self.title("Adjust Widget")
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
            frame_main, command=self.open_widget_menu,
            text="Config", width=15, height=2, relief="groove",
            bg="#D47815", fg="white", activebackground="#EF9009")
        button.grid(row=2, column=1, padx=10, pady=10)

    def open_widget_menu(self):
        try:
            WidgetConfigMenu(self, widget=self.entry, parameters=self.ENTRY_PARAMETERS)
        except ValueError as err:
            messagebox.showerror("WidgetConfigMenu", str(err))

if __name__ == "__main__":
    app = Application()
    app.mainloop()
