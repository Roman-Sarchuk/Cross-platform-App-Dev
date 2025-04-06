import tkinter as tk
from tkinter import ttk
from tkinter import colorchooser


class EntryScale(ttk.Frame):
    _allowed_kwargs = {"min_value", "max_value", "entry_width", "scale_length", "fraction_digits", "variable", "show_set_button"}

    def __init__(self, master=None, **kwargs):
        custom_kwargs = {k: v for k, v in kwargs.items() if k in self._allowed_kwargs}
        frame_kwargs = {k: v for k, v in kwargs.items() if k not in self._allowed_kwargs}

        super().__init__(master, **frame_kwargs)

        # vars
        self.min_var = tk.DoubleVar(value=custom_kwargs.get("min_value", 0))
        self.max_var = tk.DoubleVar(value=custom_kwargs.get("max_value", 100))
        self.cur_var = custom_kwargs.get("variable", tk.DoubleVar())
        self.cur_var.set((self.min_var.get()+self.max_var.get())/2)
        self.cur_var.trace_add("write", self.__validate_cur_var)

        # base value initialisation
        entry_width = custom_kwargs.get("entry_width", 8)
        scale_length = custom_kwargs.get("scale_length", 150)
        self.show_set_button = custom_kwargs.get("show_set_button", False)
        self.fraction_digits = custom_kwargs.get("fraction_digits", 2)

        # interface building
        lb_min = ttk.Label(self, textvariable=self.min_var)
        lb_min.grid(row=0, column=0)

        self.entry_cur = ttk.Entry(self, width=entry_width, justify="center")
        self.entry_cur.insert(0, str(self.cur_var.get()))
        self.entry_cur.grid(row=0, column=1)
        self.entry_cur.bind("<FocusOut>", self.__on_entry_focus_out)
        self.entry_cur.bind("<Return>", self.__on_entry_focus_out)
        # Also "<FocusIn>" is bound if show_set_button is True

        lb_max = ttk.Label(self, textvariable=self.max_var)
        lb_max.grid(row=0, column=2)

        self.scale = ttk.Scale(
            self, variable=self.cur_var,
            orient=tk.HORIZONTAL, length=scale_length,
            from_=self.min_var.get(), to=self.max_var.get(),
            command=self.__on_scale_move
        )
        self.scale.grid(row=1, column=0, columnspan=3, pady=4)

        # Also 'self.button_set' is created if show_set_button is True

        # end of init
        if self.show_set_button:
            self.button_set = ttk.Button(self, text="", state=tk.DISABLED)
            self.button_set.grid(row=2, column=0, columnspan=3)
            self.entry_cur.bind("<FocusIn>", self.__on_entry_focus_in)

        if frame_kwargs:
            super().config(**frame_kwargs)

    def config(self, **kwargs):
        custom_kwargs = {k: v for k, v in kwargs.items() if k in self._allowed_kwargs}
        frame_kwargs = {k: v for k, v in kwargs.items() if k not in self._allowed_kwargs}

        if custom_kwargs:
            self._validate_custom_kwargs(custom_kwargs)

            if "min_value" in custom_kwargs:
                self.min_var.set(custom_kwargs["min_value"])
                self.scale.config(from_=custom_kwargs["min_value"])

            if "max_value" in custom_kwargs:
                self.max_var.set(custom_kwargs["max_value"])
                self.scale.config(to=custom_kwargs["max_value"])

            if "entry_width" in custom_kwargs:
                self.entry_cur.config(width=custom_kwargs["entry_width"])

            if "scale_length" in custom_kwargs:
                self.scale.config(length=custom_kwargs["scale_length"])

            if "fraction_digits" in custom_kwargs:
                self.fraction_digits = custom_kwargs["fraction_digits"]

            if "variable" in custom_kwargs and isinstance(kwargs["variable"], tk.Variable):
                self.cur_var = kwargs["variable"]

        if frame_kwargs:
            super().config(**frame_kwargs)

    def _validate_custom_kwargs(self, kwargs):
        for key in kwargs:
            if key not in self._allowed_kwargs:
                allowed = ', '.join(sorted(self._allowed_kwargs))
                raise ValueError(f"This custom parameters '{key}' are not allowed.\n\tAllowed parameters: {allowed}")

    def __validate_cur_var(self, *args):
        try:
            # Get the current value from the DoubleVar
            current = self.cur_var.get()

            # Format to 2 decimal places
            formatted = float(f"{current:.{self.fraction_digits}f}")

            # Check if within bounds
            if formatted < self.min_var.get():
                self.cur_var.set(self.min_var.get())
            elif formatted > self.max_var.get():
                self.cur_var.set(self.max_var.get())
            else:
                self.cur_var.set(formatted)
        except:
            # If the entry contains invalid text, reset to min value
            self.cur_var.set(self.min_var.get())
        self.entry_cur.delete(0, tk.END)  # Clear the entry
        self.entry_cur.insert(0, str(self.cur_var.get()))  # Insert new text

    def __on_scale_move(self, value):
        # Format the value to have 2 decimal places and update DoubleVar
        formatted_value = float(f"{float(value):.2f}")
        self.cur_var.set(formatted_value)

    def __on_entry_focus_in(self, event):
        self.button_set.config(text="set", state=tk.NORMAL)

    def __on_entry_focus_out(self, event):
        # Ensure proper formatting when leaving the entry field
        try:
            current = float(self.entry_cur.get())
            formatted = float(f"{current:.2f}")
            self.cur_var.set(formatted)
        except:
            self.cur_var.set(self.min_var.get())
        if self.show_set_button:
            self.button_set.config(text="", state=tk.DISABLED)


class Application(tk.Tk):
    NUMBER_COUNT = 3
    START_COLOR = "#025669"
    MIN_WEIGHT = 10
    MAX_WEIGHT = 100

    def __init__(self):
        super().__init__()

        # root setting
        self.title("Line Editor")
        self.resizable(width=False, height=False)
        style = ttk.Style()
        #style.theme_use('alt')

        # vars
        self.points = [{'x': tk.DoubleVar(), 'y': tk.DoubleVar()} for _ in range(self.NUMBER_COUNT)]
        self.width_var = tk.DoubleVar()
        self.fill_var = tk.StringVar()
        self.fill_var.trace_add("write", self.__on_change_fill)

        # main Frames
        frame_control_panel = ttk.LabelFrame(text="Control Panel")
        frame_control_panel.pack(side="left", padx=5, pady=5)
        frame_canvas = ttk.LabelFrame(text="Canvas")
        frame_canvas.pack(side="left")

        # ----- Control Panel -----
        # create points UI
        frame_points = ttk.Frame(frame_control_panel)
        frame_points.pack(padx=5, pady=5)

        for point in self.points:
            frame_x_y = ttk.LabelFrame(
                frame_points,
                text=f"Point #{self.points.index(point)+1}",
                relief="solid",
            )
            frame_x_y.pack(padx=5)

            frame_x = ttk.LabelFrame(
                frame_x_y,
                text="x:",
                relief="solid",
            )
            frame_x.pack()

            spinbox_x = ttk.Spinbox(
                frame_x,
                textvariable=point['x'],
                from_=0,
                to=500,
                width=5,
            )
            spinbox_x.pack(fill="x", padx=2, pady=2)

            frame_y = ttk.LabelFrame(
                frame_x_y,
                text="y:",
                relief="solid",
            )
            frame_y.pack()

            spinbox_y = ttk.Spinbox(
                frame_y,
                textvariable=point['y'],
                from_=0,
                to=500,
                width=5,
            )
            spinbox_y.pack()

        # edit weight
        frame_weight = ttk.LabelFrame(frame_control_panel, text="Weight", padding=5)
        frame_weight.pack(padx=5)

        scale = EntryScale(
            frame_weight, variable=self.width_var,
            min_value=self.MIN_WEIGHT, max_value=self.MAX_WEIGHT,
            scale_length=90, entry_width=5, show_set_button=True
        )
        scale.pack()

        # choose color
        frame_fill = ttk.LabelFrame(frame_control_panel, text="Choose Color", padding=5)
        frame_fill.pack(padx=5, pady=5)

        self.button_color = tk.Button(
            frame_fill, command=self.__choose_color,
            width=10
        )
        self.button_color.pack()
        # ----- ------- ----- -----

        # end of init
        self.fill_var.set(self.START_COLOR)

    def __on_change_fill(self, *args):
        self.button_color.config(bg=self.fill_var.get())

    def __choose_color(self):
        color = colorchooser.askcolor(title="Line Fill")
        if color[1]:  # color[1] — HEX-cod
            self.fill_var.set(color[1] if color[1] else self.START_COLOR)


if __name__ == '__main__':
    app = Application()
    app.mainloop()
