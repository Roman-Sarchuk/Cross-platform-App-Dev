import tkinter as tk
from tkinter import ttk, colorchooser, messagebox
from random import randint


class EntryScale(ttk.Frame):
    _allowed_kwargs = {"min_value", "max_value", "entry_width", "scale_length", "fraction_digits", "variable", "show_button"}

    def __init__(self, master=None, **kwargs):
        custom_kwargs = {k: v for k, v in kwargs.items() if k in self._allowed_kwargs}
        frame_kwargs = {k: v for k, v in kwargs.items() if k not in self._allowed_kwargs}

        super().__init__(master, **frame_kwargs)

        # vars
        self._min_var = tk.DoubleVar(value=custom_kwargs.get("min_value", 0))
        self._max_var = tk.DoubleVar(value=custom_kwargs.get("max_value", 100))
        self._cur_var = custom_kwargs.get("variable", tk.DoubleVar())
        self._cur_var.set((self._min_var.get() + self._max_var.get()) / 2)
        self._cur_var.trace_add("write", self.__validate_cur_var)

        # base value initialisation
        entry_width = custom_kwargs.get("entry_width", 8)
        scale_length = custom_kwargs.get("scale_length", 150)
        self._show_button = custom_kwargs.get("show_button", False)
        self._fraction_digits = custom_kwargs.get("fraction_digits", 2)

        # interface building
        lb_min = ttk.Label(self, textvariable=self._min_var)
        lb_min.grid(row=0, column=0)

        self._entry_cur = ttk.Entry(self, width=entry_width, justify="center")
        self._entry_cur.insert(0, str(self._cur_var.get()))
        self._entry_cur.grid(row=0, column=1)
        self._entry_cur.bind("<FocusOut>", self.__on_entry_focus_out)
        self._entry_cur.bind("<Return>", self.__on_entry_focus_out)
        # Also "<FocusIn>" is bound if _show_button is True

        lb_max = ttk.Label(self, textvariable=self._max_var)
        lb_max.grid(row=0, column=2)

        self._scale = ttk.Scale(
            self, variable=self._cur_var,
            orient=tk.HORIZONTAL, length=scale_length,
            from_=self._min_var.get(), to=self._max_var.get(),
            command=self.__on_scale_move
        )
        self._scale.grid(row=1, column=0, columnspan=3, pady=4)

        # Also 'self._button_set' is created if _show_button is True

        # end of init
        if self._show_button:
            self._button_set = ttk.Button(self, text="", state=tk.DISABLED)
            self._button_set.grid(row=2, column=0, columnspan=3)
            self._entry_cur.bind("<FocusIn>", self.__on_entry_focus_in)

        if frame_kwargs:
            super().config(**frame_kwargs)

    def config(self, **kwargs):
        custom_kwargs = {k: v for k, v in kwargs.items() if k in self._allowed_kwargs}
        frame_kwargs = {k: v for k, v in kwargs.items() if k not in self._allowed_kwargs}

        if custom_kwargs:
            self._validate_custom_kwargs(custom_kwargs)

            if "min_value" in custom_kwargs:
                self._min_var.set(custom_kwargs["min_value"])
                self._scale.config(from_=custom_kwargs["min_value"])

            if "max_value" in custom_kwargs:
                self._max_var.set(custom_kwargs["max_value"])
                self._scale.config(to=custom_kwargs["max_value"])

            if "entry_width" in custom_kwargs:
                self._entry_cur.config(width=custom_kwargs["entry_width"])

            if "scale_length" in custom_kwargs:
                self._scale.config(length=custom_kwargs["scale_length"])

            if "fraction_digits" in custom_kwargs:
                self._fraction_digits = custom_kwargs["_fraction_digits"]

            if "variable" in custom_kwargs and isinstance(kwargs["variable"], tk.Variable):
                self._cur_var = kwargs["variable"]

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
            current = self._cur_var.get()

            # Format to 2 decimal places
            formatted = float(f"{current:.{self._fraction_digits}f}")

            # Check if within bounds
            if formatted < self._min_var.get():
                self._cur_var.set(self._min_var.get())
            elif formatted > self._max_var.get():
                self._cur_var.set(self._max_var.get())
            else:
                self._cur_var.set(formatted)
        except:
            # If the entry contains invalid text, reset to min value
            self._cur_var.set(self._min_var.get())
        self._entry_cur.delete(0, tk.END)  # Clear the entry
        self._entry_cur.insert(0, str(self._cur_var.get()))  # Insert new text

    def __on_scale_move(self, value):
        # Format the value to have 2 decimal places and update DoubleVar
        formatted_value = float(f"{float(value):.2f}")
        self._cur_var.set(formatted_value)

    def __on_entry_focus_in(self, event):
        self._button_set.config(text="set", state=tk.NORMAL)

    def __on_entry_focus_out(self, event):
        # Ensure proper formatting when leaving the entry field
        try:
            current = float(self._entry_cur.get())
            formatted = float(f"{current:.2f}")
            self._cur_var.set(formatted)
        except:
            self._cur_var.set(self._min_var.get())
        if self._show_button:
            self._button_set.config(text="", state=tk.DISABLED)


class Application(tk.Tk):
    START_COLOR = "#025669"
    MIN_WEIGHT = 1
    MAX_WEIGHT = 10
    START_POINT_COUNT = 3
    CANVAS_SIZE_DELTA = 20

    def __init__(self):
        super().__init__()

        # root setting
        self.title("Line Editor")
        self.resizable(width=False, height=False)
        style = ttk.Style()
        style.theme_use('alt')

        # vars
        self.width_var = tk.DoubleVar()
        self.fill_var = tk.StringVar()
        self.fill_var.trace_add("write", self.__on_change_fill)

        # main Frames
        main_frame = ttk.Frame(self)
        main_frame.pack()
        self.frame_control_panel = ttk.LabelFrame(main_frame, text="Control Panel")
        self.frame_control_panel.pack(side="left", padx=5, pady=5)
        self.frame_canvas = ttk.LabelFrame(main_frame, text="Canvas")
        self.frame_canvas.pack(side="left", padx=5, pady=5)
        self.frame_canvas.pack_propagate(False)

        # ----- Control Panel -----
        # point input field
        frame_points = ttk.LabelFrame(self.frame_control_panel, text="Points", padding=5)
        frame_points.pack(padx=5, pady=5)

        self.text_points = tk.Text(frame_points, height=8, width=10)
        self.text_points.pack()

        # edit weight
        frame_weight = ttk.LabelFrame(self.frame_control_panel, text="Weight", padding=5)
        frame_weight.pack(padx=5)

        scale = EntryScale(
            frame_weight, variable=self.width_var,
            min_value=self.MIN_WEIGHT, max_value=self.MAX_WEIGHT,
            scale_length=90, entry_width=5, show_button=True
        )
        scale.pack()

        # choose color
        frame_fill = ttk.LabelFrame(self.frame_control_panel, text="Choose Color", padding=5)
        frame_fill.pack(padx=5, pady=(5, 0))

        self.button_color = tk.Button(
            frame_fill, command=self.__choose_color,
            width=10
        )
        self.button_color.pack()

        # buttons
        frame_buttons = ttk.LabelFrame(self.frame_control_panel)
        frame_buttons.pack(pady=(0, 10))

        button_draw = ttk.Button(frame_buttons, text="Draw", command=self.__on_draw_button)
        button_draw.pack(padx=5)

        button_clear = ttk.Button(frame_buttons, text="Clear", command=lambda: self.canvas.delete("all"))
        button_clear.pack(padx=5, pady=(5, 8))
        # ----- ------- ----- -----

        # canvas
        self.canvas = tk.Canvas(self.frame_canvas, bg="white")

        # --- end of init ---
        try:
            self.after(100, self.__init_canvas)
        except:
            self.after(100, self.__init_canvas)
        # set rand color
        self.fill_var.set("#{:06x}".format(randint(0, 0xFFFF00)))

    def __init_canvas(self):
        # add canvas
        self.frame_canvas.config(
            width=self.frame_control_panel.winfo_height(),
            height=self.frame_control_panel.winfo_height())

        self.canvas.pack(side="left", fill="both", expand=True)

        # set points to tk.Text
        min_coord = 10
        max_coord = self.frame_control_panel.winfo_height() - 50
        points = ""
        for i in range(self.START_POINT_COUNT):
            points += f"{randint(min_coord, max_coord)},{randint(min_coord, max_coord)}"
            if i != self.START_POINT_COUNT - 1:
                points += '\n'

        self.text_points.insert(0.0, points)

    def __on_change_fill(self, *args):
        self.button_color.config(bg=self.fill_var.get())

    def __choose_color(self):
        color = colorchooser.askcolor(title="Line Fill")
        if color[1]:  # color[1] — HEX-cod
            self.fill_var.set(color[1] if color[1] else self.START_COLOR)

    def _get_points(self) -> list:
        text = self.text_points.get('1.0', 'end-1c').strip()
        # protection: empty field
        if not text:
            raise ValueError("The field of the points is empty!\n"
                             "Enter some points first.")

        # Split the input string by newlines
        lines = text.split('\n')

        points = []
        for line in lines:
            # Skip empty lines
            if not line.strip():
                continue

            point_str = line.strip()

            # Split coordinates and convert to numbers
            coords = point_str.split(',')
            if len(coords) == 2:
                try:
                    x = float(coords[0].strip())
                    y = float(coords[1].strip())
                    points.append(x)
                    points.append(y)
                except ValueError:
                    # protection: can't convert to float
                    raise ValueError(f"Invalid line format '{point_str}'.\n"
                                     f"Can't get coordinates!\n"
                                     f"Line must has only x and y coordinates separated by a comma!")
            else:
                # protection: more than 2 coords
                raise ValueError(f"Invalid line format '{point_str}'.\n"
                                 f"Line must has only x and y coordinates separated by a comma!")

        return points

    def __on_draw_button(self):
        try:
            points = self._get_points()

            for i in range(len(points)):
                self.canvas.create_polygon(
                    *points, width=self.width_var.get(),
                    fill=self.fill_var.get(), outline=self.fill_var.get()
                )

        except ValueError as err:
            messagebox.showwarning("Drawing...", str(err))


if __name__ == '__main__':
    app = Application()
    app.mainloop()
