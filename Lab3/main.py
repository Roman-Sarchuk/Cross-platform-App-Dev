from tinydb import TinyDB, Query
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from random import randint, choice as rand_choice, uniform as rand_uniform


class DBHandler(TinyDB):
    def __init__(self, path, fields):
        super().__init__(path)
        self.work_tabel = self.table("_default")
        self.fields = fields    # {field_name: field_type, ...}

    def insert(self, values):
        # validate args
        if len(values) != len(self.fields):
            raise ValueError(
                f"You try insert {values} in DB, but you have to pass {len(self.fields)} values to the function")

        for value, key in zip(values, self.fields.keys()):
            expected_type = self.fields[key]
            if not isinstance(expected_type, type):
                raise TypeError(f"Expected type for the field '{key}' should be a type, but got '{expected_type}'!")
            if not isinstance(value, expected_type):
                raise ValueError(f"The '{value}' is incorrect value for the '{key}' that has the '{expected_type}' type!")

        # inserting
        self.work_tabel.insert(dict(zip(self.fields.keys(), values)))

    def insert_rand(self, number, variables):
        records = []

        for _ in range(number):
            values = []

            for var in variables:
                if isinstance(var, str):
                    values.append(var + str(randint(0, 50)))
                elif isinstance(var, list) or isinstance(var, tuple):
                    values.append(rand_choice(var))
                elif isinstance(var, dict) and "min" in var and "max" in var:
                    if isinstance(var["min"], int) and isinstance(var["max"], int):
                        values.append(randint(var[min], var[max]))
                    elif isinstance(var["min"], float) and isinstance(var["max"], float):
                        number = rand_uniform(var["min"], var["max"])
                        values.append(round(number, var.get("fraction_digits", 2)))

            records.append(values)
            self.insert(values)

        return records

    def get_matching_records(self, document: dict):
        if not document or len(document) == 0:
            return

        query = Query()
        query_condition = None

        for key, value in document.items():
            # converting
            if isinstance(value, str):
                try:
                    value = int(value)
                except ValueError:
                    try:
                        value = float(value)
                    except ValueError:
                        pass
            # For the first condition, just set it
            if query_condition is None:
                query_condition = (getattr(query, key) == value)
            # For subsequent conditions, combine with AND logic
            else:
                query_condition &= (getattr(query, key) == value)

        return self.work_tabel.search(query_condition)

    def clear(self):
        self.work_tabel.truncate()


class AppTreeDBTestUtils:
    def __init__(self, root: tk.Tk, db: DBHandler, tree: ttk.Treeview, rand_variable: tuple):
        self.db = db
        self.tree = tree
        self.rand_variable = rand_variable

        root.bind("<Control-p>", self.insert_rand_handler)
        root.bind("<Control-Delete>", self.clear_db_handler)

    def insert_rand_handler(self, event):
        records = self.db.insert_rand(5, self.rand_variable)

        for values in records:
            #self.db.insert(values)
            self.tree.insert("", "end", values=values)

        messagebox.showinfo("Random inserting...", f"Records insert successfully:\n{records}")

    def clear_db_handler(self, event):
        if not messagebox.askyesno("DB clearing...", "Are you sure you want to delete all records?"):
            return

        self.db.clear()

        for item in self.tree.get_children():
            self.tree.delete(item)

        messagebox.showinfo("DB clearing...", f"Records deleted successfully!")


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
    FILE_NAME = "CatalogDB.json"
    FIELDS = {"name": str, "price": float, "status": str}
    TREE_FIELD_NAMES = ["Назва", "Ціна", "Статус"]
    STATUSES = ["В наявності", "Продано", "Очікується", "Резерв", "Списано", "У ремонті", "Пошкоджений"]
    MIN_PRICE = 100.0
    MAX_PRICE = 20000.0
    RAND_VARIABLES = ("Ігровий Контролер", {"min": MIN_PRICE, "max": MAX_PRICE}, STATUSES)

    def __init__(self):
        super().__init__()
        self.db = DBHandler(self.FILE_NAME, self.FIELDS)

        # validate
        if len(self.RAND_VARIABLES) != len(self.FIELDS):
            raise AttributeError("'RAND_VARIABLES' doesn't have the same length as 'FIELDS'!")
        if len(self.TREE_FIELD_NAMES) != len(self.FIELDS):
            raise AttributeError("'TREE_FIELD_NAMES' doesn't have the same length as 'FIELDS'!")

        # root setting
        self.title("CatalogDB")
        style = ttk.Style()
        style.theme_use('clam')

        # vars
        self.vars = dict(zip(self.FIELDS.keys(), (tk.StringVar(), tk.DoubleVar(), tk.StringVar())))
        self.vars["price"].set(self.MIN_PRICE)
        self.vars["status"].set(self.STATUSES[0])

        # ----- Frame initialisation -----
        frame_tree = ttk.Frame(self, width=450)
        frame_tree.pack(pady=(10, 0))
        frame_data = ttk.LabelFrame(self, text="Data Bar", padding=5, width=300)
        frame_data.pack(padx=10, pady=(10, 0))
        frame_control = ttk.Labelframe(self, text="Control Bar", padding=(5, 5, 5, 10), width=450)
        frame_control.pack(padx=10, pady=10)
        # ----- ----- -------------- -----

        # ----- Set up Treeview -----
        scrollbar = ttk.Scrollbar(frame_tree, orient="vertical")
        scrollbar.pack(side="right", fill="y")

        self.tree = ttk.Treeview(
            frame_tree,
            columns=tuple(self.FIELDS.keys()),
            show="headings",
            height=10,
            yscrollcommand=scrollbar.set,
        )

        for i, field_name in enumerate(self.FIELDS.keys()):
            self.tree.heading(field_name, text=self.TREE_FIELD_NAMES[i], anchor='w')
            self.tree.column(field_name, width=160, anchor="w", stretch=(i == 0 or i == len(self.FIELDS) - 1))

        self.tree.pack()

        self.load_data()

        scrollbar.config(command=self.tree.yview)
        # ----- --- -- -------- -----

        # ----- Set up Data frame -----
        lb_name = ttk.Label(frame_data, text="Name:")
        lb_name.grid(row=0, column=0, sticky='w', padx=10)
        lb_price = ttk.Label(frame_data, text="Price:")
        lb_price.grid(row=0, column=1, sticky='w', padx=10)
        lb_status = ttk.Label(frame_data, text="Status:")
        lb_status.grid(row=0, column=2, sticky='w', padx=10)

        entry_name = ttk.Entry(frame_data, textvariable=self.vars["name"])
        entry_name.grid(row=1, column=0, padx=10)

        scale_slider = EntryScale(
            frame_data, variable=self.vars["price"],
            min_value=self.MIN_PRICE, max_value=self.MAX_PRICE,
            show_set_button=True
        )
        scale_slider.grid(row=1, column=1, padx=10)

        combo_status = ttk.Combobox(frame_data, textvariable=self.vars["status"], values=self.STATUSES, state="read")
        combo_status.grid(row=1, column=2, padx=10)
        # ----- --- -- ---- ----- -----

        # ----- Set up Control frame -----
        btn_params = {
            "Insert": self.insert_handler,
            "Delete": self.delete_handler,
            "Get": self.get_item_handler,
            "Set": self.set_item_handler
        }
        for i, (text, func) in enumerate(btn_params.items()):
            ttk.Button(frame_control,
                       text=text, width=15,
                       command=func
                       ).grid(row=0, column=i, padx=5)
        # ----- --- -- ------- ----- -----

        # Adding test functionality
        AppTreeDBTestUtils(self, self.db, self.tree, self.RAND_VARIABLES)

    def insert_handler(self):
        # getting
        values = [var.get() for var in self.vars.values()]

        # validate
        for value, field_name in zip(values, self.FIELDS.keys()):
            if not value:
                messagebox.showwarning("Inserting...", f"The '{field_name}' can't be empty")
                return

        self.db.insert(values)
        self.tree.insert("", "end", values=values)

        messagebox.showinfo("Inserting...", f"Record insert successfully:\n{values}")

    def delete_handler(self):
        selection = self.tree.selection()
        # validate
        if not selection:
            return

        deleted_records = []
        for item in selection:
            values = self.tree.item(item, "values")  # Get values as tuple
            matching_records = self.db.get_matching_records(dict(zip(self.FIELDS.keys(), values)))
            first_record_id = matching_records[0].doc_id  # Get the unique doc_id
            self.db.remove(doc_ids=[first_record_id])  # Delete the record by doc_id

            self.tree.delete(item)
            deleted_records.append(values)

        messagebox.showinfo("Deleting...", f"Such records were deleted:\n{deleted_records}")

    def get_item_handler(self):
        selection = self.tree.selection()
        # validate
        if not selection:
            return

        values = self.tree.item(selection[0]).get("values")

        for i, key in enumerate(self.FIELDS):
            self.vars[key].set(values[i])

    def set_item_handler(self):
        selection = self.tree.selection()
        # validate
        if not selection:
            return

        values = self.tree.item(selection[0], "values")
        # validate
        new_values = []
        for field_name, var in self.vars.items():
            new_values.append(var.get())
            if not new_values[-1]:
                messagebox.showwarning("Setting...", f"The '{field_name}' can't be empty")
                return

        # setting
        matching_records = self.db.get_matching_records(dict(zip(self.FIELDS.keys(), values)))
        first_record_id = matching_records[0].doc_id  # Get the unique doc_id
        self.db.update(dict(zip(self.FIELDS.keys(), new_values)), doc_ids=[first_record_id])
        for field_name, var in self.vars.items():
            self.tree.set(selection[0], column=field_name, value=var.get())

        messagebox.showinfo("Setting...", f"For record '{values}' was set this value '{new_values}'")

    def load_data(self):
        # clear table
        for row in self.tree.get_children():
            self.tree.delete(row)

        # data getting from DB
        records = self.db.all()

        # add records in the Treeview
        for record in records:
            self.tree.insert("", "end", values=[record[field] for field in self.FIELDS.keys()])


if __name__ == '__main__':
    app = Application()
    app.mainloop()
