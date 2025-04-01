from tinydb import TinyDB, Query
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from random import randint, choice as rand_choice


class AppDBHandler(TinyDB):
    def __init__(self, path, window, fields):
        super().__init__(path)
        self.work_tabel = self.table("_default")
        self.window = window
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
                elif isinstance(var, int):
                    values.append(randint(var, var + 5000))
                elif isinstance(var, list) or isinstance(var, tuple):
                    values.append(rand_choice(var))

            records.append(values)
            self.insert(values)

        return records

    def clear(self):
        self.work_tabel.truncate()


class TestAppFunc:
    def __init__(self, root: tk.Tk, db: TinyDB, tree: ttk.Treeview, rand_variable: tuple):
        self.db = db
        self.tree = tree
        self.rand_variable = rand_variable

        root.bind("<r>", self.insert_rand_handler)
        root.bind("<Delete>", self.clear_db_handler)

    def insert_rand_handler(self, event):
        records = self.db.insert_rand(5, self.rand_variable)

        for values in records:
            self.tree.insert("", "end", values=values)

        messagebox.showinfo("Random inserting...", f"Records insert successfully:\n{records}")

    def clear_db_handler(self, event):
        if not messagebox.askyesno("DB clearing...", "Are you sure you want to delete all records?"):
            return

        self.db.clear()

        for item in self.tree.get_children():
            self.tree.delete(item)

        messagebox.showinfo("DB clearing...", f"Records deleted successfully!")


class Application(tk.Tk):
    FILE_NAME = "CatalogDB.json"
    FIELDS = {"name": str, "price": int, "status": str}
    MIN_SCALE = 100
    MAX_SCALE = 20000
    STATUSES = ["В наявності", "Продано", "Очікується", "Резерв", "Списано", "У ремонті", "Пошкоджений"]
    RAND_VARIABLES = ("Ігровий Контролер", 100, STATUSES)

    def __init__(self):
        super().__init__()
        self.db = AppDBHandler(self.FILE_NAME, self, self.FIELDS)

        # validate
        if len(self.RAND_VARIABLES) != len(self.FIELDS):
            raise AttributeError("'RAND_VARIABLES' doesn't have the same length as 'FIELDS'!")

        # root setting
        self.title = "CatalogDB"
        style = ttk.Style()
        style.theme_use('clam')
        vcmd = (self.register(self.__validate_price), "%P")

        # vars
        self.vars = dict(zip(self.FIELDS.keys(), (tk.StringVar(), tk.IntVar(), tk.StringVar())))
        self.vars["price"].set(self.MIN_SCALE)
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
            columns=("name", "price", "status"),
            show="headings",
            selectmode="browse",
            height=10,
            yscrollcommand=scrollbar.set,
        )

        self.tree.heading("name", text="Назва", anchor="w")
        self.tree.heading("price", text="Ціна", anchor="w")
        self.tree.heading("status", text="Статус", anchor="w")

        self.tree.column("name", width=295, anchor="w", stretch=True)
        self.tree.column("price", width=75, anchor="w", stretch=False)
        self.tree.column("status", width=100, anchor="w", stretch=True)

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

        entry = ttk.Entry(frame_data, textvariable=self.vars["name"])
        entry.grid(row=1, column=0, padx=10)

        # -- Set up scale --
        frame_scale = ttk.Frame(frame_data)
        frame_scale.grid(row=1, column=1, padx=10)

        scale_lb_min = ttk.Label(frame_scale, text=str(self.MIN_SCALE))
        scale_lb_min.grid(row=0, column=0)
        scale_entry_cur = ttk.Entry(
            frame_scale, textvariable=self.vars["price"],
            width=8, justify="center",
            validate="key", validatecommand=vcmd)
        scale_entry_cur.grid(row=0, column=1)
        scale_lb_max = ttk.Label(frame_scale, text=str(self.MAX_SCALE))
        scale_lb_max.grid(row=0, column=2)
        scale_slider = ttk.Scale(
            frame_scale, style="Custom.Horizontal.TScale",
            orient=tk.HORIZONTAL, length=150,
            from_=self.MIN_SCALE, to=self.MAX_SCALE,
            command=lambda val: self.vars["price"].set(int(float(val)))
        )
        scale_slider.grid(row=1, column=0, columnspan=3)
        # -- --- -- ----- --

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
        TestAppFunc(self, self.db, self.tree, self.RAND_VARIABLES)

    def __validate_price(self, new_value):
        if not new_value:
            self.vars["price"].set(self.MIN_SCALE)
            return False

        if new_value.isdigit():
            num = int(new_value)

            if num < self.MIN_SCALE:
                self.vars["price"].set(self.MIN_SCALE)
                return False
            elif num > self.MAX_SCALE:
                self.vars["price"].set(self.MAX_SCALE)
                return False

            return self.MIN_SCALE <= num <= self.MAX_SCALE

        return False

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

        for item in selection:
            self.tree.delete(item)

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

        # validate
        for field_name, var in self.vars.items():
            if not var.get():
                messagebox.showwarning("Setting...", f"The '{field_name}' can't be empty")
                return

        for field_name, var in self.vars.items():
            self.tree.set(selection[0], column=field_name, value=var.get())

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
