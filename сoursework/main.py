import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import os
import string
import random
from enum import Enum, auto
import re


class Singleton:
    _instance = None
    _initialized = False

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance


# ~~~~~~~~~~~~~~~ BACKEND ~~~~~~~~~~~~~~~
DB_NAME = "data.db"


class TableName(Enum):
    DEFAULT = "workspace"
    USER_ROLES = "user_roles"
    USERS = "users"
    OPERATION_TYPES = "operation_types"
    LOGS = "logs"
    SETTINGS = "settings"


class SettingName(Enum):
    AUTHENTICATION = "authentication"
    LOGS = "logs"


class Encryptor(Singleton):
    SYMBOLS = string.ascii_lowercase + "-_." * 4
    MAX_RAND_TEXT_LETTERS = 3
    MIN_RAND_BOOL_LETTERS = 5

    @staticmethod
    def __convert_to_unicode_list(text: str) -> list[int]:
        return [ord(char) for char in text]

    def __letters_to_insert(self, code) -> int:
        return max(1, code % self.MAX_RAND_TEXT_LETTERS)

    def mask_text(self, text) -> str:
        # get the text codes
        unicode_codes = self.__convert_to_unicode_list(text)

        # form the parts
        parts = []
        random.seed(text)
        for char, code in zip(text, unicode_codes):
            random_letters = random.sample(self.SYMBOLS, self.__letters_to_insert(code))
            parts.append("".join(random_letters) + char)
        random.seed()

        # combine the parts into a result
        return "".join(parts)

    def mask_boolean(self, key: str, boolean: bool) -> str:
        random.seed(key if boolean else key[::-1])
        letters_count = self.MIN_RAND_BOOL_LETTERS if len(key) <= self.MIN_RAND_BOOL_LETTERS \
            else random.randint(self.MIN_RAND_BOOL_LETTERS, len(key))
        random_letters = random.sample(self.SYMBOLS, letters_count)
        masked_text = "".join(random_letters)
        random.seed()

        return masked_text

    def unmask_boolean(self, key: str, mask_boolean: str) -> bool:
        if self.mask_boolean(key, True) == mask_boolean:
            return True

        return False if self.mask_boolean(key, False) == mask_boolean else None


class DBHandler(Singleton):
    def __init__(self, db_name: str):
        if not self._initialized:
            self.db_name = db_name

            self._initialized = True

    @staticmethod
    def __extract_conditions_params(data: dict) -> tuple[list, list]:
        conditions = []
        params = []

        for key, value in data.items():
            conditions.append(f"{key}=?")
            params.append(value)

        return conditions, params

    def get(self, table: TableName, where:dict=None) -> list[dict]:
        query = f"SELECT * FROM {table.value}"

        # Execute query and return results
        with sqlite3.connect(self.db_name) as conn:
            conn.row_factory = sqlite3.Row  # This enables column access by name
            cursor = conn.cursor()
            if where:
                conditions, params = self.__extract_conditions_params(where)
                query += f" WHERE {" AND ".join(conditions)}"
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            rows = cursor.fetchall()

            # Convert rows to dictionaries
            result = [dict(row) for row in rows]
            return result

    def insert(self, table: TableName, row: dict):
        query = f"INSERT INTO {table.value} ({", ".join(row.keys())}) VALUES ({", ".join("?" * len(row.values()))})"

        # Execute query
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute(query, tuple(row.values()))

    def remove(self, table: TableName, where: dict):
        conditions, params = self.__extract_conditions_params(where)

        query = f"DELETE FROM {table.value} WHERE {" AND ".join(conditions)}"

        # Execute query
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)

    def update(self, table: TableName, new_row_data: dict, where: dict):
        set_conditions, set_params = self.__extract_conditions_params(new_row_data)

        where_conditions, where_params = self.__extract_conditions_params(where)

        query = f"UPDATE {table.value} SET {", ".join(set_conditions)} WHERE {" AND ".join(where_conditions)}"

        # Execute query
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute(query, set_params + where_params)

    def get_row_count(self, table: TableName):
        query = f"SELECT COUNT(*) FROM {table.value}"

        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute(query)
            return cursor.fetchone()[0]


class SettingsHandler(Singleton):
    def __init__(self, db_path: str):
        if not self._initialized:
            self.encryptor = Encryptor()
            self.db_handler = DBHandler(db_path)

            self._initialized = True

    def get(self, key: SettingName) -> str:
        masked_key = self.encryptor.mask_text(key.value)
        row = self.db_handler.get(TableName.SETTINGS, {"key": masked_key})
        return row[0]["value"] if row else None

    def insert(self, key: SettingName, value: bool):
        masked_key = self.encryptor.mask_text(key.value)
        masked_value = self.encryptor.mask_boolean(key.value, value)
        self.db_handler.insert(TableName.SETTINGS, {"key": masked_key, "value": masked_value})

    def update(self, key: SettingName, value: bool):
        masked_key = self.encryptor.mask_text(key.value)
        masked_value = self.encryptor.mask_boolean(key.value, value)
        self.db_handler.update(TableName.SETTINGS, {"value": masked_value}, {"key": masked_key})


class DatabaseInitializer(Singleton):
    REQUIRED_TABLES = {
        TableName.DEFAULT.value: '''
            CREATE TABLE IF NOT EXISTS workspace (
                id INTEGER PRIMARY KEY NOT NULL UNIQUE
            );
        ''',
        TableName.USER_ROLES.value: '''
            CREATE TABLE IF NOT EXISTS user_roles (
                id INTEGER PRIMARY KEY NOT NULL UNIQUE,
                name TEXT NOT NULL UNIQUE
            );
        ''',
        TableName.USERS.value: '''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY NOT NULL UNIQUE,
                username TEXT NOT NULL,
                login TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                role_id INTEGER NOT NULL,
                created_date REAL NOT NULL,
                FOREIGN KEY(role_id) REFERENCES user_roles(id)
            );
        ''',
        TableName.OPERATION_TYPES.value: '''
            CREATE TABLE IF NOT EXISTS operation_types (
                id INTEGER PRIMARY KEY NOT NULL UNIQUE,
                name TEXT NOT NULL UNIQUE
            );
        ''',
        TableName.LOGS.value: '''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY NOT NULL UNIQUE,
                operation_type_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                log_date REAL NOT NULL,
                description TEXT,
                FOREIGN KEY(operation_type_id) REFERENCES operation_types(id),
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
        ''',
        TableName.SETTINGS.value: '''
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT NOT NULL UNIQUE,
                value TEXT NOT NULL
            );
        '''
    }
    SETTINGS = {
        SettingName.AUTHENTICATION: True,
        SettingName.LOGS: True,
    }
    USER_ROLES = ["admin", "user"]

    def __init__(self, db_path: str, is_info_logging=False):
        if not self._initialized:
            self.is_info_logging = is_info_logging
            self.logs = []

            self.db_path = db_path
            self.connection = None
            self.cursor = None

            self._initialized = True

    def connect_to_db_or_create(self):
        db_exists = os.path.exists(self.db_path)
        self.connection = sqlite3.connect(self.db_path)
        self.cursor = self.connection.cursor()

        if not db_exists:
            self._log_info(f"🔗|📁 Створено файл БД: {self.db_path}")
        else:
            self._log_info(f"🔗|✅ Підключено до наявної БД: {self.db_path}")

    def check_and_create_tables(self):
        if not self.connection and not self.cursor:
            self._log_info("🚫 Не підключений до DB, виконайте спершу connect_to_db_or_create()")

        for table_name, sql in self.REQUIRED_TABLES.items():
            if not self._table_exists(table_name):
                self.cursor.execute(sql)
                self.connection.commit()
                self._log_info(f"📄|🧱 Створено таблицю: {table_name}")
            else:
                self._log_info(f"📄|✅ Таблиця вже існує: {table_name}")

    def verify_and_fill_settings(self):
        encryptor = Encryptor()
        settings_handler = SettingsHandler(self.db_path)
        for key, value in self.SETTINGS.items():
            setting_value = settings_handler.get(key)

            if setting_value is None:
                settings_handler.insert(key, value)
                self._log_info(f"🔧|🔼 Додано параметер '{key.value}' у таблицю 'settings' із значенням за замовчуванням")
            elif encryptor.unmask_boolean(key.value, setting_value) is None:
                settings_handler.update(key, value)
                self._log_info(f"🔧|[❗] '{key.value}' пошкоджений у таблиці 'settings'; встановлено значення за замовчування")
            else:
                self._log_info(f"🔧|✅ '{key.value}' є валіде у таблицю 'settings'")

    def check_and_fill_user_roles(self):
        bd_handler = DBHandler(self.db_path)

        for role in self.USER_ROLES:
            row = bd_handler.get(TableName.USER_ROLES, {"name": role})
            if not row:
                bd_handler.insert(TableName.USER_ROLES, {"name": role})
                self._log_info(f"🎭|🔼 Додано базову роль '{role}' у таблицю 'user_roles'")
            else:
                self._log_info(f"🎭|✅ Базова роль '{role}' міститься у таблицю 'user_roles'")

    def verify_and_init_db(self):
        self.connect_to_db_or_create()
        self.check_and_create_tables()
        self.verify_and_fill_settings()
        self.check_and_fill_user_roles()
        self.print_logs()
        self.close()

    def _table_exists(self, table_name: str) -> bool:
        self.cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name=?;
        """, (table_name,))
        return self.cursor.fetchone() is not None

    def close(self):
        if self.connection:
            self.connection.close()
            self._log_info(f"[{self.__class__.__name__}]: 🔒 Підключення до БД закрито.")

    def _log_info(self, text):
        if self.is_info_logging:
            self.logs.append(f"[{self.__class__.__name__}]: {text}")

    def print_logs(self):
        if self.logs:
            for log in self.logs:
                print(log)


class UsersHandler(Singleton):
    def __init__(self, db_path: str):
        if not self._initialized:
            self.db_handler = DBHandler(db_path)
            self.selected_user = None

            self._initialized = True

    def select(self, login, password):
        pass

    def insert(self):
        pass

    def remove(self):
        pass

    def authenticate(self) -> bool:
        pass

    def authorize(self) -> bool:
        pass

    def get_count(self):
        return self.db_handler.get_row_count(TableName.USERS)


class DefaultTableHandler(Singleton):
    def __init__(self, db_name: str):
        if not self._initialized:
            self.db_name = db_name

            self._initialized = True

    def insert(self, row: dict):
        pass

    def remove(self, index: int):
        pass

    def update(self, row: dict):
        pass

    def clear_data(self):
        pass

# ~~~~~~~~~~~~~~~ ~~~~~~~ ~~~~~~~~~~~~~~~

# ~~~~~~~~~~~~~~~ FRONTEND ~~~~~~~~~~~~~~~
class FieldType(Enum):
    ENTRY = auto()
    COMBOBOX = auto()
    SECURITY_ENTRY = auto()


class Application(tk.Tk):
    def __init__(self):
        super().__init__()
        self.encryptor = Encryptor()
        self.settings_handler = SettingsHandler(DB_NAME)
        self.db_handler = DBHandler(DB_NAME)

        # --- DB init & verify ---
        db_initer = DatabaseInitializer(DB_NAME, True)
        db_initer.verify_and_init_db()

        # --- build interface ---
        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}

        # add the menus
        for F in (MainMenu, LoginMenu, NewAccountMenu, NewRecordMenu, SettingsMenu):
            frame = F(parent=container, controller=self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.open_start_menu()

    def open_start_menu(self):
        authentication_value = self.settings_handler.get(SettingName.AUTHENTICATION)
        is_authentication = self.encryptor.unmask_boolean(SettingName.AUTHENTICATION.value, authentication_value)

        if is_authentication:
            user_count = self.db_handler.get_row_count(TableName.USERS)
            if user_count > 0:
                self.show_frame(LoginMenu)
            else:
                self.show_frame(NewAccountMenu)
        else:
            self.show_frame(MainMenu)

    def show_frame(self, frame_class):
        """Raise the specified frame to the top"""
        frame = self.frames[frame_class]
        frame.tkraise()


class MainMenu(ttk.Frame):
    def __init__(self, parent, controller, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)


class DataEntryForm(ttk.Frame):
    SECURITY_SIGN = "•"
    SHOW_PASSWORD_SIGN = "👁"
    HIDE_PASSWORD_SIGN = "🔒"

    def __init__(self, parent, title: str, fields_data: list[dict], button_parameters: list[dict], *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.fields_data = fields_data
        self.button_parameters = button_parameters
        self.vars = {}

        # Set column and row weights for resizing
        self.columnconfigure(0, weight=3)
        self.columnconfigure(1, weight=2)
        self.columnconfigure(2, weight=3)

        for i in range(1 + len(fields_data) + 1):   # title , len(fields_data), button_frame
            self.rowconfigure(i, weight=1)

        # Title
        self.title_frame = ttk.Frame(self)
        self.title_frame.grid(row=0, column=0, columnspan=3, sticky="s", pady=(20, 30))
        self.title_frame.columnconfigure(0, weight=1)

        self.title_label = ttk.Label(self.title_frame, text=title, font=("", 16, "bold"))
        self.title_label.grid(row=0, column=0)

        # Create form fields
        self._create_form_fields()

        # Create buttons
        self._create_buttons()

        # Add padding around all widgets
        for child in self.winfo_children():
            child.grid_configure(padx=10, pady=5)

    def __toggle_password_show(self, entry_widget, button_widget):
        if entry_widget.cget("show"):
            entry_widget.config(show="")
            button_widget.config(text=self.HIDE_PASSWORD_SIGN)
        else:
            entry_widget.config(show=self.SECURITY_SIGN)
            button_widget.config(text=self.SHOW_PASSWORD_SIGN)

    @staticmethod
    def __make_callback_func(func, *args):
        return lambda: func(*args)

    def _create_form_fields(self):
        """Create and arrange the form fields"""
        for i, field_data in enumerate(self.fields_data):
            label_text = field_data['var_name'].capitalize()
            if "_" in label_text:
                label_text = " ".join(field_data['var_name'].split("_"))
            label_text += ":"

            if field_data["type"] == FieldType.ENTRY:
                label = ttk.Label(self, text=label_text)
                label.grid(row=i + 1, column=0, sticky="e")

                self.vars[field_data["var_name"]] = tk.StringVar()

                entry = ttk.Entry(self, textvariable=self.vars[field_data["var_name"]])
                entry.grid(row=i + 1, column=1, sticky="ew")
            elif field_data["type"] == FieldType.SECURITY_ENTRY:
                label = ttk.Label(self, text=label_text)
                label.grid(row=i + 1, column=0, sticky="e")

                self.vars[field_data["var_name"]] = tk.StringVar()

                entry = ttk.Entry(self, textvariable=self.vars[field_data["var_name"]], show=self.SECURITY_SIGN)
                entry.grid(row=i + 1, column=1, sticky="ew")

                button_view = ttk.Button(self, text="👁", width=3)
                func = self.__make_callback_func(self.__toggle_password_show, entry, button_view)
                button_view.config(command=func)
                button_view.grid(row=i + 1, column=2, sticky="w")
            elif field_data["type"] == FieldType.COMBOBOX:
                label = ttk.Label(self, text=label_text)
                label.grid(row=i + 1, column=0, sticky="e")

                self.vars[field_data["var_name"]] = tk.StringVar(value=field_data["list"][0])

                combo = ttk.Combobox(self, textvariable=self.vars[field_data["var_name"]], values=field_data["list"])
                combo.grid(row=i + 1, column=1, sticky="ew")
                combo.state(["readonly"])

    def _create_buttons(self):
        """Create and arrange the buttons"""
        button_frame = ttk.Frame(self)
        button_frame.grid(row=len(self.fields_data) + 1, column=0, columnspan=3, sticky="n", pady=20)

        for i, parameters in enumerate(self.button_parameters):
            button = ttk.Button(button_frame, **parameters)
            button.grid(row=0, column=i, padx=10)

    def get_value(self, var_name):
        return self.vars[var_name].get()


class LoginMenu(ttk.Frame):
    def __init__(self, parent, controller, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)


class NewAccountMenu(ttk.Frame):
    def __init__(self, parent, controller, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.controller = controller
        self.parent = parent
        self.db_handler = DBHandler(DB_NAME)

        role_rows = self.db_handler.get(TableName.USER_ROLES)
        roles = [row["name"] for row in role_rows]

        self.entry_form_fields_data = [
            {"var_name": "username", "type": FieldType.ENTRY},
            {"var_name": "login", "type": FieldType.ENTRY},
            {"var_name": "password", "type": FieldType.SECURITY_ENTRY},
            {"var_name": "confirm_password", "type": FieldType.SECURITY_ENTRY},
            {"var_name": "role", "type": FieldType.COMBOBOX, "list": roles}
        ]
        self.vars_name = [field_data["var_name"] for field_data in self.entry_form_fields_data]
        self.entry_form_button_parameters = [
            {"text": "Create", "command": self.create_new_account},
            {"text": "Cancel", "command": None},
        ]

        self.data_entry_form = DataEntryForm(self, "Create New Account", self.entry_form_fields_data, self.entry_form_button_parameters)
        self.data_entry_form.pack(fill=tk.BOTH, expand=True)

    def create_new_account(self):
        pass

    def cancel(self):
        pass

    def set_first_account_mod(self):
        pass


class NewRecordMenu(ttk.Frame):
    def __init__(self, parent, controller, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)


class SettingsMenu(ttk.Frame):
    def __init__(self, parent, controller, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)

# ~~~~~~~~~~~~~~~ ~~~~~~~~ ~~~~~~~~~~~~~~~

if __name__ == "__main__":
    app = Application()
    app.mainloop()
