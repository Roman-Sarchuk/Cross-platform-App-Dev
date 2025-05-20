import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
from enum import Enum, auto
import os
import sys
from pathlib import Path
from cryptography.fernet import Fernet
import bcrypt
import hmac
import hashlib
from secrets import SystemRandom


class Singleton:
    _instance = None
    _initialized = False

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

# ~~~~~~~~~~~~~~~ BACKEND ~~~~~~~~~~~~~~~
DB_NAME = "data.db"
DEFAULT_ADMIN_ROLE = "admin"
DEFAULT_USER_ROLE = "user"


# --- enum classes ---
class TableName(Enum):
    USER_ROLES = "user_roles"
    USERS = "users"
    SETTINGS = "settings"


class SettingName(Enum):
    AUTHENTICATION = "authentication"


class AuthenticationResult(Enum):
    INCORRECT_LOGIN = "Incorrect Login!"
    INCORRECT_PASSWORD = "Incorrect Password!"
    SUCCESS = "Success"


# --- security ---
class KeyStorer(Singleton):
    KEY_FILE_NAME = "secret.key"

    def __init__(self):
        if not self._initialized:
            self.obfuscator = Obfuscator()
            self.__is_key_generated = False

            self.fernet_key = None

            self.key_file_path = self._get_local_file_path()
            if self.key_file_path.exists():
                self.load_fernet_key()
            else:
                self.__is_key_generated = True
                self.fernet_key = Fernet.generate_key()
                self.save_fernet_key()

            self._initialized = True

    def _get_local_file_path(self) -> Path:
        if getattr(sys, 'frozen', False):  # Якщо запаковано як .exe (PyInstaller тощо)
            base_path = Path(sys.executable).parent
        else:
            base_path = Path(__file__).resolve().parent

        return base_path / self.KEY_FILE_NAME

    def save_fernet_key(self):
        with open(self.key_file_path, "wb") as f:
            masked_key = self.obfuscator.mask_key(self.fernet_key)
            f.write(masked_key)
        try:
            os.chmod(self.key_file_path, 0o600)  # rw------- for user
        except Exception:
            pass

    def load_fernet_key(self):
        with open(self.key_file_path, "rb") as f:
            masked_key = f.read()
            self.fernet_key = self.obfuscator.unmask_key(masked_key)

    def get_fernet_key(self):
        return self.fernet_key

    def is_key_generated(self):
        return self.__is_key_generated


class Obfuscator(Singleton):
    KEY_LENGTH = 44
    CHUNK_LEN = 4

    def __init__(self):
        if not self._initialized:
            self.secure_random = SystemRandom()

            self._initialized = True

    def mask_key(self, f_key: bytes) -> bytes:
        key = f_key.decode()

        if len(key) != self.KEY_LENGTH:
            raise ValueError("Invalid key length")

        chunks = []
        for i, offset_i in enumerate(range(0, len(key), self.CHUNK_LEN)):
            chunk = key[offset_i:offset_i + self.CHUNK_LEN]
            index_char = chr(ord('a') + i)
            chunks.append(index_char + chunk)

        self.secure_random.shuffle(chunks)
        return ''.join(chunks).encode()

    @staticmethod
    def _split_index_and_chunk(indexed_chunk: str) -> tuple[int, str]:
        index_char = indexed_chunk[0]
        index = ord(index_char) - ord('a')

        chunk = indexed_chunk[1:]

        return index, chunk

    def unmask_key(self, masked_key: bytes) -> bytes:
        key = masked_key.decode()

        if len(key) != self.KEY_LENGTH + self.KEY_LENGTH // self.CHUNK_LEN:
            raise ValueError("Invalid key length")

        indexed_chunks = [key[i:i+self.CHUNK_LEN+1] for i in range(0, len(key), self.CHUNK_LEN+1)]
        chunks_with_index = [self._split_index_and_chunk(indexed_chunks[i]) for i in range(0, len(indexed_chunks))]

        sorted_chunks_with_index = sorted(chunks_with_index, key=lambda chunk_with_index: chunk_with_index[0])

        key_chunks = [chunk for _, chunk in sorted_chunks_with_index]
        return ''.join(key_chunks).encode()


class Encryptor(Singleton):
    def __init__(self):
        if not self._initialized:
            self.fernet_key = KeyStorer().get_fernet_key()
            self.cipher = Fernet(self.fernet_key)

            self._initialized = True

    def encrypt_with_fernet(self, data: str) -> str:
        return self.cipher.encrypt(data.encode()).decode()

    def decrypt_with_fernet(self, encrypted_data: str) -> str:
        return self.cipher.decrypt(encrypted_data.encode()).decode()

    @staticmethod
    def hash_with_salt(value: str) -> str:
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(value.encode('utf-8'), salt)
        return hashed.decode()

    @staticmethod
    def verify_salty_hash(value: str, hashed_value: str) -> bool:
        return bcrypt.checkpw(value.encode(), hashed_value.encode())

    def hash(self, text: str) -> str:
        h = hmac.new(self.fernet_key, text.encode(), hashlib.sha256)
        return h.hexdigest()

    def hash_boolean(self, key: str, boolean: bool) -> str:
        data = f"{key}:true" if boolean else f"{key}:false"
        return self.hash_with_salt(data)

    def match_boolean_hash(self, key: str, hashed_boolean: str) -> bool:
        if self.verify_salty_hash(f"{key}:true", hashed_boolean):
            return True
        elif self.verify_salty_hash(f"{key}:false", hashed_boolean):
            return False
        return None


# --- db handlers ---
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

    def get_rows(self, table: TableName, where: dict = None) -> list[dict]:
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

    def record_exists(self, table: TableName, where: dict) -> bool:
        return bool(self.get_rows(table, where))


class SettingsHandler(Singleton):
    def __init__(self, db_path: str):
        if not self._initialized:
            self.encryptor = Encryptor()
            self.db_handler = DBHandler(db_path)

            self._initialized = True

    def get(self, key: SettingName) -> str:
        hashed_key = self.encryptor.hash(key.value)
        rows = self.db_handler.get_rows(TableName.SETTINGS, {"key": hashed_key})
        return rows[0]["value"] if rows else None

    def get_value(self, key: SettingName) -> bool:
        hashed_value = self.get(key)
        return self.encryptor.match_boolean_hash(key.value, hashed_value) if hashed_value else None

    def insert(self, key: SettingName, value: bool):
        hashed_key = self.encryptor.hash(key.value)
        hashed_boolean = self.encryptor.hash_boolean(key.value, value)
        self.db_handler.insert(TableName.SETTINGS, {"key": hashed_key, "value": hashed_boolean})

    def update(self, key: SettingName, new_value: bool):
        hashed_key = self.encryptor.hash(key.value)
        hashed_boolean = self.encryptor.hash_boolean(key.value, new_value)
        self.db_handler.update(TableName.SETTINGS, {"value": hashed_boolean}, {"key": hashed_key})


class DatabaseInitializer(Singleton):
    REQUIRED_TABLES = {
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
                created_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(role_id) REFERENCES user_roles(id)
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
    }
    DEFAULT_USER_ROLES = [DEFAULT_ADMIN_ROLE, DEFAULT_USER_ROLE]

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
            hashed_setting_value = settings_handler.get(key)

            if hashed_setting_value is None:
                settings_handler.insert(key, value)
                self._log_info(f"🔧|🔼 Додано параметер '{key.value}' у таблицю 'settings' із значенням за замовчуванням")
            elif encryptor.match_boolean_hash(key.value, hashed_setting_value) is None:
                settings_handler.update(key, value)
                self._log_info(f"🔧|[❗] '{key.value}' пошкоджений у таблиці 'settings'; встановлено значення за замовчування")
            else:
                self._log_info(f"🔧|✅ '{key.value}' є валіде у таблицю 'settings'")

    def check_and_fill_user_roles(self):
        encryptor = Encryptor()
        db_handler = DBHandler(self.db_path)
        user_handler = UsersHandler(self.db_path)
        role_dict = user_handler.get_roles()

        for role_name in self.DEFAULT_USER_ROLES:
            if role_name not in role_dict:
                encrypted_role = encryptor.encrypt_with_fernet(role_name)
                db_handler.insert(TableName.USER_ROLES, {"name": encrypted_role})
                self._log_info(f"🎭|🔼 Додано базову роль '{role_name}' у таблицю 'user_roles'")
            else:
                self._log_info(f"🎭|✅ Базова роль '{role_name}' міститься у таблицю 'user_roles'")

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
    UNENCRYPTED_FIELDS = ["id", "password", "role_id", "login", "created_date"]
    FIELDS = ["id", "username", "login", "password", "role", "created_date"]

    def __init__(self, db_path: str):
        if not self._initialized:
            self.encryptor = Encryptor()
            self.db_handler = DBHandler(db_path)
            self.db_name = db_path
            self.authenticated_user = None

            self._initialized = True

    def add(self, username, login, password, role_id):
        hashed_password = self.encryptor.hash_with_salt(password)

        self.db_handler.insert(TableName.USERS, {
            "username": self.encryptor.encrypt_with_fernet(username),
            "login": login,
            "password": hashed_password,
            "role_id": role_id
        })

    def remove(self, user_id):
        self.db_handler.remove(TableName.USERS, {"id": user_id})

    def authenticate(self, login, password) -> AuthenticationResult:
        user_rows = self.db_handler.get_rows(TableName.USERS, {"login": login})

        if not user_rows:
            return AuthenticationResult.INCORRECT_LOGIN

        user_data = user_rows[0]

        if not self.encryptor.verify_salty_hash(password, user_data["password"]):
            return AuthenticationResult.INCORRECT_PASSWORD

        self.authenticated_user = user_data
        return AuthenticationResult.SUCCESS

    def authorize_authenticated_user(self) -> str:
        if self.authenticated_user is None:
            return None

        role_rows = self.db_handler.get_rows(TableName.USER_ROLES, {"id": self.authenticated_user["role_id"]})
        role = self.encryptor.decrypt_with_fernet(role_rows[0]["name"])

        if role == DEFAULT_ADMIN_ROLE:
            return DEFAULT_ADMIN_ROLE
        return DEFAULT_USER_ROLE

    def get_field_names(self):
        # with sqlite3.connect(self.db_name) as conn:
        #     cursor = conn.cursor()
        #     query = f"PRAGMA table_info({TableName.USERS.value});"
        #
        #     cursor.execute(query)
        #     columns_info = cursor.fetchall()    # cid | name | type | notnull | dflt_value | pk
        #     column_names = [col[1] for col in columns_info]
        #     return column_names
        return self.FIELDS

    def get_roles(self) -> dict[str, int]:
        role_rows = self.db_handler.get_rows(TableName.USER_ROLES)

        for role_row in role_rows:
            role_row["name"] = self.encryptor.decrypt_with_fernet(role_row["name"])

        return {role["name"]: role["id"] for role in role_rows}

    def logout_authenticated_user(self):
        self.authenticated_user = None

    def get_authenticated_user_name(self):
        return self.encryptor.decrypt_with_fernet(self.authenticated_user["username"]) if self.authenticated_user else None

    def get_records(self):
        query = f"""
        SELECT u.id, u.username, u.login,u.password, r.name as role, u.created_date FROM {TableName.USERS.value} as u 
        JOIN {TableName.USER_ROLES.value} as r ON u.role_id=r.id;
        """

        with sqlite3.connect(self.db_name) as conn:
            conn.row_factory = sqlite3.Row  # This enables column access by name
            cursor = conn.cursor()
            cursor.execute(query)
            rows = cursor.fetchall()
            records = [dict(row) for row in rows]

        for record in records:
            for key, value in record.items():
                if key not in self.UNENCRYPTED_FIELDS and value is not None:
                    record[key] = self.encryptor.decrypt_with_fernet(value)

        return records

# ~~~~~~~~~~~~~~~ ~~~~~~~ ~~~~~~~~~~~~~~~

# ~~~~~~~~~~~~~~~ FRONTEND ~~~~~~~~~~~~~~~
# enum class
class FieldType(Enum):
    ENTRY = auto()
    COMBOBOX = auto()
    SECURITY_ENTRY = auto()


# main class
class Application(tk.Tk):
    def __init__(self):
        super().__init__()
        self.encryptor = Encryptor()
        self.settings_handler = SettingsHandler(DB_NAME)
        self.db_handler = DBHandler(DB_NAME)

        # --- DB init & verify ---
        db_initer = DatabaseInitializer(DB_NAME, True)
        db_initer.verify_and_init_db()

        # user params
        self.is_authentication_turn_on = self.settings_handler.get_value(SettingName.AUTHENTICATION)
        self.access_role = None    # DEFAULT_ADMIN_ROLE or DEFAULT_USER_ROLE

        # --- build interface ---
        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        # --- menus ---
        self.frames = {}
        self.current_menu = None
        self.back_menu = None

        for F in (MainMenu, LoginMenu, NewAccountMenu):
            frame = F(parent=container, controller=self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.open_start_menu()

    def show_frame(self, frame_class):
        """Raise the specified frame to the top"""
        self.back_menu = self.current_menu
        self.current_menu = frame_class

        frame = self.frames[frame_class]
        self.event_generate("<<show_frame>>")
        frame.tkraise()

    def open_start_menu(self):
        if self.is_authentication_turn_on:
            user_count = self.db_handler.get_row_count(TableName.USERS)
            if user_count > 0:
                self.show_frame(LoginMenu)
            else:
                self.frames[NewAccountMenu].turn_on_first_account_mod()
                self.show_frame(NewAccountMenu)
        else:
            self.show_frame(MainMenu)

    def go_back_menu(self):
        if self.back_menu:
            self.show_frame(self.back_menu)
            self.back_menu = None
        else:
            self.open_start_menu()

    def set_access_role(self, access_role):
        self.access_role = access_role

    def get_access_role(self):
        return self.access_role

    def is_authentication(self):
        return self.is_authentication_turn_on


# --- menu frames ---
class MainMenu(ttk.Frame):
    def __init__(self, parent, controller: Application, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.parent = parent
        self.controller = controller
        self.users_handler = UsersHandler(DB_NAME)

        self.field_names = self.users_handler.get_field_names()

        self._build_interface()
        #self.update_frame()

        self.controller.bind("<<show_frame>>", self.update_frame, add="+")
        self.controller.bind("<<new_account_created>>", self.load_data, add="+")

    def _build_interface(self):
        # ----- Frame initialisation -----
        frame_header = ttk.Frame(self, padding=(5, 5, 5, 10), width=450)
        frame_header.pack(expand=True, fill=tk.X, padx=10, pady=10)
        frame_tree = ttk.Frame(self, width=450)
        frame_tree.pack(padx=10, pady=(0,10))
        # ----- ----- -------------- -----

        # ----- Set up Treeview -----
        scrollbar = ttk.Scrollbar(frame_tree, orient="vertical")
        scrollbar.pack(side="right", fill="y")

        self.tree = ttk.Treeview(
            frame_tree,
            columns=self.field_names,
            show="headings",
            height=10,
            yscrollcommand=scrollbar.set,
        )

        for field_name in self.field_names:
            self.tree.heading(field_name, text=field_name, anchor='w')
            self.tree.column(field_name, width=80, anchor="w") #, stretch=(i == 0 or i == len(self.FIELDS) - 1)

        self.tree.pack()

        self.load_data()

        scrollbar.config(command=self.tree.yview)
        # ----- --- -- -------- -----

        # ----- Set up Header frame -----
        self.user_label = ttk.Label(frame_header, text="USER-NAME")

        self.logout_button = ttk.Button(
            frame_header,
            text="Log Out", width=15,
            command=self.__on_logout_clicked
        )

        self.new_account_button = ttk.Button(
            frame_header,
            text="New Account", width=15,
            command=self.__on_new_account_clicked
        )
        # ----- --- -- ------- ----- -----

    def __create_modal(self, title: str) -> tk.Toplevel:
        top_level = tk.Toplevel(self.controller)

        # top_level setting
        top_level.title(title)
        top_level.resizable(width=False, height=False)
        top_level.transient(self.controller)
        top_level.grab_set()

        return top_level

    def load_data(self, event=None):
        # clear table
        for row in self.tree.get_children():
            self.tree.delete(row)

        # data getting from DB
        records = self.users_handler.get_records()

        # add records in the Treeview
        for record in records:
            self.tree.insert("", "end", values=[record[field] for field in self.field_names])

    def update_frame(self, event=None):
        if self.controller.is_authentication():
            self.user_label.configure(text=self.users_handler.get_authenticated_user_name())
            self.user_label.pack(side=tk.LEFT)
            if self.controller.get_access_role() == DEFAULT_ADMIN_ROLE:
                self.logout_button.pack(side=tk.RIGHT)
                self.new_account_button.pack(side=tk.RIGHT)
            else:
                self.logout_button.pack(side=tk.RIGHT)
                self.new_account_button.pack_forget()
        else:
            self.user_label.configure(text="ADMIN")
            self.user_label.pack(side=tk.LEFT)
            self.logout_button.pack_forget()
            self.new_account_button.pack(side=tk.RIGHT)

    def __on_new_account_clicked(self):
        modal = self.__create_modal("Add Record")

        frame = NewAccountMenu(parent=modal, controller=None, comm=lambda: self.__on_modal_new_account_created(modal))
        frame.grid(row=0, column=0, sticky="nsew")

    def __on_logout_clicked(self):
        self.users_handler.logout_authenticated_user()
        self.controller.open_start_menu()

    def __on_modal_new_account_created(self, modal):
        modal.destroy()
        self.load_data()


class DataEntryForm(ttk.Frame):
    SECURITY_SIGN = "•"
    SHOW_PASSWORD_SIGN = "👁"
    HIDE_PASSWORD_SIGN = "🔒"

    def __init__(self, parent, title: str, fields_data: list[dict], button_parameters: list[dict], *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.fields_data = fields_data
        self.button_parameters = button_parameters
        self.vars = {}
        self.control_widgets = {}   # field (entry/combobox + buttons)

        # Set column and row weights for resizing
        self.columnconfigure(0, weight=3)
        self.columnconfigure(1, weight=2)
        self.columnconfigure(2, weight=3)

        for i in range(len(fields_data) + 2):   # title , len(fields_data), button_frame
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

                self.control_widgets[field_data["var_name"]] = entry
            elif field_data["type"] == FieldType.SECURITY_ENTRY:
                label = ttk.Label(self, text=label_text)
                label.grid(row=i + 1, column=0, sticky="e")

                self.vars[field_data["var_name"]] = tk.StringVar()

                entry = ttk.Entry(self, textvariable=self.vars[field_data["var_name"]], show=self.SECURITY_SIGN)
                entry.grid(row=i + 1, column=1, sticky="ew")

                self.control_widgets[field_data["var_name"]] = entry

                button_view = ttk.Button(self, text="👁", width=3)
                func = self.__make_callback_func(self.__toggle_password_show, entry, button_view)
                button_view.config(command=func)
                button_view.grid(row=i + 1, column=2, sticky="w")
            elif field_data["type"] == FieldType.COMBOBOX:
                label = ttk.Label(self, text=label_text)
                label.grid(row=i + 1, column=0, sticky="e")

                self.vars[field_data["var_name"]] = tk.StringVar(value=field_data["list"][0])

                combo = ttk.Combobox(
                    self, textvariable=self.vars[field_data["var_name"]],
                    values=field_data["list"], state="readonly"
                )
                combo.grid(row=i + 1, column=1, sticky="ew")

                self.control_widgets[field_data["var_name"]] = combo

    def _create_buttons(self):
        """Create and arrange the buttons"""
        button_frame = ttk.Frame(self)
        button_frame.grid(row=len(self.fields_data) + 1, column=0, columnspan=3, sticky="n", pady=20)

        for i, parameters in enumerate(self.button_parameters):
            button = ttk.Button(button_frame, **parameters)
            button.grid(row=0, column=i, padx=10)
            self.control_widgets[parameters["text"].lower()] = button

    def get_field_value(self, var_name):
        return self.vars[var_name].get()

    def set_field_value(self, var_name, value):
        self.vars[var_name].set(value)

    def clear_form(self):
        for var in self.vars.values():
            var.set("")

    def config_control_widget(self, var_name, **kwargs):
        self.control_widgets[var_name].config(**kwargs)


class LoginMenu(ttk.Frame):
    def __init__(self, parent, controller: Application, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.controller = controller
        self.parent = parent
        self.user_handler = UsersHandler(DB_NAME)

        self.entry_form_fields_data = [
            {"var_name": "login", "type": FieldType.ENTRY},
            {"var_name": "password", "type": FieldType.SECURITY_ENTRY},
        ]
        self.var_names = [field_data["var_name"] for field_data in self.entry_form_fields_data]
        self.entry_form_button_parameters = [
            {"text": "Log In", "command": self.login, "width": 15},
        ]

        self.data_entry_form = DataEntryForm(
            self, "Login Menu",
            self.entry_form_fields_data, self.entry_form_button_parameters
        )
        self.data_entry_form.pack(fill=tk.BOTH, expand=True)

        self.controller.bind("<<show_frame>>", self.update_frame, add="+")

    def login(self):
        # varify empty fields
        for var_name in self.var_names:
            value = self.data_entry_form.get_field_value(var_name)
            if not value:
                messagebox.showwarning("Login Menu", f"The field '{var_name}' can't be empty!")
                return

        authentication_result = self.user_handler.authenticate(
            login = self.data_entry_form.get_field_value("login"),
            password = self.data_entry_form.get_field_value("password")
        )

        # check authentication
        if authentication_result != AuthenticationResult.SUCCESS:
            messagebox.showwarning("Login Menu", authentication_result.value)
            return

        # login
        access_level = self.user_handler.authorize_authenticated_user()
        self.controller.set_access_role(access_level)
        self.controller.show_frame(MainMenu)

    def update_frame(self, event):
        self.data_entry_form.clear_form()


class NewAccountMenu(ttk.Frame):
    def __init__(self, parent, controller:Application=None, comm=None, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.controller = controller
        self.parent = parent
        self.comm_on_new_account = comm
        self.db_handler = DBHandler(DB_NAME)
        self.user_handler = UsersHandler(DB_NAME)
        self.is_first_account_mod = False

        self.role_dict = self.user_handler.get_roles()   # name, id
        roles = tuple(self.role_dict.keys())

        self.entry_form_fields_data = [
            {"var_name": "username", "type": FieldType.ENTRY},
            {"var_name": "login", "type": FieldType.ENTRY},
            {"var_name": "password", "type": FieldType.SECURITY_ENTRY},
            {"var_name": "confirm_password", "type": FieldType.SECURITY_ENTRY},
            {"var_name": "role", "type": FieldType.COMBOBOX, "list": roles}
        ]
        self.var_names = [field_data["var_name"] for field_data in self.entry_form_fields_data]
        self.entry_form_button_parameters = [
            {"text": "Create", "command": self.create_new_account},
        ]

        self.data_entry_form = DataEntryForm(
            self, "Create New Account",
            self.entry_form_fields_data, self.entry_form_button_parameters
        )
        self.data_entry_form.pack(fill=tk.BOTH, expand=True)

        if self.controller:
            self.controller.bind("<<show_frame>>", self.update_frame, add="+")

    def create_new_account(self):
        user_values = {}

        # varify empty fields
        for var_name in self.var_names:
            value = self.data_entry_form.get_field_value(var_name)
            if not value:
                messagebox.showwarning("Creating New Account...", f"The field '{var_name}' can't be empty!")
                return
            user_values[var_name] = value

        # verify password == confirm_password
        if user_values["password"] != user_values["confirm_password"]:
            messagebox.showwarning("Creating New Account...", f"Password and confirm_password don't match!")
            return

        # verify login available
        if self.db_handler.record_exists(TableName.USERS, {"login": user_values["login"]}):
            messagebox.showwarning("Creating New Account...", "A user with that login already exists. Please choose a different login!")

        # create account
        self.user_handler.add(
            username = user_values["username"],
            login = user_values["login"],
            password = user_values["password"],
            role_id = self.role_dict[user_values["role"]]
        )

        if self.controller:
            self.controller.event_generate("<<new_account_created>>")
            self.controller.go_back_menu()

        if self.comm_on_new_account:
            self.comm_on_new_account()

        if self.is_first_account_mod:
            self.turn_off_first_account_mod()

    def update_frame(self, event):
        self.data_entry_form.clear_form()

    def turn_on_first_account_mod(self):
        self.is_first_account_mod = True

        self.data_entry_form.set_field_value("role", "admin")
        self.data_entry_form.config_control_widget("role", state="disabled")    # role combobox

    def turn_off_first_account_mod(self):
        self.is_first_account_mod = False

        self.data_entry_form.config_control_widget("role", state="readonly")    # role combobox
# ~~~~~~~~~~~~~~~ ~~~~~~~~ ~~~~~~~~~~~~~~~

if __name__ == "__main__":
    app = Application()
    app.mainloop()
