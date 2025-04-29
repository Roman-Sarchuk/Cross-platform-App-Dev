import random
import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import os
import string
import random
from enum import Enum


class Singleton:
    _instance = None
    _initialized = False

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance


class SettingName(Enum):
    AUTHENTICATION = "authentication"
    LOGS = "logs"


# ~~~~~~~~~~~~~~~ BACKEND ~~~~~~~~~~~~~~~
DB_NAME = "data.db"


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


class SettingsHandler(Singleton):
    def __init__(self, db_path: str):
        if not self._initialized:
            self.encryptor = Encryptor()
            self.db_path = db_path

            self._initialized = True

    def get(self, key: SettingName):
        masked_key = self.encryptor.mask_text(key.value)
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT key, value FROM settings WHERE key=?;",
                (masked_key,)
            )
            row = cursor.fetchone()
            if row:
                return {"key": row[0], "value": row[1]}
            return None

    def add(self, key: SettingName, value: bool):
        masked_key = self.encryptor.mask_text(key.value)
        masked_value = self.encryptor.mask_boolean(key.value, value)
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?)",
                (masked_key, masked_value)
            )

    def update(self, key: SettingName, value: bool):
        masked_key = self.encryptor.mask_text(key.value)
        masked_value = self.encryptor.mask_boolean(key.value, value)
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE settings SET value = ? WHERE key = ?",
                (masked_value, masked_key)
            )


class DatabaseInitializer(Singleton):
    REQUIRED_TABLES = {
        "workspace": '''
            CREATE TABLE IF NOT EXISTS workspace (
                id INTEGER PRIMARY KEY NOT NULL UNIQUE
            );
        ''',
        "user_roles": '''
            CREATE TABLE IF NOT EXISTS user_roles (
                id INTEGER PRIMARY KEY NOT NULL UNIQUE,
                name TEXT NOT NULL UNIQUE
            );
        ''',
        "users": '''
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
        "operation_types": '''
            CREATE TABLE IF NOT EXISTS operation_types (
                id INTEGER PRIMARY KEY NOT NULL UNIQUE,
                name TEXT NOT NULL UNIQUE
            );
        ''',
        "logs": '''
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
        "settings": '''
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
        if not self.connection and not self.cursor:
            self._log_info("🚫 Не підключений до DB, виконайте спершу connect_to_db_or_create()")

        encryptor = Encryptor()
        settings_handler = SettingsHandler(self.db_path)
        for key, value in self.SETTINGS.items():
            setting = settings_handler.get(key)

            if setting is None:
                settings_handler.add(key, value)
                self._log_info(f"🔧|🔼 Додано параметер '{key.value}' у таблицю 'settings' із значенням за замовчуванням")
            elif encryptor.unmask_boolean(key.value, setting["value"]) is None:
                settings_handler.update(key, value)
                self._log_info(f"🔧|[❗] '{key.value}' пошкоджений у таблиці 'settings'; встановлено значення за замовчування")
            else:
                self._log_info(f"🔧|✅ '{key.value}' є валіде у таблицю 'settings'")

    def _table_exists(self, table_name: str) -> bool:
        self.cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name=?;
        """, (table_name,))
        return self.cursor.fetchone() is not None

    def close(self):
        if self.connection:
            self.connection.close()
            self._log_info(f"[{self.__class__.__name__}]: 🔒 Підключення до БД закрито.")  # TODO: Debug.log

    def _log_info(self, text):
        if self.is_info_logging:
            self.logs.append(f"[{self.__class__.__name__}]: {text}")

    def print_logs(self):
        if self.logs:
            for log in self.logs:
                print(log)


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

class Application(tk.Tk):
    def __init__(self):
        super().__init__()
        # --- DB init & verify ---
        db_initer = DatabaseInitializer(DB_NAME, True)
        db_initer.connect_to_db_or_create()
        db_initer.check_and_create_tables()
        db_initer.verify_and_fill_settings()
        db_initer.print_logs()
        db_initer.close()

        # --- build interface ---
        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}

        # add the menus
        for F in (MainMenu, LoginMenu, NewAccountMenu, NewRecordMenu, SettingsMenu):
            frame = F(container)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.open_start_menu()

    def open_start_menu(self):
        settings_handler = SettingsHandler(DB_NAME)
        is_authentication = settings_handler.get(SettingName.AUTHENTICATION)
        self.show_frame(MainMenu)

    def show_frame(self, frame_class):
        """Raise the specified frame to the top"""
        frame = self.frames[frame_class]
        frame.tkraise()


class MainMenu(ttk.Frame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)


class LoginMenu(ttk.Frame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)


class NewAccountMenu(ttk.Frame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)


class NewRecordMenu(ttk.Frame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)


class SettingsMenu(ttk.Frame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)

# ~~~~~~~~~~~~~~~ ~~~~~~~~ ~~~~~~~~~~~~~~~

if __name__ == "__main__":
    app = Application()
    app.mainloop()
