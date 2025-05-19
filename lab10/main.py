import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
from enum import Enum, auto
import os
import sys
from pathlib import Path
from cryptography.fernet import Fernet
import bcrypt
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
    LOGS = "logs"


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
    def hash(value: str) -> str:
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(value.encode('utf-8'), salt)
        return hashed.decode()

    @staticmethod
    def verify_hash(value: str, hashed_value: str) -> bool:
        return bcrypt.checkpw(value.encode(), hashed_value.encode())

    def hash_boolean(self, key: str, boolean: bool) -> str:
        data = f"{key}:true" if boolean else f"{key}:false"
        return self.hash(data)

    def match_boolean_hash(self, key: str, masked_boolean: str) -> bool:
        encoded_masked_boolean = masked_boolean
        if self.verify_hash(f"{key}:true", encoded_masked_boolean):
            return True
        elif self.verify_hash(f"{key}:false", encoded_masked_boolean):
            return False
        return None


# --- db handlers ---
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
        SettingName.LOGS: True,
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

        for role in self.DEFAULT_USER_ROLES:
            row = bd_handler.get_rows(TableName.USER_ROLES, {"name": role})
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
# ~~~~~~~~~~~~~~~ ~~~~~~~ ~~~~~~~~~~~~~~~

# ~~~~~~~~~~~~~~~ FRONTEND ~~~~~~~~~~~~~~~
class Application(tk.Tk):
    def __init__(self):
        super().__init__()
# ~~~~~~~~~~~~~~~ ~~~~~~~~ ~~~~~~~~~~~~~~~

if __name__ == "__main__":
    app = Application()
    app.mainloop()
