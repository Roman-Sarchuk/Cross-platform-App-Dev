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
from re import fullmatch


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
    DEFAULT = "workspace"
    USER_ROLES = "user_roles"
    USERS = "users"
    SETTINGS = "settings"
    OPERATION_TYPES = "operation_types"
    LOGS = "logs"


class OperationType(Enum):
    LOGIN = "login"
    NEW_ACCOUNT = "new_account"
    LOGOUT = "logout"
    INSERT = "insert"
    UPDATE = "update"
    DELETE = "delete"
    NEW_COLUMN = "new_column"
    DELETE_COLUMN = "delete_column"
    RENAME_COLUMN = "update_column"


class SettingName(Enum):
    AUTHENTICATION = "authentication"
    LOGS = "logs"


class AuthenticationResult(Enum):
    INCORRECT_LOGIN = "Incorrect Login!"
    INCORRECT_PASSWORD = "Incorrect Password!"
    SUCCESS = "Success"


# --- security ---
class KeyStorer(Singleton):
    """
    Singleton-клас для зберігання та обробки симетричного ключа шифрування (Fernet).

    Ключ зберігається у локальному файлі (за замовчуванням "secret.key").
    Під час ініціалізації класу:
      - якщо файл з ключем існує — ключ завантажується;
      - якщо ні — генерується новий ключ, обфускується і зберігається.

    Attributes:
        KEY_FILE_NAME (str): назва для файлу, який містить ключ
        fernet_key (bytes): Поточний симетричний ключ шифрування.
        key_file_path (Path): Шлях до файлу з ключем.
    """
    KEY_FILE_NAME = "secret.key"

    def __init__(self):
        if not self._initialized:
            self.obfuscator = Obfuscator()

            self.fernet_key = None

            self.key_file_path = self._get_local_file_path()
            if self.key_file_path.exists():
                self.load_fernet_key()
            else:
                self.fernet_key = Fernet.generate_key()
                self.save_fernet_key()

            self._initialized = True

    def _get_local_file_path(self) -> Path:
        """
        Повертає шлях до файлу з ключем залежно від середовища виконання (звичайне чи заморожене)
        """
        if getattr(sys, 'frozen', False):  # Якщо запаковано як .exe (PyInstaller тощо)
            base_path = Path(sys.executable).parent
        else:
            base_path = Path(__file__).resolve().parent

        return base_path / self.KEY_FILE_NAME

    def save_fernet_key(self):
        """
        Обфускує поточний Fernet-ключ і зберігає його у файл з обмеженням доступу
        """
        with open(self.key_file_path, "wb") as f:
            masked_key = self.obfuscator.mask_key(self.fernet_key)
            f.write(masked_key)
        try:
            os.chmod(self.key_file_path, 0o600)  # rw------- for user
        except Exception:
            pass

    def load_fernet_key(self):
        """
        Завантажує Fernet-ключ з файлу, розшифровуючи його за допомогою обфускатора.
        """
        with open(self.key_file_path, "rb") as f:
            masked_key = f.read()
            self.fernet_key = self.obfuscator.unmask_key(masked_key)

    def get_fernet_key(self):
        return self.fernet_key


class Obfuscator(Singleton):
    """
    Singleton-клас для обфускації та деобфускації симетричного Fernet-ключа.

    Алгоритм обфускації:
      - Ключ ділиться на рівномірні частини (чанки).
      - До кожного чанка додається індекс у вигляді символу (a, b, c...).
      - Чанки перемішуються у випадковому порядку.

    Алгоритм деобфускації:
      - Розбиває рядок на чанки з індексами.
      - Сортує їх за індексами.
      - Відновлює оригінальний ключ.

    Attributes:
        KEY_LENGTH (int): Довжина очікуваного ключа (44 символи для Fernet).
        CHUNK_LEN (int): Розмір чанка в символах (4 символи).
        secure_random (SystemRandom): екземпдяр класу SystemRandom для безпечного рандому
    """
    KEY_LENGTH = 44
    CHUNK_LEN = 4

    def __init__(self):
        if not self._initialized:
            self.secure_random = SystemRandom()

            self._initialized = True

    def mask_key(self, f_key: bytes) -> bytes:
        """
        Обфускує переданий ключ Fernet.

        Додає до кожного чанка індексний символ, перемішує їх та повертає результат як байти.

        Args:
            f_key (bytes): Оригінальний Fernet-ключ (у байтах).

        Returns:
            bytes: Обфускований ключ.

        Raises:
            ValueError: Якщо довжина ключа не дорівнює KEY_LENGTH.
        """
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
        """
        Розділяє індексований чанк на індекс і значення чанка.

        Args:
            indexed_chunk (str): Чанк з індексом (наприклад, 'a1B3').

        Returns:
            tuple[int, str]: Індекс (0–n) та відповідний чанк, де n = KEY_LENGTH/CHUNK_LEN.
        """
        index_char = indexed_chunk[0]
        index = ord(index_char) - ord('a')

        chunk = indexed_chunk[1:]

        return index, chunk

    def unmask_key(self, masked_key: bytes) -> bytes:
        """
        Відновлює оригінальний ключ з обфускованого представлення.

        Розпарсює чанки з індексами, сортує та збирає ключ у правильному порядку.

        Args:
            masked_key (bytes): Обфускований ключ.

        Returns:
            bytes: Відновлений оригінальний ключ.

        Raises:
            ValueError: Якщо довжина обфускованого ключа некоректна (!= KEY_LENGTH + KEY_LENGTH / CHUNK_LEN).
        """
        key = masked_key.decode()

        if len(key) != self.KEY_LENGTH + self.KEY_LENGTH // self.CHUNK_LEN:
            raise ValueError("Invalid key length")

        indexed_chunks = [key[i:i+self.CHUNK_LEN+1] for i in range(0, len(key), self.CHUNK_LEN+1)]
        chunks_with_index = [self._split_index_and_chunk(indexed_chunks[i]) for i in range(0, len(indexed_chunks))]

        sorted_chunks_with_index = sorted(chunks_with_index, key=lambda chunk_with_index: chunk_with_index[0])

        key_chunks = [chunk for _, chunk in sorted_chunks_with_index]
        return ''.join(key_chunks).encode()


class Encryptor(Singleton):
    """
    Singleton-клас для шифрування, розшифрування, хешування та перевірки даних.

    Використовує Fernet (симетричне шифрування) для шифрування/дешифрування рядків.
    Використовує bcrypt для соленого хешування та перевірки.
    Також реалізує HMAC-хешування з ключем Fernet.

    Attributes:
        fernet_key (bytes): Симетричний ключ Fernet.
        cipher (Fernet): Об'єкт Fernet для шифрування/дешифрування.
    """

    def __init__(self):
        if not self._initialized:
            self.fernet_key = KeyStorer().get_fernet_key()
            self.cipher = Fernet(self.fernet_key)

            self._initialized = True

    def encrypt_with_fernet(self, data: str) -> str:
        """
        Шифрує рядок за допомогою Fernet.

        Args:
            data (str): Вхідний текст для шифрування.

        Returns:
            str: Зашифрований текст у форматі base64.
        """
        return self.cipher.encrypt(data.encode()).decode()

    def decrypt_with_fernet(self, encrypted_data: str) -> str:
        """
        Розшифровує текст, зашифрований Fernet.

        Args:
            encrypted_data (str): Зашифрований текст у форматі base64.

        Returns:
            str: Відновлений оригінальний текст.
        """
        return self.cipher.decrypt(encrypted_data.encode()).decode()

    @staticmethod
    def hash_with_salt(value: str) -> str:
        """
        Хешує рядок з використанням bcrypt з генерацією нового солі.

        Args:
            value (str): Текст для хешування.

        Returns:
            str: Солений bcrypt-хеш у вигляді рядка.
        """
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(value.encode('utf-8'), salt)
        return hashed.decode()

    @staticmethod
    def verify_salty_hash(value: str, hashed_value: str) -> bool:
        """
       Перевіряє відповідність рядка та bcrypt-хешу.

       Args:
           value (str): Оригінальний текст.
           hashed_value (str): Збережений bcrypt-хеш.

       Returns:
           bool: True, якщо текст відповідає хешу, інакше False.
       """
        return bcrypt.checkpw(value.encode(), hashed_value.encode())

    def hash(self, text: str) -> str:
        """
        Створює HMAC-SHA256 хеш тексту з використанням ключа Fernet у якості key.

        Args:
            text (str): Вхідний текст.

        Returns:
            str: Хеш у шістнадцятковому форматі.
        """
        h = hmac.new(self.fernet_key, text.encode(), hashlib.sha256)
        return h.hexdigest()

    def hash_boolean(self, key: str, boolean: bool) -> str:
        """
        Хешує булеве значення з ключем, додаючи "key:true" або "key:false" та солячи.

        Args:
            key (str): Ключ для створення рядка.
            boolean (bool): Булеве значення для хешування.

        Returns:
            str: Солений bcrypt-хеш.
        """
        data = f"{key}:true" if boolean else f"{key}:false"
        return self.hash_with_salt(data)

    def match_boolean_hash(self, key: str, hashed_boolean: str) -> bool:
        """
        Підбирає булеве значення, якому відповідає солений bcrypt-хеш
        що утворене за допомогою ключа.

        Args:
            key (str): Ключ, що використовувався при хешуванні.
            hashed_boolean (str): збережений хеш, утворений hash_boolean().

        Returns:
            bool: True або False, якщо є відповідність.
            None: Якщо відповідність не знайдена, що означає не коректний key або hashed_boolean
        """
        if self.verify_salty_hash(f"{key}:true", hashed_boolean):
            return True
        elif self.verify_salty_hash(f"{key}:false", hashed_boolean):
            return False
        return None


# --- db handlers ---
class DBHandler(Singleton):
    """
    Singleton-клас для роботи з базою даних SQLite.

    Забезпечує базові CRUD-операції: вибірка, вставка, оновлення та видалення записів.
    Підтримує формування умов WHERE з параметризованими запитами для безпеки.

    Методи використовують enum TableName для визначення таблиці.
    """

    @staticmethod
    def __extract_conditions_params(data: dict) -> tuple[list, list]:
        """
        Формує списки умов і параметрів для SQL-запитів WHERE.

        Args:
            data (dict): Словник ключ-значення для умов.

        Returns:
            tuple[list, list]: Список рядків умов та відповідних параметрів, наприклад, (["price=?", "count=?"],[100, 5])
        """
        conditions = []
        params = []

        for key, value in data.items():
            conditions.append(f"{key}=?")
            params.append(value)

        return conditions, params

    def get_rows(self, table: TableName, where: dict = None) -> list[dict]:
        """
        Отримує всі записи з таблиці, опціонально з умовами.

        Args:
            table (TableName): Таблиця для вибірки.
            where (dict, optional): Умови для WHERE (у форматі {поле: значення}).

        Returns:
            list[dict]: Список словників — записів таблиці у форматі {поле: значення}.
        """
        query = f"SELECT * FROM {table.value}"

        # Execute query and return results
        with sqlite3.connect(DB_NAME) as conn:
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

    @staticmethod
    def insert(table: TableName, row: dict):
        """
        Вставляє новий запис у таблицю.

        Args:
            table (TableName): Таблиця для вставки.
            row (dict): Дані нового запису (у форматі {поле: значення}).
        """
        query = f"INSERT INTO {table.value} ({", ".join(row.keys())}) VALUES ({", ".join("?" * len(row.values()))})"

        # Execute query
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute(query, tuple(row.values()))

    def remove(self, table: TableName, where: dict):
        """
        Видаляє записи з таблиці за заданими умовами.

        Args:
            table (TableName): Таблиця для видалення.
            where (dict): Умови для вибору записів для видалення (у форматі {поле: значення}).
        """
        conditions, params = self.__extract_conditions_params(where)

        query = f"DELETE FROM {table.value} WHERE {" AND ".join(conditions)}"

        # Execute query
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)

    def update(self, table: TableName, new_row_data: dict, where: dict):
        """
        Оновлює записи у таблиці за умовами.

        Args:
            table (TableName): Таблиця для оновлення.
            new_row_data (dict): Нові дані (у форматі {поле: значення}).
            where (dict): Умови для вибору записів для оновлення (у форматі {поле: значення}).
        """
        set_conditions, set_params = self.__extract_conditions_params(new_row_data)

        where_conditions, where_params = self.__extract_conditions_params(where)

        query = f"UPDATE {table.value} SET {", ".join(set_conditions)} WHERE {" AND ".join(where_conditions)}"

        # Execute query
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute(query, set_params + where_params)

    @staticmethod
    def get_row_count(table: TableName):
        """
        Повертає кількість рядків у таблиці.

        Args:
            table (TableName): Таблиця для підрахунку.

        Returns:
            int: Кількість записів у таблиці.
        """
        query = f"SELECT COUNT(*) FROM {table.value}"

        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute(query)
            return cursor.fetchone()[0]

    def record_exists(self, table: TableName, where: dict) -> bool:
        """
        Перевіряє, чи існує запис у таблиці за заданими умовами.

        Args:
            table (TableName): Таблиця для перевірки.
            where (dict): Умови пошуку.

        Returns:
            bool: True, якщо є хоча б один запис, інакше False.
        """
        return bool(self.get_rows(table, where))


class SettingsHandler(Singleton):
    """
    Singleton-клас для роботи з налаштуваннями додатку.

    Забезпечує збереження, оновлення та отримання налаштувань у базі даних.
    Використовує хешування ключів і значень для безпечного зберігання.
    Ключі та булеві значення зберігаються у вигляді захешованих рядків.

    Attributes:
        encryptor (Encryptor): Об’єкт для шифрування і хешування.
        db_handler (DBHandler): Об’єкт для роботи з базою даних.
    """

    def __init__(self):
        if not self._initialized:
            self.encryptor = Encryptor()
            self.db_handler = DBHandler()

            self._initialized = True

    def get(self, key: SettingName) -> str:
        """
        Отримує хешоване значення налаштування за ключем.

        Args:
            key (SettingName): Назва налаштування.

        Returns:
            str | None: Хешоване значення, або None якщо налаштування відсутнє.
        """
        hashed_key = self.encryptor.hash(key.value)
        rows = self.db_handler.get_rows(TableName.SETTINGS, {"key": hashed_key})
        return rows[0]["value"] if rows else None

    def get_value(self, key: SettingName) -> bool:
        """
        Отримує булеве значення налаштування за ключем.
        Виконує перевірку відповідності хешу до булевого значення.

        Args:
            key (SettingName): Назва налаштування.

        Returns:
            bool | None: Значення налаштування або None, якщо відсутнє.
        """
        hashed_value = self.get(key)
        return self.encryptor.match_boolean_hash(key.value, hashed_value) if hashed_value else None

    def insert(self, key: SettingName, value: bool):
        """
        Додає нове налаштування з булевим значенням.
        Ключ і значення хешуються для безпечного зберігання.

        Args:
            key (SettingName): Назва налаштування.
            value (bool): Булеве значення.
        """
        hashed_key = self.encryptor.hash(key.value)
        hashed_boolean = self.encryptor.hash_boolean(key.value, value)
        self.db_handler.insert(TableName.SETTINGS, {"key": hashed_key, "value": hashed_boolean})

    def update(self, key: SettingName, new_value: bool):
        """
        Оновлює значення існуючого налаштування.

        Args:
            key (SettingName): Назва налаштування.
            new_value (bool): Нове булеве значення.
        """
        hashed_key = self.encryptor.hash(key.value)
        hashed_boolean = self.encryptor.hash_boolean(key.value, new_value)
        self.db_handler.update(TableName.SETTINGS, {"value": hashed_boolean}, {"key": hashed_key})


class DatabaseInitializer(Singleton):
    """
    Singleton-клас для ініціалізації та валідації структури бази даних.

    Забезпечує:
    - Підключення до існуючої або створення нової SQLite бази даних.
    - Перевірку існування необхідних таблиць і їх створення за потреби.
    - Валідацію і додавання базових налаштувань, ролей користувачів і типів операцій.
    - Внутрішнє логування процесу ініціалізації (опційно).

    Attributes:
        REQUIRED_TABLES (dict): SQL-запити для створення необхідних таблиць.
        SETTINGS (dict): Параметри налаштувань за замовчуванням.
        DEFAULT_USER_ROLES (list): Список базових ролей користувачів для додавання.
        is_info_logging (bool): Прапорець для виводу логів.
        logs (list): Збереження тексту логів.
        encryptor (Encryptor): Обʼєкт для шифрування і хешування.
        db_handler (DBHandler): Обʼєкт для роботи з БД.
        settings_handler (SettingsHandler): Обʼєкт для роботи з налаштуваннями.
        users_handler (UsersHandler): Обʼєкт для роботи з користувачами.
        logger (Logger): Обʼєкт для логування операцій.
        connection (sqlite3.Connection | None): Зʼєднання з БД.
        cursor (sqlite3.Cursor | None): Курсор для виконання SQL-запитів.
    """
    REQUIRED_TABLES = {
        TableName.DEFAULT.value: f'''
            CREATE TABLE IF NOT EXISTS {TableName.DEFAULT.value} (
                id INTEGER PRIMARY KEY
            );
        ''',
        TableName.USER_ROLES.value: f'''
            CREATE TABLE IF NOT EXISTS {TableName.USER_ROLES.value} (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE
            );
        ''',
        TableName.USERS.value: f'''
            CREATE TABLE IF NOT EXISTS {TableName.USERS.value} (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                login TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                role_id INTEGER NOT NULL,
                created_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(role_id) REFERENCES user_roles(id)
            );
        ''',
        TableName.SETTINGS.value: f'''
            CREATE TABLE IF NOT EXISTS {TableName.SETTINGS.value} (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
        ''',
        TableName.OPERATION_TYPES.value: f'''
            CREATE TABLE IF NOT EXISTS {TableName.OPERATION_TYPES.value} (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                hashed_name TEXT NOT NULL UNIQUE
            );
        ''',
        TableName.LOGS.value: f'''
            CREATE TABLE IF NOT EXISTS {TableName.LOGS.value} (
                id INTEGER PRIMARY KEY,
                operation_type_id INTEGER NOT NULL,
                user_id INTEGER,
                log_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                description TEXT,
                FOREIGN KEY(operation_type_id) REFERENCES operation_types(id),
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
        '''
    }
    SETTINGS = {
        SettingName.AUTHENTICATION: True,
        SettingName.LOGS: True
    }
    DEFAULT_USER_ROLES = [DEFAULT_ADMIN_ROLE, DEFAULT_USER_ROLE]

    def __init__(self, is_info_logging=False):
        if not self._initialized:
            self.is_info_logging = is_info_logging
            self.logs = []

            self.encryptor = Encryptor()
            # db handlers
            self.db_handler = DBHandler()
            self.settings_handler = SettingsHandler()
            self.users_handler = UsersHandler()
            self.logger = Logger()

            self.connection = None
            self.cursor = None

            self._initialized = True

    def _connect_to_db_or_create(self):
        """
        Підключається до файлу бази даних SQLite або створює новий, якщо файл не існує.
        """
        db_exists = os.path.exists(DB_NAME)
        self.connection = sqlite3.connect(DB_NAME)
        self.cursor = self.connection.cursor()

        if not db_exists:
            self._log_info(f"🔗|📁 Створено файл БД: {DB_NAME}")
        else:
            self._log_info(f"🔗|✅ Підключено до наявної БД: {DB_NAME}")

    def _check_and_create_tables(self):
        """
        Перевіряє наявність необхідних таблиць у БД.
        Якщо таблиця відсутня — створює її.
        """
        if not self.connection and not self.cursor:
            self._log_info("🚫 Не підключений до DB, виконайте спершу connect_to_db_or_create()")

        for table_name, sql in self.REQUIRED_TABLES.items():
            if not self._table_exists(table_name):
                self.cursor.execute(sql)
                self.connection.commit()
                self._log_info(f"📄|🧱 Створено таблицю: {table_name}")
            else:
                self._log_info(f"📄|✅ Таблиця вже існує: {table_name}")

    def _verify_and_fill_settings(self):
        """
        Перевіряє наявність обовʼязкових налаштувань у таблиці 'settings'.
        Якщо налаштування відсутні або пошкоджені, додає або оновлює їх значення за замовчуванням.
        """
        for key, value in self.SETTINGS.items():
            hashed_setting_value = self.settings_handler.get(key)

            if hashed_setting_value is None:
                self.settings_handler.insert(key, value)
                self._log_info(f"🔧|🔼 Додано параметер '{key.value}' у таблицю 'settings' із значенням за замовчуванням")
            elif self.encryptor.match_boolean_hash(key.value, hashed_setting_value) is None:
                self.settings_handler.update(key, value)
                self._log_info(f"🔧|[❗] '{key.value}' пошкоджений у таблиці 'settings'; встановлено значення за замовчування")
            else:
                self._log_info(f"🔧|✅ '{key.value}' є валіде у таблицю 'settings'")

    def _check_and_fill_user_roles(self):
        """
        Перевіряє наявність базових ролей користувачів у таблиці 'user_roles'.
        Якщо базова роль відсутня — додає її.
        """
        role_dict = self.users_handler.get_roles()

        for role_name in self.DEFAULT_USER_ROLES:
            if role_name not in role_dict:
                encrypted_role = self.encryptor.encrypt_with_fernet(role_name)
                self.db_handler.insert(TableName.USER_ROLES, {"name": encrypted_role})
                self._log_info(f"🎭|🔼 Додано базову роль '{role_name}' у таблицю 'user_roles'")
            else:
                self._log_info(f"🎭|✅ Базова роль '{role_name}' міститься у таблицю 'user_roles'")

    def _check_and_fill_operation_types(self):
        """
        Перевіряє наявність типів операцій у таблиці 'operation_types'.
        Якщо тип операції відсутній — додає його.
        """
        operation_types = self.logger.get_operation_types()

        for op in OperationType:
            if op.value not in operation_types:
                self.db_handler.insert(TableName.OPERATION_TYPES, {
                    "name": self.encryptor.encrypt_with_fernet(op.value),
                    "hashed_name": self.encryptor.hash(op.value)
                })
                self._log_info(f"📜|🔼 Додано тип операції '{op.value}' у таблицю 'operation_types'")
            else:
                self._log_info(f"📜|✅ Тип операції '{op.value}' міститься у таблицю 'operation_types'")

    def verify_and_init_db(self):
        """
        Послідовно виконує всі кроки ініціалізації бази даних
        """
        self._connect_to_db_or_create()
        self._check_and_create_tables()
        self._verify_and_fill_settings()
        self._check_and_fill_user_roles()
        self._check_and_fill_operation_types()
        self.print_logs()
        self._close()

    def _table_exists(self, table_name: str) -> bool:
        """
        Перевіряє, чи існує таблиця з назвою `table_name` у базі даних.

        Args:
            table_name (str): Назва таблиці для перевірки.

        Returns:
            bool: True, якщо таблиця існує, інакше False.
        """
        self.cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name=?;
        """, (table_name,))
        return self.cursor.fetchone() is not None

    def _close(self):
        """
        Закриває підключення до бази даних, якщо воно відкрито.
        """
        if self.connection:
            self.connection.close()
            self._log_info(f"[{self.__class__.__name__}]: 🔒 Підключення до БД закрито.")

    def _log_info(self, text):
        """
        Додає повідомлення до логів, якщо увімкнено логування.

        Args:
            text (str): Текст повідомлення для логу.
        """
        if self.is_info_logging:
            self.logs.append(f"[{self.__class__.__name__}]: {text}")

    def print_logs(self):
        """
        Виводить накопичені логи у консоль.
        """
        if self.logs:
            for log in self.logs:
                print(log)


class Logger(Singleton):
    """
    Singleton-клас для ведення системного логування дій користувачів та операцій у додатку.

    Забезпечує:
    - Додавання логів до таблиці 'logs'.
    - Видачеюе дешифрованих записів для відображення.
    - Керування станом логування.
    - Очищення логів.
    - Встановлення поточного користувача для привʼязки до логів.

    Attributes:
        UNENCRYPTED_FIELDS (list[str]): Поля, що не потребують дешифрування в таблиці логів.
        FIELDS (list[str]): Список полів, що повертаються при отриманні записів.
        db_handler (DBHandler): Обʼєкт доступу до БД.
        encryptor (Encryptor): Клас для шифрування/дешифрування даних.
        user_id (int | None): Ідентифікатор поточного користувача.
        is_logging_turn_on (bool): Чи ввімкнене логування.
    """
    UNENCRYPTED_FIELDS = ["id", "date", "description"]
    FIELDS = ["id", "operation", "username", "role", "date", "description"]

    def __init__(self):
        if not self._initialized:
            self.db_handler = DBHandler()
            self.encryptor = Encryptor()
            self.user_id = None
            self.is_logging_turn_on = False

            self._initialized = True

    def set_user_id(self, user_id: int):
        """
        Встановлює ID поточного користувача для привʼязки до логів.

        Args:
            user_id (int | None): Ідентифікатор користувача.
        """
        self.user_id = user_id

    def get_operation_types(self) -> list[str]:
        """
        Повертає список назв усіх типів операцій, розшифрованих із таблиці 'operation_types'.

        Returns:
            list[str]: Розшифровані назви типів операцій.
        """
        rows = self.db_handler.get_rows(TableName.OPERATION_TYPES)

        operation_types = []
        for row in rows:
            operation_types.append(self.encryptor.decrypt_with_fernet(row["name"]))

        return operation_types

    def add(self, operation_type: OperationType, description:str=""):
        """
        Додає запис до таблиці логів, якщо логування увімкнене.

        Args:
            operation_type (OperationType): Тип операції, що логуватиметься.
            description (str, optional): Опис операції. За замовчуванням порожній рядок.
        """
        if not self.is_logging_turn_on:
            return

        operation_type_rows = self.db_handler.get_rows(
            TableName.OPERATION_TYPES, {"hashed_name": self.encryptor.hash(operation_type.value)}
        )
        operation_type_id = operation_type_rows[0]["id"]

        if not self.user_id:
            self.db_handler.insert(TableName.LOGS, {
                "operation_type_id": operation_type_id,
                "description": description
            })
        else:
            self.db_handler.insert(TableName.LOGS, {
                "operation_type_id": operation_type_id,
                "user_id": self.user_id,
                "description": description
            })

    def get_records(self):
        """
        Повертає всі записи з таблиці логів у вигляді словників з розшифрованими полями.

        Returns:
            list[dict]: Список логів у форматі {поле: значення}.
        """
        query = f"""
        SELECT l.id, o.name as operation, u.username, r.name as role, l.log_date as date, l.description
        FROM {TableName.LOGS.value} as l 
        JOIN {TableName.OPERATION_TYPES.value} as o ON l.operation_type_id=o.id
        LEFT JOIN {TableName.USERS.value} as u ON l.user_id=u.id
        LEFT JOIN {TableName.USER_ROLES.value} as r on u.role_id=r.id;
        """

        with sqlite3.connect(DB_NAME) as conn:
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

    def get_field_names(self):
        return self.FIELDS

    def set_logging_state(self, value: bool):
        self.is_logging_turn_on = value

    @staticmethod
    def clear_logs():
        """
        Очищає всі записи з таблиці 'logs'.
        """
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM logs;")


class UsersHandler(Singleton):
    """
    Клас-обгортка для роботи з користувачами системи.

    Забезпечує:
    - Реєстрацію, автентифікацію та авторизацію користувачів.
    - Отримання ролей користувачів.
    - Ведення логування операцій (вхід, вихід, створення, видалення).
    - Отримання та дешифрування даних користувачів для відображення.

    Attributes:
        UNENCRYPTED_FIELDS (list[str]): Список полів, які не шифруються у БД.
        FIELDS (list[str]): Поля для таблиці користувачів при виведенні.
        encryptor (Encryptor): Клас для шифрування/дешифрування даних.
        db_handler (DBHandler): Обʼєкт доступу до БД.
        logger (Logger): Обʼєкт взаємодії із логами.
        authenticated_user (dict | None): Поточний автентифікований користувач.
    """
    UNENCRYPTED_FIELDS = ["id", "password", "role_id", "login", "created_date"]
    FIELDS = ["id", "username", "login", "password", "role", "created_date"]

    def __init__(self):
        if not self._initialized:
            self.encryptor = Encryptor()
            self.db_handler = DBHandler()
            self.logger = Logger()
            self.authenticated_user = None

            self._initialized = True

    def add(self, username, login, password, role_id):
        """
        Додає нового користувача до БД з шифруванням і хешуванням пароля.
        Якщо додавання відбувається під час ініціалізації першого користувача — встановлюється user_id для логування.

        Args:
            username (str): Ім'я користувача.
            login (str): Унікальний логін.
            password (str): Пароль у відкритому вигляді.
            role_id (int): ID відповідної ролі користувача.
        """
        hashed_password = self.encryptor.hash_with_salt(password)

        self.db_handler.insert(TableName.USERS, {
            "username": self.encryptor.encrypt_with_fernet(username),
            "login": login,
            "password": hashed_password,
            "role_id": role_id
        })

        if self.logger.user_id:
            self.logger.add(OperationType.NEW_ACCOUNT)
        else:
            rows = self.db_handler.get_rows(TableName.USERS, {"login": login})
            user_id = rows[0]["id"]
            self.logger.set_user_id(user_id)
            self.logger.add(OperationType.NEW_ACCOUNT, description="initial account")

    def remove(self, user_id):
        """
        Видаляє користувача за його ID та логуює дію з розшифрованими даними.

        Args:
            user_id (int): ID відповідного користувача.
        """
        row = self.db_handler.get_rows(TableName.USERS, {"id": user_id})[0]
        for k, v in row.items():
            if k not in self.UNENCRYPTED_FIELDS:
                row[k] = self.encryptor.decrypt_with_fernet(v)

        self.db_handler.remove(TableName.USERS, {"id": user_id})

        self.logger.add(OperationType.DELETE, description=str(row))

    def authenticate(self, login, password) -> AuthenticationResult:
        """
        Автентифікує користувача за логіном та паролем.
        Повертає відповідний результат автентифікації, встановлює користувача як поточного.

        Args:
            login (str): Логін користувача.
            password (str): Пароль у відкритому вигляді.

        Returns:
            AuthenticationResult: Результат (SUCCESS | INCORRECT_LOGIN | INCORRECT_PASSWORD).
        """
        user_rows = self.db_handler.get_rows(TableName.USERS, {"login": login})

        if not user_rows:
            return AuthenticationResult.INCORRECT_LOGIN

        user_data = user_rows[0]

        if not self.encryptor.verify_salty_hash(password, user_data["password"]):
            return AuthenticationResult.INCORRECT_PASSWORD

        self.authenticated_user = user_data
        self.logger.set_user_id(user_data["id"])
        self.logger.add(OperationType.LOGIN,)
        return AuthenticationResult.SUCCESS

    def authorize_authenticated_user(self) -> str:
        """
        Визначає роль поточного автентифікованого користувача.

        Returns:
            str | None: Роль користувача (адміністратор або користувач), або None, якщо не авторизований.
        """
        if self.authenticated_user is None:
            return None

        role_rows = self.db_handler.get_rows(TableName.USER_ROLES, {"id": self.authenticated_user["role_id"]})
        role = self.encryptor.decrypt_with_fernet(role_rows[0]["name"])

        if role == DEFAULT_ADMIN_ROLE:
            return DEFAULT_ADMIN_ROLE
        return DEFAULT_USER_ROLE

    def get_field_names(self):
        """
        Повертає список імен полів для таблиці користувачів.

        Returns:
            list[str]: Назви полів.
        """
        return self.FIELDS

    def get_roles(self) -> dict[str, int]:
        """
        Отримує список ролей користувачів з розшифрованими назвами.

        Returns:
            dict[str, int]: Назва ролі, ID.
        """
        role_rows = self.db_handler.get_rows(TableName.USER_ROLES)

        for role_row in role_rows:
            role_row["name"] = self.encryptor.decrypt_with_fernet(role_row["name"])

        return {role["name"]: role["id"] for role in role_rows}

    def logout_authenticated_user(self):
        self.logger.add(OperationType.LOGOUT)
        self.authenticated_user = None
        self.logger.set_user_id(None)

    def get_authenticated_user_name(self):
        return self.encryptor.decrypt_with_fernet(self.authenticated_user["username"]) if self.authenticated_user else ""

    def get_records(self):
        """
        Повертає всі користувацькі записи з таблиці 'users', розшифровуючи відповідні поля.

        Returns:
            list[dict]: Список записів користувачів.
        """
        query = f"""
        SELECT u.id, u.username, u.login,u.password, r.name as role, u.created_date FROM {TableName.USERS.value} as u 
        JOIN {TableName.USER_ROLES.value} as r ON u.role_id=r.id;
        """

        with sqlite3.connect(DB_NAME) as conn:
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


class DefaultTableHandler(Singleton):
    """
    Клас для керування головною (workspace) таблицею в базі даних.

    Реалізує:
    - Додавання, редагування, видалення записів.
    - Роботу з колонками: додавання, видалення, перейменування.
    - Шифрування/дешифрування даних перед збереженням або отриманням.
    - Логування всіх змін.

    Attributes:
        UNENCRYPTED_FIELDS (list[str]): Список незашифрованих полів (наприклад, id).
        encryptor (Encryptor): Клас для шифрування/дешифрування даних.
        db_handler (DBHandler): Обʼєкт доступу до БД.
        logger (Logger): Обʼєкт взаємодії із логами.
    """
    UNENCRYPTED_FIELDS = ["id"]

    def __init__(self):
        if not self._initialized:
            self.encryptor = Encryptor()
            self.db_handler = DBHandler()
            self.logger = Logger()

            self._initialized = True

    def add_record(self, row: dict):
        """
        Додає новий запис до таблиці, попередньо зашифрувавши всі значення.

        Args:
            row (dict): Дані нового запису (у форматі {поле: значення}).
        """
        for k, v in row.items():
            row[k] = self.encryptor.encrypt_with_fernet(v)

        self.db_handler.insert(TableName.DEFAULT, row)
        self.logger.add(OperationType.INSERT)

    def _find_id_by_row(self, row: dict):
        """
        Знаходить ID запису, що повністю збігається з вхідним словником (після дешифрування).

        Args:
            row (dict): Значення полів, які мають співпасти (у форматі {поле: значення}). Вимагається весь рядок

        Returns:
            int | None: ID запису або None, якщо не знайдено.
        """
        data = self.db_handler.get_rows(TableName.DEFAULT)
        for record in data:
            for k, v in record.items():
                if k not in self.UNENCRYPTED_FIELDS:
                    record[k] = self.encryptor.decrypt_with_fernet(v)
            if all(record.get(key) == row.get(key) for key in row.keys()):
                return record.get('id')
        return None

    def delete_record(self, row: dict):
        """
        Видаляє запис, який повністю збігається з вхідними даними (після дешифрування).

        Args:
            row (dict): Значення полів запису, який треба видалити (у форматі {поле: значення}). Вимагається весь рядок
        """
        row_id = self._find_id_by_row(row)

        self.db_handler.remove(TableName.DEFAULT, {"id": row_id})
        self.logger.add(OperationType.DELETE, description=str(row))

    def edit_record(self, old_record: dict, new_row: dict):
        """
        Оновлює поля запису, які змінилися.

        Args:
            old_record (dict): Поточні значення запису (у форматі {поле: значення}). Вимагається весь рядок
            new_row (dict): Нові значення полів (у форматі {поле: значення}). Достатньо зазначити лише нові
                            дані, а не весь рядок
        """
        row_id = self._find_id_by_row(old_record)

        new_data = {}

        for key, value in new_row.items():
            if old_record[key] != new_row[key]:
                new_data[key] = self.encryptor.encrypt_with_fernet(value)

        if new_data:
            self.db_handler.update(TableName.DEFAULT, new_data, {"id": row_id})
            self.logger.add(OperationType.UPDATE, description=f"{new_data} -> {old_record}")

    def add_column(self, name: str):
        """
        Додає нову колонку до таблиці.

        Args:
            name (str): Назва нової колонки.
        """
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute(f'ALTER TABLE {TableName.DEFAULT.value} ADD COLUMN {name} TEXT DEFAULT "";')
        self.logger.add(OperationType.NEW_COLUMN)

    def delete_column(self, name: str):
        """
        Видаляє колонку з таблиці.

        Args:
            name (str): Назва колонки для видалення.
        """
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute(f"ALTER TABLE {TableName.DEFAULT.value} DROP COLUMN {name};")
        self.logger.add(OperationType.DELETE_COLUMN, name)

    def rename_column(self, old_name: str, new_name: str):
        """
        Перейменовує колонку в таблиці.

        Args:
            old_name (str): Поточна назва колонки.
            new_name (str): Нова назва колонки.
        """
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            cursor.execute(f"ALTER TABLE {TableName.DEFAULT.value} RENAME COLUMN {old_name} TO {new_name};")
        self.logger.add(OperationType.RENAME_COLUMN, f"{old_name} -> {new_name}")

    @staticmethod
    def get_field_names():
        """
        Повертає список назв всіх колонок таблиці, окрім 'id'.

        Returns:
            list[str]: Список колонок.
        """
        with sqlite3.connect(DB_NAME) as conn:
            cursor = conn.cursor()
            query = f"PRAGMA table_info({TableName.DEFAULT.value});"

            cursor.execute(query)
            columns_info = cursor.fetchall()    # cid | name | type | notnull | dflt_value | pk
            column_names = [col[1] for col in columns_info]
            column_names.remove("id")
            return column_names

    def get_records(self):
        """
        Повертає всі записи з таблиці, розшифрувавши значення, окрім поля 'id'.

        Returns:
            list[dict]: Список розшифрованих записів (у форматі {поле: значення}).
        """
        rows = self.db_handler.get_rows(TableName.DEFAULT)
        for row in rows:
            row.pop("id")
            for k, v in row.items():
                row[k] = self.encryptor.decrypt_with_fernet(v)
        return rows

# ~~~~~~~~~~~~~~~ ~~~~~~~ ~~~~~~~~~~~~~~~

# ~~~~~~~~~~~~~~~ FRONTEND ~~~~~~~~~~~~~~~

# enum class
class FieldType(Enum):
    ENTRY = auto()
    COMBOBOX = auto()
    SECURITY_ENTRY = auto()


# main class
class Application(tk.Tk):
    """
    Головний клас GUI-застосунку Arcanite, побудованого на бібліотеці Tkinter.

    Відповідає за:
    - Виклик ініціалізатора бази даних
    - Побудову графічного інтерфейсу та взаємодію між різними екранами (меню).
    - Обробку зміни екранів

    Attributes:
        encryptor (Encryptor): Клас для шифрування/дешифрування даних.
        settings_handler (SettingsHandler): Обʼєкт для роботи з налаштуваннями.
        db_handler (DBHandler): Обʼєкт доступу до БД.
        access_role (str | None): Роль поточного користувача (адміністратор або користувач).
        var_authentication (tk.BooleanVar): Стан налаштування аутентифікації.
        var_logging (tk.BooleanVar): Стан налаштування логування.
        frames (dict): Словник з усіма створеними фреймами меню.
        current_menu (type): Поточний активний фрейм.
        back_menu (type | None): Попередній фрейм для повернення назад.
    """

    def __init__(self):
        super().__init__()
        # DB init & verify
        db_initer = DatabaseInitializer()
        db_initer.verify_and_init_db()

        # DB interaction
        self.encryptor = Encryptor()
        self.settings_handler = SettingsHandler()
        self.db_handler = DBHandler()

        # user params
        self.access_role = None    # DEFAULT_ADMIN_ROLE or DEFAULT_USER_ROLE
        self.var_authentication = tk.BooleanVar(value=self.settings_handler.get_value(SettingName.AUTHENTICATION))
        self.var_logging = tk.BooleanVar(value=self.settings_handler.get_value(SettingName.LOGS))
        Logger().set_logging_state(self.var_logging.get())

        # --- build interface ---
        self.title("Arcanite")
        self.geometry("500x350")

        self.menubar = tk.Menu(self)
        self.config(menu=self.menubar)

        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        # --- menus ---
        self.frames = {}
        self.current_menu = None
        self.back_menu = None

        for F in (MainMenu, LoginMenu, NewAccountMenu, UserMenu):
            frame = F(container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.open_start_menu()

    def show_frame(self, frame_class):
        """
        Показує (піднімає) заданий фрейм на передній план.

        Args:
            frame_class (type): Клас фрейму, який слід показати.
        """
        self.back_menu = self.current_menu
        self.current_menu = frame_class

        self.menubar.delete(0, "end")

        frame = self.frames[frame_class]
        self.event_generate("<<show_frame>>", data="DATA1224")
        frame.tkraise()

    def open_start_menu(self):
        """
        Визначає, який початковий фрейм відображати залежно від налаштувань аутентифікації:
        - Якщо увімкнено: показує меню входу або створення акаунта (якщо кількість користувачів == 0).
        - Інакше: головне меню.
        """
        if self.var_authentication.get():
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
        """
        Встановлює роль доступу поточного користувача.

        Args:
            access_role (str): Значення ролі доступу (admin/user).
        """
        self.access_role = access_role

    def get_access_role(self) -> str:
        """
        Повертає поточну роль користувача.

        Returns:
            str: Роль доступу (admin/user або порожній рядок).
        """
        return self.access_role if self.access_role else ""

    @staticmethod
    def get_info_doc():
        return (
            "Версія: Arcanite 1.0v\n"
            "Автор: roman.sarchuk.pp.2023@lpnu.ua\n"
            "Ліцензія: MIT\n"
            "Загальна інформація:\n"
            "Це десктопна програма з графічним інтерфейсом, створена на базі бібліотеки Tkinter (Python), "
            "яка взаємодіє з локальною базою даних SQLite. Програма забезпечує безпечну роботу з даними, "
            "використовуючи аутентифікацію користувачів, авторизацію, шифрування чутливої інформації та "
            "логування всіх дій користувача. Надає можливість вмикати/вимикати аутентифікацію та логування, "
            "забезпечуючи гнучке використання застосунку залежно від потреб користувача."
        )


# --- custom widgets ---
class EditableTreeview(ttk.Treeview):
    """
    Розширений клас Treeview з підтримкою редагування вмісту осередків по подвійному кліку.

    Дає змогу:
    - Редагувати значення в комірках безпосередньо у віджеті.
    - Валідувати нові значення через задану функцію.
    - Динамічно оновлювати позицію редактора при зміні розмірів або скролінгу.

    Parameters:
        master (tk.Widget): Батьківський віджет.
        validate_command (Callable): Опціональна функція валідації, яка викликається перед збереженням редагування.
                                     Має підпис: (old_value, new_value, item_iid, column) -> bool
        **kwargs: Усі стандартні параметри Treeview.

    Attributes:
        validate_command (Callable): Опціональна функція валідації, яка викликається перед збереженням редагування.
        entry (tk.Entry | None): Поточне поле вводу для редагування.
        _editing_info (tuple | None): Інформація про активну комірку редагування (item_iid, column).
    """

    def __init__(self, master, validate_command=None, **kwargs):
        self.validate_command = validate_command
        super().__init__(master, **kwargs)

        self.bind("<Double-1>", self.__on_double_click)
        self.bind("<Configure>", self.__on_resize)
        self.bind("<ButtonRelease-1>", self.__on_resize)

        self.entry = None
        self._editing_info = None

    def __on_double_click(self, event):
        """
        Обробник події подвійного кліку.
        Активує режим редагування, якщо клацнуто по клітинці або тексту дерева.

        Args:
            event (tk.Event): Подія натискання.
        """
        region = self.identify("region", event.x, event.y)
        if region not in ("cell", "tree"):
            return

        row_id = self.identify_row(event.y)
        column = self.identify_column(event.x)

        if not row_id:
            return

        self._show_entry(row_id, column)

    def _show_entry(self, row_id, column):
        """
        Показує поле введення (Entry) поверх клітинки для редагування її вмісту.

        Args:
            row_id (str): ID рядка у Treeview.
            column (str): Номер колонки (наприклад, "#0" для дерева).
        """
        bbox = self.bbox(row_id, column)
        if not bbox:
            return

        x, y, width, height = bbox

        # Отримуємо поточне значення
        if column == "#0":  # Це дерево (текст вузла)
            value = self.item(row_id, "text")
        else:
            value = self.set(row_id, column)

        if self.entry:
            self.entry.destroy()

        self.entry = tk.Entry(self)
        self.entry.place(x=x, y=y, width=width, height=height)
        self.entry.insert(0, value)
        self.entry.focus()

        self.entry.bind("<Return>", lambda e: self._save_edit(row_id, column))
        self.entry.bind("<Escape>", lambda e: self._cancel_edit())

        self._editing_info = (row_id, column)

    def _save_edit(self, item, column):
        """
        Зберігає нове значення з поля введення, викликає функцію валідації (якщо задана),
        та оновлює Treeview.

        Args:
            item (str): ID рядка у Treeview.
            column (str): Номер колонки (наприклад, "#0" для дерева).
        """
        if self.entry:
            new_value = self.entry.get()

            if self.validate_command:
                if column == "#0":  # Це дерево (текст вузла)
                    old_value = self.item(item, "text")
                else:
                    old_value = self.set(item, column)
                cmd_res = self.validate_command(old_value, new_value, item, column)
                if not cmd_res:
                    return

            if column == "#0":
                self.item(item, text=new_value)
            else:
                self.set(item, column, new_value)

            self.entry.destroy()
            self.entry = None
            self._editing_info = None

    def _cancel_edit(self):
        """
        Скасовує редагування, знищуючи поле вводу без збереження змін.
        """
        if self.entry:
            self.entry.destroy()
            self.entry = None
            self._editing_info = None

    def __on_resize(self, event=None):
        """
        Оновлює положення та розмір поля введення при зміні розміру Treeview.
        """
        if self.entry and self._editing_info:
            row_id, column = self._editing_info
            bbox = self.bbox(row_id, column)
            if bbox:
                x, y, width, height = bbox
                self.entry.place(x=x, y=y, width=width, height=height)

    @staticmethod
    def get_info_doc():
        return (
            "[➕] Щоб додати нову колонку натисніть на кнопку 'Add New'.\n"
            "[✏️] Щоб змінити назву колонки два рази клацніть лівою кнопкою миші на назві колонки. Тоді 'Enter', "
            "щоб підтвердити або 'Escape', щоб скасувати.\n"
            "[🗑️] Щоб видалити колонку клацніть на неї у списку, щоб вона виділилась, тоді клацніть на кнопку "
            "'Delete'.\n"
        )


class SortableTreeview(ttk.Treeview):
    """
    Treeview з підтримкою сортування колонок та перетягування рядків мишею.

    Цей клас додає дві основні функціональності:
    - Сортування даних при натисканні на заголовок колонки (вгору/вниз).
    - Перетягування рядків для зміни їхнього порядку вручну.

    Parameters:
        master (tk.Widget): Батьківський віджет.
        **kwargs: Усі стандартні параметри Treeview.

    Attributes:
        ARROWS (dict[bool, str]): Словник відповідності напрямку сортування відповідній unicode стрільці
        columns (list[str]): Список назв колонок.
        sort_directions (dict[str, Optional[bool]]): Напрямок сортування для кожної колонки (True -> ASC, False -> DESC).
        dragged_item (str | None): ID перетягуваного рядка.
    """
    ARROWS = {False: "\u25BC", True: "\u25B2"}

    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)

        self.columns = kwargs["columns"]
        self.sort_directions = {col: None for col in self.columns}  # None, True (ASC), False (DESC)
        self.dragged_item = None

        self.bind("<ButtonPress-1>", self.__on_press)
        self.bind("<B1-Motion>", self.__on_drag)
        self.bind("<ButtonRelease-1>", self.__on_release)

        self.set_new_columns(self.columns)

    def clear_table(self):
        """
        Очищає всі рядки в таблиці.
        """
        for row in self.get_children():
            self.delete(row)

    def load_data(self, data: list[dict]):
        """
        Завантажує дані у таблицю. Очікується список словників, де ключі відповідають назвам колонок.

        Args:
            data (list[dict]): Дані для завантаження (у форматі {поле: значення}).
        """
        # clear table
        for row in self.get_children():
            self.delete(row)

        # add records in the Treeview
        for record in data:
            self.insert("", "end", values=[record[field] for field in self.columns])

    def set_new_columns(self, columns: list[str]):
        """
        Встановлює нові колонки в таблицю та конфігурує їх заголовки для сортування.

        Args:
            columns (list[str]): Список назв колонок.
        """
        self.columns = columns

        self.sort_directions = {col: None for col in self.columns}

        self.config(columns=self.columns)

        tree_width = self.winfo_width()
        if len(self.columns) == 0 or tree_width < len(self.columns):
            col_width = 5
        else:
            col_width = tree_width // len(self.columns)

        for col in self.columns:
            self.heading(col, text=col, anchor='w', command=lambda c=col: self.__handle_sort(c))
            self.column(col, width=col_width, anchor="w")  # , stretch=(i == 0 or i == len(self.columns) - 1)

    # --- binding ---
    def __handle_sort(self, col):
        """
        Обробляє клік по заголовку колонки, виконує сортування за обраною колонкою.

        Args:
            col (str): Назва колонки.
        """
        current = self.sort_directions[col]
        reverse = not current if current is not None else False

        # Get all data
        data = [(self.set(iid, col), iid) for iid in self.get_children('')]

        # Try to sort numerically, fallback to string
        try:
            data.sort(key=lambda t: float(t[0]), reverse=reverse)
        except ValueError:
            data.sort(key=lambda t: t[0], reverse=reverse)

        # Rearranging items in Treeview
        for index, (val, iid) in enumerate(data):
            self.move(iid, '', index)

        # Update sort directions
        for c in self.columns:
            self.sort_directions[c] = None  # reset others
            self.heading(c, text=c)  # reset heading

        self.sort_directions[col] = reverse
        self.heading(col, text=f"{col} {self.ARROWS[reverse]}")

    def __on_press(self, event):
        """
        Обробляє натискання кнопки миші — визначає, який рядок починає перетягуватись.

        Args:
            event (tk.Event): Подія натискання.
        """
        dragged = self.identify_row(event.y)
        if not dragged:
            return

        self.dragged_item = dragged
        self.selection_set(self.dragged_item)

    def __on_drag(self, event):
        """
        Обробляє переміщення миші при утриманні кнопки — переміщує рядок у нову позицію.

        Args:
            event (tk.Event): Подія переміщення.
        """
        if not self.dragged_item:
            return

        target = self.identify_row(event.y)
        if not target or target == self.dragged_item:
            return

        index = self.index(target)
        self.move(self.dragged_item, "", index)

    def __on_release(self, event=None):
        """
        Скидає стан після завершення перетягування.
        """
        self.dragged_item = None

    def __on_move_up(self, is_down):
        """
        Програмне переміщення виділеного рядка вгору або вниз.

        Args:
            is_down (bool): Напрямок переміщення — True для вниз, False для вгору.
        """
        selected = self.selection()
        if not selected:
            return

        selected_item = selected[0]
        index = self.index(selected_item)
        new_index = index + (1 if is_down else -1)
        self.move(selected_item, "", new_index)
        self.selection_set(selected_item)

    @staticmethod
    def get_info_doc():
        return (
            "[⇅] Натисніть на заголовок колонки, щоб відсортувати її. При повторному натискані на заголовок "
            "зміниться напрямок сортування.\n"
            "[↕] Затримайте на рядку із даними, щоб перемістити його та перетягуйте."
        )


class SortableEditableTreeview(SortableTreeview, EditableTreeview):
    """
    Розширений Treeview-елемент, що поєднує можливість редагування комірок та сортування колонок.

    Клас успадковує функціональність обох:
        - EditableTreeview: дозволяє редагувати значення у клітинках подвійним кліком.
        - SortableTreeview: дозволяє сортувати дані за колонками та перетягувати рядки.

    Parameters:
        master (tk.Widget): Батьківський віджет.
        validate_command (Callable): Опціональна функція валідації, яка викликається перед збереженням редагування.
                                     Має підпис: (old_value, new_value, item_iid, column) -> bool
        **kwargs: Усі стандартні параметри Treeview.

    Attributes:
        master (tk.Widget): Батьківський віджет.
        validate_command (Callable): Опціональна функція валідації, яка викликається перед збереженням редагування.
                                     Має підпис: (old_value, new_value, item_iid, column) -> bool
        **kwargs: Додаткові аргументи для ttk.Treeview.
    """
    def __init__(self, master, validate_command=None, **kwargs):
        super().__init__(master=master, validate_command=validate_command, **kwargs)

    @staticmethod
    def get_info_doc():
        editable_info = EditableTreeview.get_info_doc()
        sortable_info = SortableTreeview.get_info_doc()
        return f"{editable_info}{"-"*50}\n{sortable_info}"


def create_modal(master: tk.Tk, title: str) -> tk.Toplevel:
    top_level = tk.Toplevel(master)

    # top_level setting
    top_level.title(title)
    top_level.resizable(width=False, height=False)
    top_level.transient(master)
    top_level.grab_set()

    return top_level


# --- menu frames ---
class MainMenu(ttk.Frame):
    """
    Головне меню застосунку — графічний інтерфейс для роботи з таблицею записів та доступом до налаштувань.

    Забезпечує:
      - Відображення таблиці з можливістю редагування.
      - Додавання та видалення записів.
      - Налаштування вигляду таблиці.
      - Доступ до параметрів автентифікації, логування та адмін-функцій.

    Parameters:
        parent (tk.Widget): Батьківський віджет.
        controller (Application): Головний контролер програми.
        **kwargs: Усі стандартні параметри ttk.Frame.

    Attributes:
        parent (tk.Widget): Батьківський віджет.
        controller (Application): Головний контролер програми.
        users_handler (UsersHandler): Обробник авторизації користувачів.
        settings_handler (SettingsHandler): Обробник системних налаштувань.
        def_table_handler (DefaultTableHandler): Керує завантаженням і редагуванням даних таблиці.
        logger (Logger): Логування змін та подій.
        field_names (list[str]): Список назв колонок таблиці.
        user_label (ttk.Label): Віджет, який відображає username користувача та його рівень доступу
                                або просто "ADMIN", якщо вимкнена авторизація
        logout_button (ttk.Button): Кнопка длявиходу із акаунту. Привована, якщо вимкнена авторизація
        tree (SortableEditableTreeview): Віджет таблиці з підтримкою сортування та редагування.
        modal (tk.Toplevel | None): Активне модальне вікно, якщо є.
    """

    def __init__(self, parent, controller: Application, **kwargs):
        super().__init__(parent, **kwargs)
        self.parent = parent
        self.controller = controller
        self.users_handler = UsersHandler()
        self.settings_handler = SettingsHandler()
        self.def_table_handler = DefaultTableHandler()
        self.logger = Logger()

        self.field_names = self.def_table_handler.get_field_names()

        self.modal = None
        self._build_interface()

        self.controller.bind("<<show_frame>>", self.update_frame, add="+")

    def _build_interface(self):
        """
        Створює і розміщує усі графічні елементи інтерфейсу:
        заголовок з ім'ям користувача, таблицю записів та панель дій (footer).
        """
        # ----- Set up Header frame -----
        frame_header = ttk.Frame(self, padding=(5, 5, 5, 10), width=450)
        frame_header.pack(anchor="n", fill=tk.X, padx=10, pady=10)

        self.user_label = ttk.Label(frame_header, text="USER-NAME")
        self.user_label.pack(side=tk.LEFT)

        self.logout_button = ttk.Button(
            frame_header,
            text="Log Out", width=15,
            command=self.__on_logout_clicked
        )
        # ----- --- -- ------- ----- -----

        # ----- Set up Body frame -----
        frame_body = ttk.Frame(self, width=450)
        frame_body.pack(expand=True, fill=tk.BOTH, padx=10)

        scrollbar = ttk.Scrollbar(frame_body, orient="vertical")
        scrollbar.pack(side="right", fill="y")

        self.tree = SortableEditableTreeview(
            frame_body,
            validate_command=self.__on_edit_called,
            columns = self.field_names,
            selectmode = "browse",
            show = "headings",
            height = 8,
            yscrollcommand = scrollbar.set,
        )
        self.tree.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        scrollbar.config(command=self.tree.yview)

        self.load_data()
        # ----- --- -- ---- ----- -----

        # ----- Set up Footer frame -----
        frame_footer = ttk.Frame(self, width=450)
        frame_footer.pack(anchor="s", fill=tk.X, padx=10, pady=10)

        button_new_record = ttk.Button(frame_footer, text="Add New", command=self.__on_add_new_clicked, width=15)
        button_new_record.pack(side=tk.LEFT)

        button_del_record = ttk.Button(frame_footer, text="Delete", command=self.__on_delete_clicked, width=15)
        button_del_record.pack(side=tk.LEFT)

        button_table_setting = ttk.Button(frame_footer, text="Set up Table", command=self.__on_set_up_table_clicked, width=15)
        button_table_setting.pack(side=tk.RIGHT)
        # ----- --- -- ------ ----- -----

    def load_data(self, event=None):
        """
        Завантажує записи з БД та передає їх до таблиці.

        Args:
            event (tk.Event | None): Подія, що викликає завантаження. Необов’язковий.
        """
        # data getting from DB
        records = self.def_table_handler.get_records()

        self.tree.load_data(records)

    def update_frame(self, event=None):
        """
        Оновлює інтерфейс при перемиканні на головне меню:
        - Встановлює меню залежно від ролі користувача.
        - Оновлює відображення імені користувача.
        - Оновлює відображення кнопки "Logout" залежно від параметра authentication

        Args:
            event (tk.Event | None): Подія, що викликає завантаження. Необов’язковий.
        """
        if self.controller.current_menu != MainMenu:
            return

        edit_menu = tk.Menu(self.controller.menubar, tearoff=0)
        edit_menu.add_command(label="Додати запис", command=self.__on_add_new_clicked)
        edit_menu.add_command(label="Видалити обраний запис", command=self.__on_delete_clicked)
        edit_menu.add_command(label="Налаштувати таблицю", command=self.__on_set_up_table_clicked)
        self.controller.menubar.add_cascade(label="Редагувати", menu=edit_menu)

        if self.controller.var_authentication.get():
            # authentication is turn ON
            self.user_label.configure(
                text=self.users_handler.get_authenticated_user_name() + f" ({self.controller.get_access_role()})"
            )
            self.logout_button.pack(side=tk.RIGHT)

            if self.controller.get_access_role() == DEFAULT_ADMIN_ROLE:
                # authentication is turn ON and access_role is ADMIN
                setting_menu = tk.Menu(self.controller.menubar, tearoff=0)
                setting_menu.add_checkbutton(
                    label="Автентифікація користувачів",
                    variable=self.controller.var_authentication, command=self.__on_menu_change_authentication
                )
                setting_menu.add_checkbutton(
                    label="Логування операцій",
                    variable=self.controller.var_logging, command=self.__on_menu_change_logging
                )
                self.controller.menubar.add_cascade(label="Налаштування", menu=setting_menu)

                admin_panel_menu = tk.Menu(self.controller.menubar, tearoff=0)
                admin_panel_menu.add_command(label="Переглянути логи", command=self.__on_menu_view_logs_clicked)
                admin_panel_menu.add_command(label="Видалити логи", command=self.__on_menu_delete_logs_clicked)
                admin_panel_menu.add_command(label="Відкрити панель користувачів",
                                             command=self.__on_menu_user_panel_clicked)
                self.controller.menubar.add_cascade(label="Адмін-панель", menu=admin_panel_menu)
        else:
            # authentication is turn OFF
            self.user_label.configure(text="ADMIN")
            self.logout_button.pack_forget()

            setting_menu = tk.Menu(self.controller.menubar, tearoff=0)
            setting_menu.add_checkbutton(
                label="Автентифікація користувачів",
                variable=self.controller.var_authentication, command=self.__on_menu_change_authentication
            )
            setting_menu.add_checkbutton(
                label="Логування операцій",
                variable=self.controller.var_logging, command=self.__on_menu_change_logging
            )
            self.controller.menubar.add_cascade(label="Налаштування", menu=setting_menu)

            admin_panel_menu = tk.Menu(self.controller.menubar, tearoff=0)
            admin_panel_menu.add_command(label="Переглянути логи", command=self.__on_menu_view_logs_clicked)
            admin_panel_menu.add_command(label="Видалити логи", command=self.__on_menu_delete_logs_clicked)
            self.controller.menubar.add_cascade(label="Адмін-панель", menu=admin_panel_menu)

        help_menu = tk.Menu(self.controller.menubar, tearoff=0)
        help_menu.add_command(
            label="Про програму",
            command=lambda: messagebox.showinfo("Про програму", self.controller.get_info_doc())
        )
        help_menu.add_command(
            label="Як взаємодіяти із таблицею",
            command=lambda: messagebox.showinfo("Як взаємодіяти із таблицею", self.tree.get_info_doc())
        )
        self.controller.menubar.add_cascade(label="Інфо.", menu=help_menu)

    # --- binding function ---
    def __on_logout_clicked(self):
        """
        Обробляє натискання кнопки "Log Out":
        - Виходить з-під користувача.
        - Повертає на початкове меню.
        """
        self.users_handler.logout_authenticated_user()
        self.controller.set_access_role(None)
        self.controller.open_start_menu()

    def __on_add_new_clicked(self):
        """
        Відкриває модальне вікно для додавання нового запису до таблиці.
        """
        if not self.field_names:
            return

        modal = create_modal(self.controller, "Add New Record")

        new_record_menu = NewRecordMenu(modal, self.tree, self.field_names)
        new_record_menu.pack(expand=True, fill=tk.BOTH)

    def __on_delete_clicked(self):
        """
        Видаляє обраний запис з таблиці та БД.
        Якщо запис не обрано — показує попередження.
        """
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Видалення...", "Спершу оберіть запис у таблиці!")
            return

        selected_item_iid = selected_item[0]
        columns = self.tree["columns"]

        values = {col: self.tree.set(selected_item_iid, col) for col in columns}

        self.def_table_handler.delete_record(values)
        self.tree.delete(selected_item_iid)

    def __on_edit_called(self, old_value, new_value, item, column):
        """
        Обробляє зміну значення в таблиці.

        Args:
            old_value (str): Попереднє значення.
            new_value (str): Нова введена користувачем строка.
            item (str): Ідентифікатор елемента в таблиці.
            column (str): Номер колонки у вигляді рядка, наприклад, '#3'.

        Returns:
            bool: True, якщо редагування успішне, інакше False.
        """
        if not new_value:
            return False

        column_index = int(column.replace('#', '')) - 1  # перетворюємо '#3' → 2
        column_name = self.tree['columns'][column_index]

        old_row = self.tree.set(item)
        self.def_table_handler.edit_record(old_row, {column_name: new_value})

        return True

    def __on_close_set_up_table_modal(self):
        """
        Закриває модальне вікно налаштувань таблиці та оновлює інтерфейс таблиці.
        """
        self.field_names = self.def_table_handler.get_field_names()
        self.tree.clear_table()
        self.tree.set_new_columns(self.field_names)
        self.load_data()
        self.modal.destroy()

    def __on_set_up_table_clicked(self):
        """
        Відкриває модальне вікно для налаштування колонок таблиці.
        """
        self.modal = create_modal(self.controller, "Table Settings")
        self.modal.protocol("WM_DELETE_WINDOW", self.__on_close_set_up_table_modal)

        table_settings_menu = TableSettingsMenu(self.modal)
        table_settings_menu.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        table_settings_menu.load_data(self.field_names)

    def __on_menu_change_authentication(self):
        """
        Перемикає стан автентифікації користувачів через меню налаштувань.
        """
        self.settings_handler.update(SettingName.AUTHENTICATION, self.controller.var_authentication.get())
        self.__on_logout_clicked()

    def __on_menu_change_logging(self):
        """
        Перемикає стан логування подій через меню налаштувань.
        """
        self.settings_handler.update(SettingName.LOGS, self.controller.var_logging.get())
        self.logger.set_logging_state(self.controller.var_logging.get())

    def __on_menu_view_logs_clicked(self):
        """
        Відкриває модальне вікно з переглядом логів.
        """
        # data getting from DB
        field_names = self.logger.get_field_names()
        records = self.logger.get_records()

        # build interface
        modal = create_modal(self.controller, "Logs")
        modal.resizable(width=True, height=True)
        modal.geometry("450x250")

        scrollbar = ttk.Scrollbar(modal, orient="vertical")
        scrollbar.pack(side="right", fill="y")

        tree = SortableTreeview(
            modal,
            columns=field_names,
            selectmode="browse",
            show="headings",
            height=10,
            yscrollcommand=scrollbar.set,
        )
        scrollbar.config(command=tree.yview)
        tree.load_data(records)

        tree.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

    def __on_menu_delete_logs_clicked(self):
        """
        Видаляє всі логи з підтвердженням користувача.
        """
        result = messagebox.askyesno("Видалення логів...", "Ви впевнені, що хочете видалити всі логи?")

        if result:
            self.logger.clear_logs()

    def __on_menu_user_panel_clicked(self):
        """
        Відкриває панель керування користувачами.
        """
        self.controller.show_frame(UserMenu)


class DataEntryForm(ttk.Frame):
    """
    Універсальна форма введення даних з полями (entry, combobox, пароль) та кнопками дій.

    Забезпечує:
      - Динамічне створення полів вводу залежно від переданих параметрів.
      - Відображення прихованих символів у полях пароля.
      - Додавання кнопок з callback-функціональністю.

    Parameters:
        parent (tk.Widget): Батьківський віджет.
        title (str): Заголовок форми.
        fields_data (list[dict]): Список словників із конфігурацією кожного поля. Очікувані ключі:
            - 'var_name' (str): Ім’я змінної поля.
            - 'type' (FieldType): Тип поля (ENTRY, SECURITY_ENTRY, COMBOBOX).
            - 'list' (list[str], optional): Список варіантів для combobox.
        button_parameters (list[dict]): Параметри для створення кнопок. Відповідає **kwargs для ttk.Button.
        **kwargs: Додаткові аргументи для ttk.Frame.

    Attributes:
        SECURITY_SIGN (str): Символ, який використовується для приховання пароля.
        SHOW_PASSWORD_SIGN (str): Піктограма для кнопки, що показує пароль.
        HIDE_PASSWORD_SIGN (str): Піктограма для кнопки, що приховує пароль.
        fields_data (list[dict]): Список даних для створення полів.
        button_parameters (list[dict]): Конфігурація для створення кнопок.
        vars (dict[str, tk.StringVar]): Всі змінні, прив’язані до полів форми.
        control_widgets (dict[str, Widget]): Всі контрольні елементи форми (поля, combobox, кнопки).
    """
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
        title_frame = ttk.Frame(self)
        title_frame.grid(row=0, column=0, columnspan=3, sticky="s", pady=(20, 30))
        title_frame.columnconfigure(0, weight=1)

        title_label = ttk.Label(title_frame, text=title, font=("", 16, "bold"))
        title_label.grid(row=0, column=0)

        # Create form fields
        self._create_form_fields()

        # Create buttons
        self._create_buttons()

        # Add padding around all widgets
        for child in self.winfo_children():
            child.grid_configure(padx=10, pady=5)

    def __toggle_password_show(self, entry_widget, button_widget):
        """
        Перемикає видимість символів у полі введення пароля.

        Parameters:
            entry_widget (ttk.Entry): Поле пароля.
            button_widget (ttk.Button): Кнопка, яка викликає цю функцію.
        """
        if entry_widget.cget("show"):
            entry_widget.config(show="")
            button_widget.config(text=self.HIDE_PASSWORD_SIGN)
        else:
            entry_widget.config(show=self.SECURITY_SIGN)
            button_widget.config(text=self.SHOW_PASSWORD_SIGN)

    @staticmethod
    def __make_callback_func(func, *args):
        """
        Генерує callback-функцію з переданими аргументами.

        Parameters:
            func (callable): Функція, яка викликається.
            *args: Аргументи для функції.

        Returns:
            callable: Лямбда-функція.
        """
        return lambda: func(*args)

    def _create_form_fields(self):
        """
        Створює графічні поля вводу на основі `fields_data`.
        Підтримувані типи: ENTRY, SECURITY_ENTRY, COMBOBOX.
        """
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
        """
        Створює кнопки у нижній частині форми згідно з `button_parameters`.
        """
        button_frame = ttk.Frame(self)
        button_frame.grid(row=len(self.fields_data) + 1, column=0, columnspan=3, sticky="n", pady=20)

        for i, parameters in enumerate(self.button_parameters):
            button = ttk.Button(button_frame, **parameters)
            button.grid(row=0, column=i, padx=10)
            self.control_widgets[parameters["text"].lower()] = button

    def get_field_value(self, var_name):
        """
        Повертає значення, введене в поле форми.

        Parameters:
            var_name (str): Назва змінної.

        Returns:
            str: Значення поля.
        """
        return self.vars[var_name].get()

    def set_field_value(self, var_name, value):
        """
        Встановлює значення у відповідне поле форми.

        Parameters:
            var_name (str): Назва змінної.
            value (str): Значення, яке слід встановити.
        """
        self.vars[var_name].set(value)

    def clear_form(self):
        """
        Очищує всі поля форми (встановлює порожні значення).
        """
        for var in self.vars.values():
            var.set("")

    def config_control_widget(self, var_name, **kwargs):
        """
        Конфігурує властивості конкретного елемента керування (наприклад, entry або button).

        Parameters:
            var_name (str): Назва поля або кнопки.
            **kwargs: Параметри для методу .config().
        """
        self.control_widgets[var_name].config(**kwargs)


class LoginMenu(ttk.Frame):
    """
    Графічний інтерфейс для авторизації користувача у застосунку.

    Забезпечує:
      - Введення логіна та пароля.
      - Перевірку заповненості полів.
      - Аутентифікацію користувача та обробку результату.
      - Перехід до головного меню при успішному вході.

    Parameters:
        parent (tk.Widget): Батьківський віджет.
        controller (Application): Головний контролер застосунку.
        **kwargs: Додаткові іменовані аргументи для ttk.Frame.

    Attributes:
        controller (Application): Контролер, що керує переходами між екранами.
        user_handler (UsersHandler): Обробник авторизації користувачів.
        var_names (list[str]): Список назв змінних, пов’язаних з полями форми.
        data_entry_form (DataEntryForm): Форма для введення логіну та пароля.
    """

    def __init__(self, parent, controller: Application, **kwargs):
        super().__init__(parent, **kwargs)
        self.controller = controller
        self.user_handler = UsersHandler()

        entry_form_fields_data = [
            {"var_name": "login", "type": FieldType.ENTRY},
            {"var_name": "password", "type": FieldType.SECURITY_ENTRY},
        ]
        self.var_names = [field_data["var_name"] for field_data in entry_form_fields_data]
        entry_form_button_parameters = [
            {"text": "Log In", "command": self.login, "width": 15},
        ]

        self.data_entry_form = DataEntryForm(
            self, "Login Menu",
            entry_form_fields_data, entry_form_button_parameters
        )
        self.data_entry_form.pack(fill=tk.BOTH, expand=True)

        self.controller.bind("<<show_frame>>", self.update_frame, add="+")

    def login(self):
        """
        Обробляє логіку входу користувача.

        - Перевіряє, чи всі поля заповнені.
        - Виконує аутентифікацію користувача через `UsersHandler`.
        - У разі успіху встановлює роль доступу та переходить до головного меню.
        - У разі помилки відображає відповідне повідомлення.
        """
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
        """
        Очищає поля форми при кожному відображенні екрану входу.

        Parameters:
            event (tk.Event): Подія `<<show_frame>>`, яка активує оновлення.
        """
        self.data_entry_form.clear_form()


class NewAccountMenu(ttk.Frame):
    """
    Меню створення нового облікового запису.

    Віджет, який дозволяє адміністратору або першому користувачу створити новий акаунт у системі.
    Забезпечує валідацію введених даних, перевірку наявності логіна в БД та виконує створення нового користувача.

    Parameters:
        parent (tk.Widget): Батьківський віджет.
        controller (Application | None): Контролер застосунку, необхідний для навігації між меню.
        comm (Callable | None): Додаткова callback-функція, яка викликається після створення акаунту.
        **kwargs: Додаткові іменовані аргументи для ttk.Frame.

    Attributes:
        controller (Application | None): Контролер застосунку.
        comm_on_new_account (Callable | None): Callback, що викликається після створення акаунту.
        db_handler (DBHandler): Обробник запитів до БД.
        user_handler (UsersHandler): Обробник логіки користувачів.
        is_first_account_mod (bool): Прапорець, який позначає режим створення першого адміністратора.
        role_dict (dict[str, int]): Відображення назв ролей у їхні ID з БД.
        var_names (list[str]): Імена змінних, які використовуються у формі введення.
        data_entry_form (DataEntryForm): Віджет форми введення для створення акаунту.
    """
    def __init__(self, parent, controller:Application=None, comm=None, **kwargs):
        super().__init__(parent, **kwargs)
        self.controller = controller
        self.comm_on_new_account = comm
        self.db_handler = DBHandler()
        self.user_handler = UsersHandler()
        self.is_first_account_mod = False

        self.role_dict = self.user_handler.get_roles()   # name, id
        roles = tuple(self.role_dict.keys())

        entry_form_fields_data = [
            {"var_name": "username", "type": FieldType.ENTRY},
            {"var_name": "login", "type": FieldType.ENTRY},
            {"var_name": "password", "type": FieldType.SECURITY_ENTRY},
            {"var_name": "confirm_password", "type": FieldType.SECURITY_ENTRY},
            {"var_name": "role", "type": FieldType.COMBOBOX, "list": roles}
        ]
        self.var_names = [field_data["var_name"] for field_data in entry_form_fields_data]
        entry_form_button_parameters = [
            {"text": "Create", "command": self.create_new_account},
        ]

        self.data_entry_form = DataEntryForm(
            self, "Create New Account",
            entry_form_fields_data, entry_form_button_parameters
        )
        self.data_entry_form.pack(fill=tk.BOTH, expand=True)

    def create_new_account(self):
        """
        Обробляє створення нового облікового запису.

        - Перевіряє, чи всі поля заповнені.
        - Перевіряє відповідність пароля та підтвердження.
        - Перевіряє, чи логін ще не зайнятий у БД.
        - Додає користувача через `UsersHandler`.
        - Викликає callback або змінює екран при потребі.
        - Очищає форму після завершення.
        """
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
            return

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

        self.data_entry_form.clear_form()

    def update_frame(self, event):
        """
        Очищає поля форми при кожному відображенні меню створення акаунту.

        Parameters:
            event (tk.Event): Подія, яка викликає оновлення.
        """
        self.data_entry_form.clear_form()

    def turn_on_first_account_mod(self):
        """
        Вмикає режим створення першого облікового запису адміністратора.
        Автоматично обирає роль 'admin' і блокує вибір інших ролей.
        """
        self.is_first_account_mod = True

        self.data_entry_form.set_field_value("role", "admin")
        self.data_entry_form.config_control_widget("role", state="disabled")    # role combobox

    def turn_off_first_account_mod(self):
        """
        Вимикає режим створення першого облікового запису.
        Робить поле вибору ролі знову доступним для редагування.
        """
        self.is_first_account_mod = False

        self.data_entry_form.config_control_widget("role", state="readonly")    # role combobox


class NewRecordMenu(ttk.Frame):
    """
    Меню додавання нового запису до таблиці.

    Графічний інтерфейс, який дозволяє користувачеві ввести дані для нового запису та додати його до таблиці (Treeview),
    а також до базового сховища (через DefaultTableHandler).

    Parameters:
        toplevel (tk.Toplevel): Вікно, у якому відображається форма додавання.
        tree (ttk.Treeview): Віджет таблиці, до якого додається новий запис.
        field_names (Iterable[str]): Список імен полів для нового запису.
        **kwargs: Додаткові параметри для ініціалізації ttk.Frame.

    Attributes:
        def_table_handler (DefaultTableHandler): Обробник, який відповідає за збереження записів.
        controller (tk.Toplevel): Контролер-вікно, в якому відображається форма.
        tree (ttk.Treeview): Таблиця, до якої додається новий запис.
        var_names (list[str]): Список імен змінних для полів введення.
        data_entry_form (DataEntryForm): Віджет форми введення нового запису.
    """

    def __init__(self, toplevel: tk.Toplevel, tree: ttk.Treeview, field_names, **kwargs):
        super().__init__(toplevel, **kwargs)
        self.def_table_handler = DefaultTableHandler()
        self.controller = toplevel
        self.tree = tree

        entry_form_fields_data = [
            {"var_name": field_name, "type": FieldType.ENTRY}
            for field_name in field_names
        ]
        self.var_names = [field_data["var_name"] for field_data in entry_form_fields_data]
        entry_form_button_parameters = [
            {"text": "Add", "command": self.add_new_record, "width": 15},
            {"text": "Cancel", "command": self.controller.destroy, "width": 15},
        ]

        self.data_entry_form = DataEntryForm(
            self, "Add New Record",
            entry_form_fields_data, entry_form_button_parameters
        )
        self.data_entry_form.pack(fill=tk.BOTH, expand=True)

    def add_new_record(self):
        """
        Обробляє додавання нового запису.

        - Зчитує значення з форми.
        - Перевіряє, щоб не всі поля були порожні.
        - Додає запис до таблиці (Treeview).
        - Зберігає запис у базовій структурі даних через DefaultTableHandler.
        - Закриває модальне вікно після успішного додавання.
        """
        data = {var_name: self.data_entry_form.get_field_value(var_name) for var_name in self.var_names}

        # varify empty fields
        if all([not value for value in data.values()]):
            messagebox.showwarning("Login Menu", f"Не можуть всі поля бути пусті!")
            return

        self.tree.insert("", "end", values=tuple(data.values()))
        self.def_table_handler.add_record(data)

        self.controller.destroy()


class TableSettingsMenu(ttk.Frame):
    """
    Меню налаштувань таблиці для управління колонками.

    Дозволяє додавати, перейменовувати та видаляти колонки таблиці.
    Включає графічний інтерфейс з EditableTreeview для відображення та редагування колонок.

    Parameters:
        master (tk.Widget): Батьківський віджет.
        **kwargs: Додаткові іменовані аргументи для ttk.Frame.

    Attributes:
        def_table_handler (DefaultTableHandler): Обробник операцій над таблицею.
        var_new_col (tk.StringVar): Змінна для введення назви нової колонки.
        frame_tree (ttk.Frame): Фрейм, що містить список колонок.
        frame_add_new_colum (ttk.Frame): Фрейм для введення нової колонки.
        tree (EditableTreeview): Віджет для відображення та редагування колонок.
    """

    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.def_table_handler = DefaultTableHandler()

        self.var_new_col = tk.StringVar()

        self.frame_tree = ttk.Frame(self)
        self.frame_tree.grid(row=0, column=0, sticky=tk.NSEW)
        self.frame_add_new_colum = ttk.Frame(self)
        self.frame_add_new_colum.grid(row=0, column=0, sticky=tk.NSEW)
        self._build_interface()

        self.frame_tree.tkraise()

    def _build_interface(self):
        """
        Створює та розташовує всі елементи інтерфейсу.

        Включає заголовок, EditableTreeview із вертикальним скролбаром,
        а також кнопки для додавання та видалення колонок.
        Надає форму для введення назви нової колонки.
        """
        # --- header ---
        frame_header = ttk.Frame(self.frame_tree)
        frame_header.pack(fill=tk.X)

        button_info = ttk.Button(frame_header, text="?", width=3, command=self.show_info)
        button_info.pack(side=tk.LEFT)

        # --- tree ---
        scrollbar = ttk.Scrollbar(self.frame_tree, orient="vertical")
        scrollbar.pack(side="right", fill="y")

        self.tree = EditableTreeview(
            self.frame_tree,
            validate_command=self.__before_edit_col_name,
            selectmode="browse",
            show="tree",
            height=10,
            yscrollcommand=scrollbar.set,
        )

        self.tree.pack(expand=True, fill=tk.BOTH)

        scrollbar.config(command=self.tree.yview)

        frame_tree_button = ttk.Frame(self.frame_tree)
        frame_tree_button.pack(fill=tk.X, padx=5, pady=5)

        frame_tree_button.grid_rowconfigure(0, weight=1)
        frame_tree_button.grid_columnconfigure(0, weight=1)
        frame_tree_button.grid_columnconfigure(1, weight=1)

        button_add_new_column = ttk.Button(
            frame_tree_button, text="Add New",
            command=lambda: self.frame_add_new_colum.tkraise()
        )
        button_add_new_column.grid(row=0, column=0)

        button_delete_column = ttk.Button(
            frame_tree_button, text="Delete",
            command=self.__on_delete_column
        )
        button_delete_column.grid(row=0, column=1)

        # --- new column ---
        self.frame_add_new_colum.grid_rowconfigure(0, weight=1)
        self.frame_add_new_colum.grid_rowconfigure(1, weight=1)
        self.frame_add_new_colum.grid_rowconfigure(2, weight=1)
        self.frame_add_new_colum.grid_columnconfigure(0, weight=1)
        self.frame_add_new_colum.grid_columnconfigure(1, weight=1)

        label = ttk.Label(self.frame_add_new_colum, text="Column name:", font=("Arial", 15))
        label.grid(column=0, row=0, columnspan=2, padx=5, pady=5)

        entry = ttk.Entry(self.frame_add_new_colum, textvariable=self.var_new_col)
        entry.grid(column=0, row=1, columnspan=2, padx=5, pady=5)

        button_apply = ttk.Button(self.frame_add_new_colum, text="Apply", command=self.__on_add_new_column)
        button_apply.grid(column=0, row=2, padx=5, pady=5)

        button_cancel = ttk.Button(self.frame_add_new_colum, text="Cancel", command=lambda: self.frame_tree.tkraise())
        button_cancel.grid(column=1, row=2, padx=5, pady=5)

    def __before_edit_col_name(self, old_value, new_value, item=None, column=None):
        """
        Перевіряє можливість перейменування колонки.

        Валідовує, що нове ім'я не порожнє, містить лише англійські літери та символ '_'.
        Спробує виконати перейменування через def_table_handler.
        Якщо виникають помилки, відображає відповідні повідомлення.

        Args:
            old_value (str): Поточна назва колонки.
            new_value (str): Нова пропонована назва колонки.
            item: Не використовується.
            column: Не використовується.

        Returns:
            bool: True, якщо перейменування допустиме і виконано; False — інакше.
        """
        if not new_value:
            messagebox.showwarning("Column edit", "Не можна вести порожнє значення!")
            return False

        if not self.__validate_english_letters(new_value):
            messagebox.showwarning("Column edit", "Використовуйте тільки англійські літери та символ _")
            return False

        try:
            self.def_table_handler.rename_column(old_value, new_value)
        except Exception as e:
            messagebox.showerror("Column edit", f"Не вдалося змінити назви колонки!\nОпис проблеми:\n{e}")
            return False
        return True

    @staticmethod
    def __validate_english_letters(value) -> bool:
        """
        Перевіряє, чи містить рядок лише англійські літери та символи підкреслення.

        Args:
            value (str): Тестований рядок.

        Returns:
            bool: True, якщо рядок коректний, інакше False.
        """
        return fullmatch(r"[a-zA-Z_]*", value) is not None

    def __on_delete_column(self):
        """
        Обробляє видалення обраної колонки.

        Показує діалог підтвердження.
        Якщо користувач підтверджує, видаляє колонку через def_table_handler і з інтерфейсу.
        При помилках відображає повідомлення.
        """
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo("Column delete", "Оберіть колонку для видалення!")
            return

        selected_item = selection[0]
        col_name = self.tree.item(selected_item, "text")

        result = messagebox.askyesno("Column delete", f"Ви впевнені, що хочете видалити колонку {col_name}?\nДані будуть втрачені!")

        if result:
            try:
                self.def_table_handler.delete_column(col_name)
                self.tree.delete(selected_item)
            except Exception as e:
                messagebox.showerror("Column delete", f"Не вдалося видалити колонки!\nОпис проблеми:\n{e}")
                return

    def __on_add_new_column(self):
        """
        Обробляє додавання нової колонки.

        Перевіряє валідність введеного імені.
        Перевіряє, що колонка з таким іменем ще не існує.
        Додає колонку у сховище і в інтерфейс.
        При помилках відображає повідомлення.
        Після додавання переключає інтерфейс назад на список колонок.
        """
        value = self.var_new_col.get()

        if not value:
            messagebox.showwarning("New Column", "Не можна вести порожнє значення!")
            return False

        if not self.__validate_english_letters(value):
            messagebox.showwarning("New Column", "Використовуйте тільки англійські літери та символ _")
            return

        if value in self.tree["columns"]:
            messagebox.showwarning("New Column", "Така колонка вже існує!")
            return

        try:
            self.def_table_handler.add_column(value)
            self.tree.insert("", "end", text=value)
        except Exception as e:
            messagebox.showerror("New Column", "Не вдалося додати колонки!\nОпис проблеми:\n{e}")
            return

        self.frame_tree.tkraise()

    def load_data(self, data: list[str]):
        """
        Завантажує список колонок у віджет Treeview.

        Args:
            data (list[str]): Список імен колонок (у форматі {поле: значення}).
        """
        for col in data:
            self.tree.insert("", "end", text=col)

    def show_info(self):
        """
        Відображає інформаційне вікно з описом елементів таблиці.

        Викликає метод get_info_doc() у віджеті tree для отримання тексту.
        """
        messagebox.showinfo("Info", self.tree.get_info_doc())


class UserMenu(ttk.Frame):
    """
    Графічне меню управління користувачами.

    Дозволяє переглядати, додавати та видаляти користувачів із бази даних.
    Включає таблицю з даними, меню дій та кнопки для основних операцій.

    Parameters:
        master (tk.Widget): Батьківський віджет.
        controller (Application): Головний контролер застосунку.
        **kwargs: Додаткові іменовані аргументи для ttk.Frame.

    Attributes:
        users_handler (UsersHandler): Обробник даних користувачів.
        controller (Application): Головний контролер додатку.
        field_names (list[str]): Назви полів для відображення у таблиці.
        tree (SortableTreeview): Віджет таблиці для перегляду даних користувачів.
        user_label (ttk.Label): Мітка з поточним ім'ям користувача.
    """

    def __init__(self, master, controller: Application, **kwargs):
        super().__init__(master, **kwargs)
        self.users_handler = UsersHandler()
        self.controller = controller

        self.field_names = self.users_handler.get_field_names()

        self._build_interface()

        self.controller.bind("<<show_frame>>", self.update_frame, add="+")
        self.controller.bind("<<new_account_created>>", self.load_data, add="+")

    def _build_interface(self):
        """
        Побудова графічного інтерфейсу користувацького меню.

        Містить три основні частини: заголовок (ім’я користувача та кнопка назад),
        тіло (таблиця користувачів), та футер (кнопки додавання/видалення).
        """
        # ----- Set up Header frame -----
        frame_header = ttk.Frame(self, padding=(5, 5, 5, 10), width=450)
        frame_header.pack(anchor="n", fill=tk.X, padx=10, pady=10)

        self.user_label = ttk.Label(frame_header, text="USER-NAME")
        self.user_label.pack(side=tk.LEFT)

        button_go_back = ttk.Button(
            frame_header,
            text="Go Back", width=15,
            command=self.__on_go_back_clicked
        )
        button_go_back.pack(side=tk.RIGHT)
        # ----- --- -- ------- ----- -----

        # ----- Set up Body frame -----
        frame_body = ttk.Frame(self, width=450)
        frame_body.pack(expand=True, fill=tk.BOTH, padx=10)

        scrollbar = ttk.Scrollbar(frame_body, orient="vertical")
        scrollbar.pack(side="right", fill="y")

        self.tree = SortableTreeview(
            frame_body,
            columns=self.field_names,
            selectmode="browse",
            show="headings",
            height=8,
            yscrollcommand=scrollbar.set,
        )
        self.tree.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        scrollbar.config(command=self.tree.yview)

        self.load_data()
        # ----- --- -- ---- ----- -----

        # ----- Set up Footer frame -----
        frame_footer = ttk.Frame(self, width=450)
        frame_footer.pack(anchor="s", fill=tk.X, padx=10, pady=10)

        button_new_record = ttk.Button(frame_footer, text="Add New", command=self.__on_add_new_clicked, width=15)
        button_new_record.pack(side=tk.LEFT)

        button_del_record = ttk.Button(frame_footer, text="Delete", command=self.__on_delete_clicked, width=15)
        button_del_record.pack(side=tk.LEFT)
        # ----- --- -- ------ ----- -----

    def load_data(self, event=None):
        """
        Завантажує дані користувачів із джерела у таблицю.

        Args:
            event (tk.Event, optional): Подія, якщо метод викликається через зв’язування. За замовчуванням None.
        """
        # data getting from DB
        records = self.users_handler.get_records()

        self.tree.load_data(records)

    def update_frame(self, event=None):
        """
        Оновлює елементи меню при показі фрейму.

        Встановлює елементи меню: "Редагувати", "Адмін-панель", "Інфо." залежно від ролі та авторизації.

        Args:
            event (tk.Event, optional): Подія, якщо викликано через зв’язування. За замовчуванням None.
        """
        if self.controller.current_menu != UserMenu:
            return

        edit_menu = tk.Menu(self.controller.menubar, tearoff=0)
        edit_menu.add_command(label="Додати користувача", command=self.__on_add_new_clicked)
        edit_menu.add_command(label="Видалити обраного користувача", command=self.__on_delete_clicked)
        self.controller.menubar.add_cascade(label="Редагувати", menu=edit_menu)

        if self.controller.var_authentication.get():
            # authentication is turn ON
            self.user_label.configure(
                text=self.users_handler.get_authenticated_user_name() + f" ({self.controller.get_access_role()})"
            )

        if not self.controller.var_authentication.get() or self.controller.get_access_role() == DEFAULT_ADMIN_ROLE:
            # authentication is turn OFF or access_role is ADMIN
            admin_panel_menu = tk.Menu(self.controller.menubar, tearoff=0)
            admin_panel_menu.add_command(label="Повернутись до головної панелі",
                                         command=self.__on_go_back_clicked)
            self.controller.menubar.add_cascade(label="Адмін-панель", menu=admin_panel_menu)

        help_menu = tk.Menu(self.controller.menubar, tearoff=0)
        help_menu.add_command(
            label="Про програму",
            command=lambda: messagebox.showinfo("Про програму", self.controller.get_info_doc())
        )
        help_menu.add_command(
            label="Як взаємодіяти із таблицею",
            command=lambda: messagebox.showinfo("Як взаємодіяти із таблицею", self.tree.get_info_doc())
        )
        self.controller.menubar.add_cascade(label="Інфо.", menu=help_menu)

    # --- binding function ---
    def __on_go_back_clicked(self):
        """
        Обробник кнопки "Go Back".
        Повертає користувача до попереднього меню.
        """
        self.controller.go_back_menu()

    def __on_modal_new_account_created(self, modal: tk.Toplevel):
        """
        Закриває модальне вікно та оновлює дані після створення нового акаунту.

        Args:
            modal (tk.Toplevel): Вікно, яке необхідно закрити.
        """
        modal.destroy()
        self.load_data()

    def __on_add_new_clicked(self):
        """
        Відкриває модальне вікно для додавання нового користувача.
        """
        modal = create_modal(self.controller, "New Account")

        frame = NewAccountMenu(parent=modal, controller=None, comm=lambda: self.__on_modal_new_account_created(modal))
        frame.pack(expand=True, fill=tk.BOTH)

    def __on_delete_clicked(self):
        """
        Видаляє обраного користувача після підтвердження.

        Якщо запис не вибрано — показує попередження.
        Якщо підтверджено — видаляє запис із бази та з інтерфейсу.
        """
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Видалення...", "Спершу оберіть запис у таблиці!")
            return

        selected_item_iid = selected_item[0]
        value = self.tree.set(selected_item_iid)

        result = messagebox.askyesno(
            "Видалення...",f"Впевнені, що хочете видалити користувача {value["username"]}?"
        )

        if not result:
            return

        self.users_handler.remove(value["id"])
        self.tree.delete(selected_item_iid)
# ~~~~~~~~~~~~~~~ ~~~~~~~~ ~~~~~~~~~~~~~~~

if __name__ == "__main__":
    app = Application()
    app.mainloop()
