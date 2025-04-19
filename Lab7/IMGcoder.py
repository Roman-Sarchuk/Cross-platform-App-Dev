import os
import base64

def encode_images_in_folder(folder_path):
    # Перевірка чи існує папка
    if not os.path.exists(folder_path):
        print(f"Папка {folder_path} не знайдена!")
        return

    # Перебираємо всі файли в папці
    counter = 0
    for filename in os.listdir(folder_path):
        counter += 1
        file_path = os.path.join(folder_path, filename)

        # Перевірка чи це файл зображення (можна доповнити перевірку за розширенням)
        if os.path.isfile(file_path) and filename.lower().endswith(('.png', '.jpg', '.jpeg')):
            try:
                # Відкриваємо файл зображення та кодуємо його в base64
                with open(file_path, "rb") as img_file:
                    encoded_string = base64.b64encode(img_file.read()).decode("utf-8")

                # Виводимо назву файлу та Base64 рядок
                print(f"{counter}) =--=--= {filename} =--=--=")
                print(f"{encoded_string}\n")
            except Exception as e:
                print(f"Не вдалося обробити файл {filename}: {e}")

# Шлях до папки з емодзі
folder_path = "emoji"  # заміни на свій шлях до папки

# Викликаємо функцію для обробки файлів у папці
encode_images_in_folder(folder_path)
