import argparse
import getpass
import hashlib
from cryptography.fernet import Fernet

# Генерация ключа шифрования при первом запуске
try:
    with open('encryption_key.key', 'rb') as key_file:
        key = key_file.read()
except FileNotFoundError:
    key = Fernet.generate_key()
    with open('encryption_key.key', 'wb') as key_file:
        key_file.write(key)

cipher_suite = Fernet(key)


# Функция для шифрования пароля
def encrypt_password(plain_password):
    try:
        # Если пароль не передан, запрашиваем его
        if plain_password is None:
            plain_password = getpass.getpass("Введите пароль для шифрования: ")

        # Хеширование для дополнительной безопасности
        hashed_password = hashlib.sha256(plain_password.encode()).hexdigest()

        # Шифрование
        encrypted_password = cipher_suite.encrypt(plain_password.encode()).decode()

        print(f"Исходный пароль: {plain_password}")
        print(f"Хэшированный пароль: {hashed_password}")
        print(f"Зашифрованный пароль: {encrypted_password}")

        return encrypted_password

    except Exception as e:
        print(f"Ошибка шифрования: {e}")
        return None


# Функция для дешифрования пароля
def decrypt_password(encrypted_password):
    try:
        # Если зашифрованный пароль не передан, запрашиваем его
        if encrypted_password is None:
            encrypted_password = input("Введите зашифрованный пароль для расшифровки: ")

        # Дешифрование
        decrypted_password = cipher_suite.decrypt(encrypted_password.encode()).decode()

        print(f"Расшифрованный пароль: {decrypted_password}")
        return decrypted_password

    except Exception as e:
        print(f"Ошибка расшифровки: {e}")
        return None


# Настройка парсера аргументов
parser = argparse.ArgumentParser(description="Программа шифрования/дешифрования паролей")
parser.add_argument('action', choices=['encrypt', 'decrypt'], help='Действие для выполнения')
parser.add_argument('--password', '-p', help='Пароль для обработки')
parser.add_argument('--encrypted', '-e', help='Зашифрованный пароль для расшифровки')
parser.add_argument('--version', '-v', action='version', version='%(prog)s 1.0')


def main():
    args = parser.parse_args()

    try:
        if args.action == 'encrypt':
            if args.password:
                encrypt_password(args.password)
            else:
                encrypt_password(None)

        elif args.action == 'decrypt':
            if args.encrypted:
                decrypt_password(args.encrypted)
            else:
                decrypt_password(None)

    except Exception as e:
        print(f"Произошла ошибка: {e}")


if __name__ == "__main__":
    main()
