
import string

def encrypt_decrypt(text, mode, key):
    letters = string.ascii_lowercase
    num_letters = len(letters)
    result = ''

    key = key % num_letters
    if mode == 'd':
        key = -key

    for char in text:
        if char.isalpha():
            if char.isupper():
                start = ord('A')
            else:
                start = ord('a')

            new_position = (ord(char) - start + key) % 26
            result += chr(start + new_position)
        else:
            result += char

    return result

def get_valid_key():
    while True:
        try:
            key = int(input('Enter a key (1 through 25): '))
            if 1 <= key <= 25:
                return key
            else:
                print("Key must be between 1 and 25. Please try again.")
        except ValueError:
            print("Invalid input. Please enter a number between 1 and 25.")

def main():
    while True:
        print("\n*** CAESAR CIPHER PROGRAM ***")
        print("1. Encrypt a message")
        print("2. Decrypt a message")
        print("3. Exit")

        choice = input("Enter your choice (1-3): ")

        if choice == '1':
            print("\nENCRYPTION MODE")
            key = get_valid_key()
            text = input('Enter the text to encrypt: ')
            ciphertext = encrypt_decrypt(text, 'e', key)
            print(f'CIPHERTEXT: {ciphertext}')

        elif choice == '2':
            print("\nDECRYPTION MODE")
            key = get_valid_key()
            text = input('Enter the text to decrypt: ')
            plaintext = encrypt_decrypt(text, 'd', key)
            print(f'PLAINTEXT: {plaintext}')

        elif choice == '3':
            print("Thank you for using the Caesar Cipher program. Goodbye!")
            break

        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()
