import hashlib
import os

user_data = {}

def generate_hash(password, salt):
    h = hashlib.sha256((password + salt).encode())
    return h.hexdigest()

def sign_up():
    username = input("Enter a username: ")
    if username in user_data:
        print("Username already exists. Please try again.")
        return

    password = input("Enter a password: ")
    salt = os.urandom(16).hex()
    hashed_password = generate_hash(password, salt)

    user_data[username] = {
        "salt": salt,
        "hashed_password": hashed_password
    }
    print("Sign-up successful!")

def login():
    username = input("Enter your username: ")
    if username not in user_data:
        print("Username doesn't exist. do sign up first.")
        return

    password = input("Enter your password: ")
    salt = user_data[username]["salt"]
    hashed_password = generate_hash(password, salt)

    if hashed_password == user_data[username]["hashed_password"]:
        print("Login successful!")
    else:
        print("Invalid password")

while True:
    print("\nSelect an option: \n1 - Sign Up \n2 - Login \n3 - Exit")
    c = input("Enter your choice: ")
    if c == "1":
        sign_up()
    elif c == "2":
        login()
    elif c == "3":
        print("Goodbye!")
        break
    else:
        print("Invalid choice.")
