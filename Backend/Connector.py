import mysql.connector as ms
import secrets
import string

from argon2 import PasswordHasher


import os
from dotenv import load_dotenv

load_dotenv()

mycon = ms.connect(
    host=os.environ.get("DB_HOST"),
    user=os.environ.get("DB_USER"),
    password=os.environ.get("DB_PASSWORD"),
    database=os.environ.get("DB_NAME")
)

mycur = mycon.cursor()

# Argon2id password hasher
ph = PasswordHasher()


def add_user():
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    # Hash password using Argon2id
    password_hash = ph.hash(password)

    q = """
        INSERT INTO users(username, password_hash)
        VALUES(%s, %s)
    """

    mycur.execute(q, (username, password_hash))
    mycon.commit()

    user_id = mycur.lastrowid

    recovery_code = give_recovery_code()

    store_recovery_code(user_id, recovery_code)

    print("User successfully added")
    print("User ID:", user_id)


def give_recovery_code():

    # Generate a 16-character alphanumeric recovery code
    alphabet = string.ascii_letters + string.digits

    recovery_code = ''.join(
        secrets.choice(alphabet)
        for _ in range(16)
    )

    print("Your recovery code is:", recovery_code)

    return recovery_code


def store_recovery_code(user_id, recovery_code):

    # Hash recovery code using Argon2id
    code_hash = ph.hash(recovery_code)

    q = """
        INSERT INTO recovery_codes(user_id, code_hash)
        VALUES(%s, %s)
    """

    mycur.execute(q, (user_id, code_hash))
    mycon.commit()

    print("Recovery code is stored successfully")


add_user()

mycur.close()
mycon.close()