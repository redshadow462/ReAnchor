import os
import mysql.connector as ms

from argon2 import PasswordHasher
from dotenv import load_dotenv

load_dotenv()

# Argon2id password hasher
ph = PasswordHasher()


def get_db_connection():
    return ms.connect(
        host=os.environ.get("DB_HOST"),
        user=os.environ.get("DB_USER"),
        password=os.environ.get("DB_PASSWORD"),
        database=os.environ.get("DB_NAME")
    )