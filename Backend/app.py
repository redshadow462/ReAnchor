from flask import Flask, request, jsonify, send_from_directory
import mysql.connector
import os
from argon2 import PasswordHasher
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

ph = PasswordHasher()

# Frontend location
FRONTEND_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "Frontend")
)


def get_db_connection():
    return mysql.connector.connect(
        host=os.environ.get("DB_HOST"),
        user=os.environ.get("DB_USER"),
        password=os.environ.get("DB_PASSWORD"),
        database=os.environ.get("DB_NAME")
    )

@app.route("/")
def home():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/css/<path:filename>")
def css(filename):
    return send_from_directory(
        os.path.join(FRONTEND_DIR, "css"),
        filename
    )

@app.route("/images/<path:filename>")
def images(filename):
    return send_from_directory(
        os.path.join(FRONTEND_DIR, "images"),
        filename
    )

@app.route("/js/<path:filename>")
def js(filename):
    return send_from_directory(
        os.path.join(FRONTEND_DIR, "js"),
        filename
    )


@app.route("/register", methods=["POST"])
def register():

    username = request.form.get("username")
    email = request.form.get("email")
    password = request.form.get("password")

    if not username or not email or not password:
        return jsonify({"error": "Missing fields"}), 400

    try:
        password_hash = ph.hash(password)

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO users (username, email, password_hash)
            VALUES (%s, %s, %s)
            """,
            (username, email, password_hash)
        )

        conn.commit()

        user_id = cursor.lastrowid

        cursor.close()
        conn.close()

        return jsonify({
            "message": "User registered successfully!",
            "user_id": user_id
        }), 200

    except mysql.connector.IntegrityError:
        return jsonify({
            "error": "Username or email already exists"
        }), 409

    except mysql.connector.Error as err:
        return jsonify({
            "error": str(err)
        }), 500


if __name__ == "__main__":
    app.run(debug=True)