from flask import Flask, request, jsonify, send_from_directory, session
import mysql.connector
import os
from argon2 import PasswordHasher
import os
from dotenv import load_dotenv
import secrets
import string
import base64

from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)

from webauthn.helpers.structs import (
    PublicKeyCredentialDescriptor,
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
)
from webauthn.helpers import base64url_to_bytes


load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY")

RP_ID = "localhost"
RP_NAME = "ReAnchor"
ORIGIN = "http://localhost:5000"

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
def bytes_to_base64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def generate_recovery_code():
    alphabet = string.ascii_uppercase + string.digits

    return "".join(
        secrets.choice(alphabet)
        for _ in range(16)
    )

def store_recovery_codes(user_id, recovery_codes):
    conn = get_db_connection()
    cursor = conn.cursor()

    for code in recovery_codes:

        code_hash = ph.hash(code)

        cursor.execute(
            """
            INSERT INTO recovery_codes
                (user_id, code_hash, used)
            VALUES
                (%s, %s, FALSE)
            """,
            (user_id, code_hash)
        )

    conn.commit()

    cursor.close()
    conn.close()

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

from flask import Flask, request, jsonify, send_from_directory, session
import mysql.connector
import os
import pyotp
import qrcode
import io
import base64

from dotenv import load_dotenv
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


load_dotenv()

app = Flask(__name__)

app.secret_key = os.environ.get("FLASK_SECRET_KEY")

ph = PasswordHasher()

FRONTEND_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "Frontend")
)



def get_db_connection():
    return mysql.connector.connect(
        host=os.environ.get("DB_HOST", "localhost"),
        user=os.environ.get("DB_USER", "root"),
        password=os.environ.get("DB_PASSWORD"),
        database=os.environ.get("DB_NAME", "Reauth")
    )

@app.route("/")
def home():
    return send_from_directory(
        FRONTEND_DIR,
        "index.html"
    )


@app.route("/css/<path:filename>")
def css(filename):
    return send_from_directory(
        os.path.join(FRONTEND_DIR, "css"),
        filename
    )


@app.route("/js/<path:filename>")
def js(filename):
    return send_from_directory(
        os.path.join(FRONTEND_DIR, "js"),
        filename
    )


@app.route("/images/<path:filename>")
def images(filename):
    return send_from_directory(
        os.path.join(FRONTEND_DIR, "images"),
        filename
    )


@app.route("/register", methods=["POST"])
def register():

    username = request.form.get("username")
    email = request.form.get("email")
    password = request.form.get("password")
    password_confirmation = request.form.get("password_confirmation")

    if not username or not email or not password:
        return jsonify({
            "error": "Missing required fields"
        }), 400

    if password != password_confirmation:
        return jsonify({
            "error": "Passwords do not match"
        }), 400

    try:
        # Hash password using Argon2id
        password_hash = ph.hash(password)

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO users
                (username, email, password_hash)
            VALUES
                (%s, %s, %s)
            """,
            (username, email, password_hash)
        )

        conn.commit()

        user_id = cursor.lastrowid

        cursor.close()
        conn.close()

        return jsonify({
            "status": "ok",
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


@app.route("/login", methods=["POST"])
def login():

    # Frontend sends EMAIL
    email = request.form.get("email")
    password = request.form.get("password")

    if not email or not password:
        return jsonify({
            "error": "Missing email or password"
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT user_id, password_hash
        FROM users
        WHERE email = %s
        """,
        (email,)
    )

    result = cursor.fetchone()

    if not result:
        cursor.close()
        conn.close()

        return jsonify({
            "error": "Invalid email or password"
        }), 401

    user_id, password_hash = result

    # Verify Argon2 password hash
    try:
        ph.verify(password_hash, password)

    except VerifyMismatchError:
        cursor.close()
        conn.close()

        return jsonify({
            "error": "Invalid email or password"
        }), 401

    # Check whether TOTP is enabled
    cursor.execute(
        """
        SELECT enabled
        FROM totp_credentials
        WHERE user_id = %s
        """,
        (user_id,)
    )

    totp_row = cursor.fetchone()

    cursor.close()
    conn.close()

    if totp_row and totp_row[0]:

        # Password correct, but 2FA still required
        session["pending_user_id"] = user_id

        return jsonify({
            "status": "2fa_required"
        }), 200

    # No TOTP enabled → complete login
    session["user_id"] = user_id

    return jsonify({
        "status": "ok",
        "message": "Logged in successfully"
    }), 200

@app.route("/2fa/setup", methods=["POST"])
def totp_setup():

    if "user_id" not in session:
        return jsonify({
            "error": "Not authenticated"
        }), 401

    user_id = session["user_id"]

    conn = get_db_connection()
    cursor = conn.cursor()

    # Get user's email
    cursor.execute(
        """
        SELECT email
        FROM users
        WHERE user_id = %s
        """,
        (user_id,)
    )

    user = cursor.fetchone()

    if not user:
        cursor.close()
        conn.close()

        return jsonify({
            "error": "User not found"
        }), 404

    email = user[0]

    # Generate new TOTP secret
    totp_secret = pyotp.random_base32()

    # Store secret but keep TOTP disabled
    cursor.execute(
        """
        INSERT INTO totp_credentials
            (user_id, secret, enabled)
        VALUES
            (%s, %s, FALSE)
        ON DUPLICATE KEY UPDATE
            secret = %s,
            enabled = FALSE
        """,
        (
            user_id,
            totp_secret,
            totp_secret
        )
    )

    conn.commit()

    cursor.close()
    conn.close()

    # Create TOTP object
    totp = pyotp.TOTP(totp_secret)

    # Create authenticator provisioning URI
    provisioning_uri = totp.provisioning_uri(
        name=email,
        issuer_name="ReAnchor"
    )

    # Generate QR code
    qr = qrcode.make(provisioning_uri)

    buffer = io.BytesIO()

    qr.save(
        buffer,
        format="PNG"
    )

    qr_code = base64.b64encode(
        buffer.getvalue()
    ).decode("utf-8")

    # Format setup key into groups of 4
    display_key = " ".join(
        totp_secret[i:i + 4]
        for i in range(0, len(totp_secret), 4)
    )

    return jsonify({
        "qr_code": f"data:image/png;base64,{qr_code}",
        "setup_key": display_key
    })

@app.route("/2fa/verify", methods=["POST"])
def totp_verify():

    if "user_id" not in session:
        return jsonify({
            "error": "Not authenticated"
        }), 401

    user_id = session["user_id"]

    user_otp = request.form.get("otp")

    if not user_otp:
        return jsonify({
            "error": "Verification code is required"
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT secret
        FROM totp_credentials
        WHERE user_id = %s
        """,
        (user_id,)
    )

    result = cursor.fetchone()

    if not result:
        cursor.close()
        conn.close()

        return jsonify({
            "error": "No TOTP setup found"
        }), 400

    totp_secret = result[0]

    totp = pyotp.TOTP(totp_secret)

    # Verify 6-digit authenticator code
    if totp.verify(user_otp, valid_window=1):

        cursor.execute(
            """
            UPDATE totp_credentials
            SET enabled = TRUE
            WHERE user_id = %s
            """,
            (user_id,)
        )

        conn.commit()

        cursor.close()
        conn.close()

        # Generate 5 recovery codes
        recovery_codes = [
            generate_recovery_code()
            for _ in range(5)
        ]

        # Store ONLY the Argon2 hashes
        store_recovery_codes(
            user_id,
            recovery_codes
        )

        return jsonify({
            "status": "enabled",
            "message": "Authenticator enabled successfully",
            "recovery_codes": recovery_codes
        }), 200

    cursor.close()
    conn.close()

    return jsonify({
        "error": (
            "Invalid verification code. "
            "Please check your authenticator app and try again."
        )
    }), 401

@app.route("/2fa/challenge", methods=["POST"])
def totp_challenge():

    if "pending_user_id" not in session:
        return jsonify({
            "error": "No pending login"
        }), 400

    user_id = session["pending_user_id"]

    user_otp = request.form.get("otp")

    if not user_otp:
        return jsonify({
            "error": "Verification code is required"
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT secret
        FROM totp_credentials
        WHERE user_id = %s
          AND enabled = TRUE
        """,
        (user_id,)
    )

    result = cursor.fetchone()

    cursor.close()
    conn.close()

    if not result:
        return jsonify({
            "error": "2FA is not enabled"
        }), 400

    totp_secret = result[0]

    totp = pyotp.TOTP(totp_secret)

    if totp.verify(user_otp, valid_window=1):

        # Complete login
        session["user_id"] = user_id

        # Remove temporary login state
        session.pop("pending_user_id", None)

        return jsonify({
            "status": "ok",
            "message": "2FA verified. Login successful."
        }), 200

    return jsonify({
        "error": "Invalid verification code"
    }), 401

@app.route("/recovery/confirm", methods=["POST"])
def confirm_recovery_code():

    if "user_id" not in session:
        return jsonify({
            "error": "Not authenticated"
        }), 401

    user_id = session["user_id"]
    code = request.form.get("code")

    if not code:
        return jsonify({
            "error": "Recovery code is required"
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT code_hash
        FROM recovery_codes
        WHERE user_id = %s
          AND used = FALSE
        """,
        (user_id,)
    )

    rows = cursor.fetchall()

    cursor.close()
    conn.close()

    for row in rows:

        code_hash = row[0]

        try:
            if ph.verify(code_hash, code):

                return jsonify({
                    "status": "confirmed",
                    "message": "Recovery code confirmed."
                }), 200

        except VerifyMismatchError:
            continue

    return jsonify({
        "error": "Invalid recovery code."
    }), 401

@app.route("/logout", methods=["POST"])
def logout():

    session.clear()

    return jsonify({
        "status": "ok",
        "message": "Logged out successfully"
    }), 200

@app.route("/webauthn/register/options", methods=["POST"])
def webauthn_register_options():

    if "user_id" not in session:
        return jsonify({
            "error": "Not authenticated"
        }), 401

    user_id = session["user_id"]

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT username
        FROM users
        WHERE user_id = %s
        """,
        (user_id,)
    )

    user_row = cursor.fetchone()

    if not user_row:
        cursor.close()
        conn.close()

        return jsonify({
            "error": "User not found"
        }), 404

    username = user_row[0]

    cursor.execute(
        """
        SELECT credential_id
        FROM webauthn_credentials
        WHERE user_id = %s
        """,
        (user_id,)
    )

    credential_rows = cursor.fetchall()

    cursor.close()
    conn.close()

    exclude_credentials = [
        PublicKeyCredentialDescriptor(
            id=row[0]
        )
        for row in credential_rows
    ]

    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=str(user_id).encode("utf-8"),
        user_name=username,
        user_display_name=username,
        exclude_credentials=exclude_credentials,
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.REQUIRED
        )
    )

    session["webauthn_register_challenge"] = bytes_to_base64url(
        options.challenge
    )

    return options_to_json(options), 200

@app.route("/webauthn/register/verify", methods=["POST"])
def webauthn_register_verify():

    if "user_id" not in session:
        return jsonify({
            "error": "Not authenticated"
        }), 401

    user_id = session["user_id"]

    challenge_b64 = session.get(
        "webauthn_register_challenge"
    )

    if not challenge_b64:
        return jsonify({
            "error": "Registration challenge expired or missing."
        }), 400

    credential = request.get_json()

    if not credential:
        return jsonify({
            "error": "Credential data is required."
        }), 400

    try:

        expected_challenge = base64url_to_bytes(
                challenge_b64
            )

        verification = verify_registration_response(
                credential=credential,
                expected_challenge=expected_challenge,
                expected_origin=ORIGIN,
                expected_rp_id=RP_ID
            )

    except Exception as e:

        return jsonify({
            "error":
                f"WebAuthn verification failed: {str(e)}"
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    try:

        cursor.execute(
            """
            INSERT INTO webauthn_credentials
                (
                    user_id,
                    credential_id,
                    public_key,
                    sign_count
                )
            VALUES
                (%s, %s, %s, %s)
            """,
            (
                user_id,
                verification.credential_id,
                verification.credential_public_key,
                verification.sign_count
            )
        )

        conn.commit()

    except mysql.connector.Error as e:

        conn.rollback()

        cursor.close()
        conn.close()

        return jsonify({
            "error":
                f"Unable to store passkey: {str(e)}"
        }), 500

    cursor.close()
    conn.close()

    session.pop(
        "webauthn_register_challenge",
        None
    )

    return jsonify({
        "status": "registered",
        "message": "Passkey registered successfully."
    }), 200

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
