from flask import Flask, request, jsonify, send_from_directory, session
import mysql.connector
import os
import pyotp
import qrcode
import io
import base64
import string
import re
import secrets
from dotenv import load_dotenv
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from dms import dms_bp

from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json
)
from webauthn.helpers.structs import (
    PublicKeyCredentialDescriptor,
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement
)
from webauthn.helpers import base64url_to_bytes

load_dotenv()
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
ph = PasswordHasher()

app.register_blueprint(dms_bp)

RP_ID = "localhost"
RP_NAME = "ReAnchor"
ORIGIN = "http://localhost:5000"

FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "Frontend"))
KNOWLEDGE_QUESTIONS = {
    1: "What was the first operating system you installed yourself?",
    2: "Which superhero's power do you consider completely useless?",
    3: "What specific pizza topping do you absolutely refuse to eat?",
    4: "What was the first command-line tool you ever memorized?",
    5: "What is the name of the first fictional weapon you wished you owned?",
    6: "Which video game boss took you the most tries to defeat?",
    7: "What specific beverage is your must-have for late-night studying?",
    8: "What was your absolute least favorite subject in middle school?",
    9: "Which anime or movie universe would you hate living in the most?",
    10: "What was the first computer program you remember being fascinated by?",
    11: "What is the one household chore you despise doing the most?",
    12: "What specific PC hardware part would you always upgrade first?",
    13: "What board game always caused arguments in your family?",
    14: "What was your favorite playground game in primary school?",
    15: "What was the first fictional world you remember imagining in detail?"
}
def validate_password(password):

    if len(password) < 12:
        return False, "Password must be at least 12 characters long."

    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."

    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."

    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number."

    if not re.search(r"[^A-Za-z0-9]", password):
        return False, "Password must contain at least one special character."

    return True, ""


def get_db_connection():
    return mysql.connector.connect(
        host=os.environ.get("DB_HOST", "localhost"),
        user=os.environ.get("DB_USER", "root"),
        password=os.environ.get("DB_PASSWORD"),
        database=os.environ.get("DB_NAME", "Reauth")
    )
def bytes_to_base64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def generate_recovery_code():
    alphabet = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(16))

def store_recovery_codes(user_id, recovery_codes):
    conn = get_db_connection()
    cursor = conn.cursor()
    for code in recovery_codes:
        code_hash = ph.hash(code)
        cursor.execute("INSERT INTO recovery_codes (user_id, code_hash, used) VALUES (%s, %s, FALSE)", (user_id, code_hash))
    conn.commit()
    cursor.close()
    conn.close()

def normalize_knowledge_answer(answer):
    return " ".join(
        answer.strip().lower().split()
    )

@app.route("/")
def home():
    return send_from_directory(FRONTEND_DIR, "index.html")

@app.route("/css/<path:filename>")
def css(filename):
    return send_from_directory(os.path.join(FRONTEND_DIR, "css"), filename)

@app.route("/js/<path:filename>")
def js(filename):
    return send_from_directory(os.path.join(FRONTEND_DIR, "js"), filename)

@app.route("/images/<path:filename>")
def images(filename):
    return send_from_directory(os.path.join(FRONTEND_DIR, "images"), filename)

@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    email = request.form.get("email")
    password = request.form.get("password")
    password_confirmation = request.form.get("password_confirmation")

    if not username or not email or not password:
        return jsonify({"error": "Missing required fields"}), 400

    if password != password_confirmation:
        return jsonify({"error": "Passwords do not match"}), 400

    valid, password_error = validate_password(password)

    if not valid:
        return jsonify({"error": password_error}), 400

    try:
        password_hash = ph.hash(password)

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
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
        return jsonify({"error": "Username or email already exists"}), 409

    except mysql.connector.Error as err:
        return jsonify({"error": str(err)}), 500

@app.route("/login", methods=["POST"])
def login():
    email = request.form.get("email")
    password = request.form.get("password")
    if not email or not password: return jsonify({"error": "Missing email or password"}), 400
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT user_id, password_hash FROM users WHERE email = %s", (email,))
    result = cursor.fetchone()
    if not result:
        cursor.close()
        conn.close()
        return jsonify({"error": "Invalid email or password"}), 401
    user_id, password_hash = result
    try:
        ph.verify(password_hash, password)
    except VerifyMismatchError:
        cursor.close()
        conn.close()
        return jsonify({"error": "Invalid email or password"}), 401
    
    cursor.execute("SELECT enabled FROM totp_credentials WHERE user_id = %s", (user_id,))
    totp_row = cursor.fetchone()
    
    cursor.execute("SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = %s", (user_id,))
    webauthn_count = cursor.fetchone()[0]
    cursor.close()
    conn.close()
    
    if (totp_row and totp_row[0]) or webauthn_count > 0:
        session["pending_user_id"] = user_id
        return jsonify({
            "status": "2fa_required",
            "has_totp": bool(totp_row and totp_row[0]),
            "has_passkey": webauthn_count > 0
        }), 200
        
    session["user_id"] = user_id

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET last_activity = CURRENT_TIMESTAMP WHERE user_id = %s",
        (user_id,)
    )
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({
        "status": "ok",
        "message": "Logged in successfully"
    }), 200

@app.route("/2fa/setup", methods=["POST"])
def totp_setup():
    if "user_id" not in session: return jsonify({"error": "Not authenticated"}), 401
    user_id = session["user_id"]
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT email FROM users WHERE user_id = %s", (user_id,))
    user = cursor.fetchone()
    if not user:
        cursor.close()
        conn.close()
        return jsonify({"error": "User not found"}), 404
    email = user[0]
    totp_secret = pyotp.random_base32()
    cursor.execute("INSERT INTO totp_credentials (user_id, secret, enabled) VALUES (%s, %s, FALSE) ON DUPLICATE KEY UPDATE secret = %s, enabled = FALSE", (user_id, totp_secret, totp_secret))
    conn.commit()
    cursor.close()
    conn.close()
    totp = pyotp.TOTP(totp_secret)
    provisioning_uri = totp.provisioning_uri(name=email, issuer_name="ReAnchor")
    qr = qrcode.make(provisioning_uri)
    buffer = io.BytesIO()
    qr.save(buffer, format="PNG")
    qr_code = base64.b64encode(buffer.getvalue()).decode("utf-8")
    display_key = " ".join(totp_secret[i:i + 4] for i in range(0, len(totp_secret), 4))
    return jsonify({"qr_code": f"data:image/png;base64,{qr_code}", "setup_key": display_key})

@app.route("/2fa/verify", methods=["POST"])
def totp_verify():
    if "user_id" not in session: return jsonify({"error": "Not authenticated"}), 401
    user_id = session["user_id"]
    user_otp = request.form.get("otp")
    if not user_otp: return jsonify({"error": "Verification code is required"}), 400
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT secret FROM totp_credentials WHERE user_id = %s", (user_id,))
    result = cursor.fetchone()
    if not result:
        cursor.close()
        conn.close()
        return jsonify({"error": "No TOTP setup found"}), 400
    totp_secret = result[0]
    totp = pyotp.TOTP(totp_secret)
    if totp.verify(user_otp, valid_window=1):
        cursor.execute("UPDATE totp_credentials SET enabled = TRUE WHERE user_id = %s", (user_id,))
        conn.commit()
        cursor.close()
        conn.close()
        recovery_codes = [generate_recovery_code() for _ in range(8)]
        store_recovery_codes(user_id, recovery_codes)
        return jsonify({"status": "enabled", "message": "Authenticator enabled successfully", "recovery_codes": recovery_codes}), 200
    cursor.close()
    conn.close()
    return jsonify({"error": "Invalid verification code. Please check your authenticator app and try again."}), 401

@app.route("/2fa/challenge", methods=["POST"])
def totp_challenge():
    if "pending_user_id" not in session: return jsonify({"error": "No pending login"}), 400
    user_id = session["pending_user_id"]
    user_otp = request.form.get("otp")
    if not user_otp: return jsonify({"error": "Verification code is required"}), 400
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT secret FROM totp_credentials WHERE user_id = %s AND enabled = TRUE", (user_id,))
    result = cursor.fetchone()
    cursor.close()
    conn.close()
    if not result: return jsonify({"error": "2FA is not enabled"}), 400
    totp_secret = result[0]
    totp = pyotp.TOTP(totp_secret)

    if totp.verify(user_otp, valid_window=1):

        session["user_id"] = user_id
        session.pop("pending_user_id", None)

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "UPDATE users SET last_activity = CURRENT_TIMESTAMP WHERE user_id = %s",
            (user_id,)
        )

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            "status": "ok",
            "message": "2FA verified. Login successful."
        }), 200

    return jsonify({"error": "Invalid verification code"}), 401

    
@app.route("/recovery/confirm", methods=["POST"])
def confirm_recovery_code():
    if "user_id" not in session: return jsonify({"error": "Not authenticated"}), 401
    user_id = session["user_id"]
    code = request.form.get("code")
    if not code: return jsonify({"error": "Recovery code is required"}), 400
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT code_hash FROM recovery_codes WHERE user_id = %s AND used = FALSE", (user_id,))
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    for row in rows:
        code_hash = row[0]
        try:
            if ph.verify(code_hash, code):
                return jsonify({"status": "confirmed", "message": "Recovery code confirmed."}), 200
        except VerifyMismatchError:
            continue
    return jsonify({"error": "Invalid recovery code."}), 401

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"status": "ok", "message": "Logged out successfully"}), 200

# WEBAUTHN ENDPOINTS
@app.route("/webauthn/register/options", methods=["POST"])
def webauthn_register_options():
    if "user_id" not in session: return jsonify({"error": "Not authenticated"}), 401
    user_id = session["user_id"]
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE user_id = %s", (user_id,))
    user_row = cursor.fetchone()
    if not user_row:
        cursor.close()
        conn.close()
        return jsonify({"error": "User not found"}), 404
    username = user_row[0]
    cursor.execute("SELECT credential_id FROM webauthn_credentials WHERE user_id = %s", (user_id,))
    credential_rows = cursor.fetchall()
    cursor.close()
    conn.close()
    exclude_credentials = [PublicKeyCredentialDescriptor(id=row[0]) for row in credential_rows]
    options = generate_registration_options(
        rp_id=RP_ID, rp_name=RP_NAME, user_id=str(user_id).encode("utf-8"), user_name=username, user_display_name=username,
        exclude_credentials=exclude_credentials, authenticator_selection=AuthenticatorSelectionCriteria(user_verification=UserVerificationRequirement.PREFERRED)
    )
    session["webauthn_register_challenge"] = bytes_to_base64url(options.challenge)
    return options_to_json(options), 200

@app.route("/webauthn/register/verify", methods=["POST"])
def webauthn_register_verify():
    if "user_id" not in session: return jsonify({"error": "Not authenticated"}), 401
    user_id = session["user_id"]
    challenge_b64 = session.get("webauthn_register_challenge")
    if not challenge_b64: return jsonify({"error": "Registration challenge expired or missing."}), 400
    credential = request.get_json()
    if not credential: return jsonify({"error": "Credential data is required."}), 400
    try:
        expected_challenge = base64url_to_bytes(challenge_b64)
        verification = verify_registration_response(credential=credential, expected_challenge=expected_challenge, expected_origin=ORIGIN, expected_rp_id=RP_ID)
    except Exception as e:
        return jsonify({"error": f"WebAuthn verification failed: {str(e)}"}), 400
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO webauthn_credentials (user_id, credential_id, public_key, sign_count) VALUES (%s, %s, %s, %s)",
            (user_id, verification.credential_id, verification.credential_public_key, verification.sign_count))
        conn.commit()
    except mysql.connector.Error as e:
        conn.rollback()
        cursor.close()
        conn.close()
        return jsonify({"error": f"Unable to store passkey: {str(e)}"}), 500
    cursor.close()
    conn.close()
    session.pop("webauthn_register_challenge", None)
    return jsonify({"status": "registered", "message": "Passkey registered successfully."}), 200

@app.route("/webauthn/login/options", methods=["POST"])
def webauthn_login_options():
    user_id = session.get("pending_user_id")
    if not user_id:
        data = request.get_json()
        if not data or not data.get("email"): return jsonify({"error": "Email is required."}), 400
        email = data.get("email")
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT user_id FROM users WHERE email = %s", (email,))
        user_row = cursor.fetchone()
        cursor.close()
        conn.close()
        if not user_row: return jsonify({"error": "Account not found."}), 404
        user_id = user_row[0]
        
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT credential_id FROM webauthn_credentials WHERE user_id = %s", (user_id,))
    credential_rows = cursor.fetchall()
    cursor.close()
    conn.close()
    if not credential_rows: return jsonify({"error": "No passkey is registered for this account."}), 404
    allow_credentials = [PublicKeyCredentialDescriptor(id=row[0]) for row in credential_rows]
    options = generate_authentication_options(rp_id=RP_ID, allow_credentials=allow_credentials, user_verification=UserVerificationRequirement.PREFERRED)
    session["webauthn_login_challenge"] = bytes_to_base64url(options.challenge)
    session["webauthn_login_user_id"] = user_id
    return options_to_json(options), 200

@app.route("/webauthn/login/verify", methods=["POST"])
def webauthn_login_verify():
    user_id = session.get("webauthn_login_user_id")
    challenge_b64 = session.get("webauthn_login_challenge")
    if not user_id or not challenge_b64: return jsonify({"error": "Passkey login session expired."}), 400
    credential = request.get_json()
    if not credential: return jsonify({"error": "Credential data is required."}), 400
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT credential_id, public_key, sign_count FROM webauthn_credentials WHERE user_id = %s", (user_id,))
    credentials = cursor.fetchall()
    if not credentials:
        cursor.close()
        conn.close()
        return jsonify({"error": "No registered passkey found."}), 404
    try:
        expected_challenge = base64url_to_bytes(challenge_b64)
        credential_id = base64url_to_bytes(credential["rawId"])
        matching_credential = next((row for row in credentials if row[0] == credential_id), None)
        if not matching_credential:
            cursor.close()
            conn.close()
            return jsonify({"error": "Passkey is not registered for this account."}), 401
        verification = verify_authentication_response(
            credential=credential, expected_challenge=expected_challenge, expected_rp_id=RP_ID, expected_origin=ORIGIN,
            credential_public_key=matching_credential[1], credential_current_sign_count=matching_credential[2]
        )
    except Exception as e:
        cursor.close()
        conn.close()
        return jsonify({"error": f"Passkey verification failed: {str(e)}"}), 401
    cursor.execute("UPDATE webauthn_credentials SET sign_count = %s WHERE user_id = %s AND credential_id = %s",
        (verification.new_sign_count, user_id, matching_credential[0]))
    conn.commit()
    cursor.close()
    conn.close()
    session.pop("webauthn_login_challenge", None)
    session.pop("webauthn_login_user_id", None)
    session.pop("pending_user_id", None)
    session["user_id"] = user_id

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "UPDATE users SET last_activity = CURRENT_TIMESTAMP WHERE user_id = %s",
        (user_id,)
    )

    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({
        "status": "ok",
        "message": "Passkey login successful."
    }), 200

@app.route("/recovery", methods=["POST"])
def recovery_login():

    recovery_code = request.form.get("recovery_code")

    if not recovery_code:
        return jsonify({
            "error": "Recovery code is required."
        }), 400

    if len(recovery_code) != 16:
        return jsonify({
            "error": "Invalid recovery code."
        }), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id, user_id, code_hash
        FROM recovery_codes
        WHERE used = FALSE
        """
    )

    recovery_rows = cursor.fetchall()

    matched_id = None
    matched_user_id = None

    for row in recovery_rows:

        recovery_id, user_id, code_hash = row

        try:
            if ph.verify(code_hash, recovery_code):
                matched_id = recovery_id
                matched_user_id = user_id
                break

        except VerifyMismatchError:
            continue

    if matched_id is None:

        cursor.close()
        conn.close()

        return jsonify({
            "error": "Invalid or already used recovery code."
        }), 401

    cursor.execute(
        """
        UPDATE recovery_codes
        SET used = TRUE
        WHERE id = %s
        """,
        (matched_id,)
    )

    conn.commit()

    cursor.close()
    conn.close()

    session["user_id"] = matched_user_id
    session.pop("pending_user_id", None)

    return jsonify({
        "status": "ok",
        "message": "Recovery verification successful."
    }), 200

@app.route("/knowledge-anchor", methods=["POST"])
def save_knowledge_anchor():

    user_id = session.get("user_id")

    if not user_id:
        return jsonify({
            "error": "Authentication required."
        }), 401

    data = request.get_json()

    if not data:
        return jsonify({
            "error": "Invalid request."
        }), 400

    question_id = data.get("question_id")
    answer = data.get("answer", "")

    try:
        question_id = int(question_id)
    except (TypeError, ValueError):
        return jsonify({
            "error": "Invalid question."
        }), 400

    if question_id not in KNOWLEDGE_QUESTIONS:
        return jsonify({
            "error": "Invalid question."
        }), 400

    answer = normalize_knowledge_answer(answer)

    if len(answer) < 3:
        return jsonify({
            "error": "Answer must contain at least 3 characters."
        }), 400

    answer_hash = ph.hash(answer)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO knowledge_anchors
        (user_id, question_id, answer_hash)
        VALUES (%s, %s, %s)
        ON DUPLICATE KEY UPDATE
            question_id = VALUES(question_id),
            answer_hash = VALUES(answer_hash)
        """,
        (
            user_id,
            question_id,
            answer_hash
        )
    )

    conn.commit()

    cursor.close()
    conn.close()

    return jsonify({
        "status": "ok",
        "message": "Knowledge anchor saved."
    }), 200
# =========================
# VAULT
# =========================

@app.route("/api/vault", methods=["GET"])
def get_vault():

    if "user_id" not in session:
        return jsonify({
            "error": "Not authenticated"
        }), 401

    user_id = session["user_id"]

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            vault_id,
            title,
            secret_content,
            category,
            created_at,
            updated_at
        FROM vault_data
        WHERE user_id = %s
        ORDER BY updated_at DESC
        """,
        (user_id,)
    )

    rows = cursor.fetchall()

    cursor.close()
    conn.close()

    vault_items = []

    for row in rows:
        vault_items.append({
            "vault_id": row[0],
            "title": row[1],
            "secret_content": row[2],
            "category": row[3],
            "created_at": (
                row[4].isoformat()
                if row[4] else None
            ),
            "updated_at": (
                row[5].isoformat()
                if row[5] else None
            )
        })

    return jsonify(vault_items), 200


@app.route("/api/vault/save", methods=["POST"])
def save_vault():

    if "user_id" not in session:
        return jsonify({
            "error": "Not authenticated"
        }), 401

    data = request.get_json(silent=True) or {}

    title = (data.get("title") or "").strip()
    secret_content = (data.get("secret_content") or "").strip()
    category = (data.get("category") or "general").strip()

    if not title:
        return jsonify({
            "error": "Vault title is required."
        }), 400

    if not secret_content:
        return jsonify({
            "error": "Vault content is required."
        }), 400

    user_id = session["user_id"]

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO vault_data
        (
            user_id,
            title,
            secret_content,
            category
        )
        VALUES (%s, %s, %s, %s)
        """,
        (
            user_id,
            title,
            secret_content,
            category
        )
    )

    conn.commit()

    vault_id = cursor.lastrowid

    cursor.close()
    conn.close()

    return jsonify({
        "status": "ok",
        "vault_id": vault_id,
        "message": "Vault item saved successfully."
    }), 200


@app.route("/api/vault/delete/<int:vault_id>", methods=["POST"])
def delete_vault(vault_id):

    if "user_id" not in session:
        return jsonify({
            "error": "Not authenticated"
        }), 401

    user_id = session["user_id"]

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        DELETE FROM vault_data
        WHERE vault_id = %s
        AND user_id = %s
        """,
        (
            vault_id,
            user_id
        )
    )

    conn.commit()

    deleted = cursor.rowcount

    cursor.close()
    conn.close()

    if deleted == 0:
        return jsonify({
            "error": "Vault item not found."
        }), 404

    return jsonify({
        "status": "ok",
        "message": "Vault item deleted."
    }), 200

@app.route("/api/me", methods=["GET"])
def get_current_user():

    if "user_id" not in session:
        return jsonify({
            "error": "Not authenticated"
        }), 401

    user_id = session["user_id"]

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT user_id, username, email
        FROM users
        WHERE user_id = %s
        """,
        (user_id,)
    )

    row = cursor.fetchone()

    cursor.close()
    conn.close()

    if not row:
        return jsonify({
            "error": "User not found"
        }), 404

    return jsonify({
        "user_id": row[0],
        "username": row[1],
        "email": row[2]
    }), 200

# =========================================================
# KNOWLEDGE ANCHOR & DYNAMIC RECOVERY FALLBACK
# =========================================================

KNOWLEDGE_QUESTIONS = {
    1: "What was the first operating system you installed yourself?",
    2: "Which superhero's power do you consider completely useless?",
    3: "What specific pizza topping do you absolutely refuse to eat?",
    4: "What was the first command-line tool you ever memorized?",
    5: "What is the name of the first fictional weapon you wished you owned?",
    6: "Which video game boss took you the most tries to defeat?",
    7: "What specific beverage is your must-have for late-night studying?",
    8: "What was your absolute least favorite subject in middle school?",
    9: "Which anime or movie universe would you hate living in the most?",
    10: "What was the first computer program you remember being fascinated by?",
    11: "What is the one household chore you despise doing the most?",
    12: "What specific PC hardware part would you always upgrade first?",
    13: "What board game always caused arguments in your family?",
    14: "What was your favorite playground game in primary school?",
    15: "What was the first fictional world you remember imagining in detail?"
}

def normalize_knowledge_answer(answer):
    return " ".join(str(answer).strip().lower().split())

@app.route("/recovery/init", methods=["POST"])
def recovery_init():
    """Checks if the user has codes left. If 0, falls back to Knowledge Anchor."""
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()

    if not email:
        return jsonify({"error": "Email is required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT user_id, username FROM users WHERE email = %s", (email,))
    user_row = cursor.fetchone()

    if not user_row:
        cursor.close()
        conn.close()
        return jsonify({"error": "Account not found."}), 404

    user_id = user_row[0]

    # Count unused recovery codes
    cursor.execute("SELECT COUNT(*) FROM recovery_codes WHERE user_id = %s AND used = 0", (user_id,))
    codes_count = cursor.fetchone()[0]

    if codes_count > 0:
        cursor.close()
        conn.close()
        return jsonify({
            "method": "code", 
            "message": f"You have {codes_count} recovery codes remaining."
        }), 200

    # If 0 codes, fetch their Knowledge Anchor
    cursor.execute("SELECT question_id FROM knowledge_anchors WHERE user_id = %s", (user_id,))
    anchor_row = cursor.fetchone()
    
    cursor.close()
    conn.close()

    if not anchor_row:
        return jsonify({"error": "0 recovery codes remaining and no Security Question set. Account locked."}), 403

    question_id = anchor_row[0]
    question_text = KNOWLEDGE_QUESTIONS.get(question_id, "Unknown security question.")

    return jsonify({
        "method": "knowledge",
        "question": question_text
    }), 200


@app.route("/recovery/knowledge", methods=["POST"])
def recovery_knowledge():
    """Verifies the Knowledge Anchor answer and logs the user in."""
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    answer = data.get("answer", "")

    if not email or not answer:
        return jsonify({"error": "Email and answer are required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT user_id, username FROM users WHERE email = %s", (email,))
    user_row = cursor.fetchone()

    if not user_row:
        cursor.close()
        conn.close()
        return jsonify({"error": "Account not found."}), 404

    user_id, username = user_row[0], user_row[1]

    cursor.execute("SELECT answer_hash FROM knowledge_anchors WHERE user_id = %s", (user_id,))
    anchor_row = cursor.fetchone()

    if not anchor_row:
        cursor.close()
        conn.close()
        return jsonify({"error": "No knowledge anchor set."}), 400

    answer_hash = anchor_row[0]
    normalized_answer = normalize_knowledge_answer(answer)

    try:
        ph.verify(answer_hash, normalized_answer)
    except VerifyMismatchError:
        cursor.close()
        conn.close()
        return jsonify({"error": "Incorrect answer. Access denied."}), 401

    # SUCCESS -> Manually update last activity with direct SQL
    cursor.execute(
        "UPDATE users SET last_activity = CURRENT_TIMESTAMP WHERE user_id = %s",
        (user_id,)
    )
    conn.commit()
    
    cursor.close()
    conn.close()

    session.clear()
    session["user_id"] = user_id
    session["username"] = username

    return jsonify({"status": "ok", "message": "Identity verified via Knowledge Anchor."}), 200
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)