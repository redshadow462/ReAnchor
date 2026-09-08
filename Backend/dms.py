import os
import secrets
import string
from datetime import datetime, timedelta
from functools import wraps

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import Blueprint, g, session, request, jsonify

from Connector import get_db_connection

# Flask Blueprint
dms_bp = Blueprint("dms", __name__)

# Password hasher
ph = PasswordHasher()


def touch_last_activity(user_id):
    """Updates last_activity to now when a user acts or authenticates."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE users
        SET last_activity = %s
        WHERE user_id = %s
        """,
        (datetime.now(), user_id)
    )
    conn.commit()
    cursor.close()
    conn.close()


def log_audit(user_id, actor_type, actor_id, action, details=None):
    """Appends an event to the audit trail."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO audit_log
                (user_id, actor_type, actor_id, action, details)
            VALUES
                (%s, %s, %s, %s, %s)
            """,
            (user_id, actor_type, actor_id, action, details)
        )
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"[Audit Log Error] {e}")


def generate_delegate_token():
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(32))


def check_dead_man_switches():
    """
    Evaluates Dead Man's Switch triggers.
    Runs periodically or on-demand.
    1. Checks if last_activity was longer ago than inactivity_days (default 30 days).
    2. Opens a contest/grace-period window (status = 'pending', confirm_at = now + grace_period).
    3. Promotes uncancelled pending triggers past confirm_at to 'confirmed'.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT s.user_id, s.inactivity_days, s.grace_period_days
        FROM dms_settings s
        WHERE s.enabled = 1
        """
    )
    configs = cursor.fetchall()

    for user_id, inactivity_days, grace_period_days in configs:
        cursor.execute(
            "SELECT last_activity FROM users WHERE user_id = %s",
            (user_id,)
        )
        row = cursor.fetchone()
        if not row or not row[0]:
            continue

        last_activity = row[0]
        if isinstance(last_activity, str):
            try:
                last_activity = datetime.strptime(last_activity[:19], "%Y-%m-%d %H:%M:%S")
            except Exception:
                continue

        now = datetime.now()
        if now - last_activity < timedelta(days=inactivity_days):
            continue

        # Check if already has an open pending or confirmed trigger
        cursor.execute(
            """
            SELECT trigger_id, status FROM dms_triggers
            WHERE user_id = %s AND status IN ('pending', 'confirmed')
            ORDER BY trigger_id DESC LIMIT 1
            """,
            (user_id,)
        )
        existing_trigger = cursor.fetchone()
        if existing_trigger:
            continue

        confirm_at = now + timedelta(days=grace_period_days)
        cursor.execute(
            """
            INSERT INTO dms_triggers (user_id, status, confirm_at)
            VALUES (%s, 'pending', %s)
            """,
            (user_id, confirm_at)
        )
        conn.commit()

        log_audit(user_id, "system", None, "trigger_started",
                  f"inactivity={inactivity_days}d, confirm_at={confirm_at.isoformat()}")

    # Promote uncancelled pending triggers whose grace period has elapsed
    cursor.execute(
        """
        UPDATE dms_triggers
        SET status = 'confirmed', resolved_at = CURRENT_TIMESTAMP
        WHERE status = 'pending' AND confirm_at <= CURRENT_TIMESTAMP
        """
    )
    conn.commit()

    cursor.close()
    conn.close()


# ---------------------------------------------------
# Status & Check-In Endpoints
# ---------------------------------------------------

@dms_bp.route("/dms/status", methods=["GET"])
def dms_status():
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    user_id = session["user_id"]
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch DMS settings (default 30 days inactivity)
    cursor.execute(
        """
        SELECT enabled, inactivity_days, grace_period_days
        FROM dms_settings
        WHERE user_id = %s
        """,
        (user_id,)
    )
    settings_row = cursor.fetchone()
    if not settings_row:
        # Default settings if none set yet
        enabled = True
        inactivity_days = 30
        grace_period_days = 3
    else:
        enabled = bool(settings_row[0])
        inactivity_days = int(settings_row[1])
        grace_period_days = int(settings_row[2])

    # Fetch last activity
    cursor.execute(
        "SELECT last_activity FROM users WHERE user_id = %s",
        (user_id,)
    )
    user_row = cursor.fetchone()
    last_activity = user_row[0] if user_row else datetime.now()
    if isinstance(last_activity, str):
        try:
            last_activity = datetime.strptime(last_activity[:19], "%Y-%m-%d %H:%M:%S")
        except Exception:
            last_activity = datetime.now()

    now = datetime.now()
    seconds_inactive = max(0, (now - last_activity).total_seconds())
    days_inactive = round(seconds_inactive / 86400, 2)
    days_remaining = max(0.0, round(inactivity_days - days_inactive, 2))

    # Fetch active/pending triggers
    cursor.execute(
        """
        SELECT trigger_id, status, confirm_at
        FROM dms_triggers
        WHERE user_id = %s AND status IN ('pending', 'confirmed')
        ORDER BY trigger_id DESC LIMIT 1
        """,
        (user_id,)
    )
    trigger_row = cursor.fetchone()
    trigger_status = trigger_row[1] if trigger_row else "idle"
    confirm_at = trigger_row[2].isoformat() if (trigger_row and trigger_row[2]) else None
    trigger_id = trigger_row[0] if trigger_row else None

    # Count delegates
    cursor.execute(
        "SELECT COUNT(*) FROM delegates WHERE owner_user_id = %s AND status != 'revoked'",
        (user_id,)
    )
    delegates_count = cursor.fetchone()[0]

    # Count vault items
    cursor.execute(
        "SELECT COUNT(*) FROM vault_data WHERE user_id = %s",
        (user_id,)
    )
    vault_items_count = cursor.fetchone()[0]

    cursor.close()
    conn.close()

    return jsonify({
        "enabled": enabled,
        "inactivity_days": inactivity_days,
        "grace_period_days": grace_period_days,
        "last_activity": last_activity.isoformat(),
        "days_inactive": days_inactive,
        "days_remaining": days_remaining,
        "trigger_status": trigger_status,
        "trigger_id": trigger_id,
        "confirm_at": confirm_at,
        "delegates_count": delegates_count,
        "vault_items_count": vault_items_count
    }), 200


@dms_bp.route("/dms/check-in", methods=["POST"])
def check_in():
    """Manual 'I am alive' check-in by the account owner."""
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    user_id = session["user_id"]
    touch_last_activity(user_id)
    log_audit(user_id, "owner", user_id, "check_in", "Manual check-in received")

    return jsonify({
        "status": "ok",
        "message": "Activity recorded. Dead Man's Switch timer reset."
    }), 200


@dms_bp.route("/dms/settings", methods=["POST"])
def dms_settings():
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    user_id = session["user_id"]
    data = request.form if request.form else request.get_json(silent=True) or {}

    enabled = str(data.get("enabled", "true")).lower() in ("true", "1", "yes")
    inactivity_days = int(data.get("inactivity_days", 30))
    grace_period_days = int(data.get("grace_period_days", 3))

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO dms_settings
            (user_id, enabled, inactivity_days, grace_period_days)
        VALUES
            (%s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            enabled = %s,
            inactivity_days = %s,
            grace_period_days = %s
        """,
        (
            user_id, enabled, inactivity_days, grace_period_days,
            enabled, inactivity_days, grace_period_days
        )
    )

    conn.commit()
    cursor.close()
    conn.close()

    log_audit(user_id, "owner", user_id, "dms_settings_updated",
              f"enabled={enabled}, inactivity_days={inactivity_days}, grace_period={grace_period_days}")

    return jsonify({"status": "ok"}), 200


# ---------------------------------------------------
# Delegate Management Endpoints
# ---------------------------------------------------

@dms_bp.route("/delegate/add", methods=["POST"])
def add_delegate():
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    owner_id = session["user_id"]
    data = request.form if request.form else request.get_json(silent=True) or {}

    password = data.get("password")
    delegate_identifier = (data.get("delegate_username") or data.get("delegate_email") or "").strip()
    scope = data.get("scope", "full_vault")

    if not password or not delegate_identifier:
        return jsonify({"error": "Password and delegate username or email are required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    # Re-verify owner's password
    cursor.execute(
        "SELECT password_hash FROM users WHERE user_id = %s",
        (owner_id,)
    )
    row = cursor.fetchone()
    if not row:
        cursor.close()
        conn.close()
        return jsonify({"error": "User not found"}), 404

    owner_hash = row[0]
    try:
        ph.verify(owner_hash, password)
    except VerifyMismatchError:
        cursor.close()
        conn.close()
        return jsonify({"error": "Password incorrect"}), 401

    # Look up delegate by username or email
    cursor.execute(
        "SELECT user_id, username FROM users WHERE username = %s OR email = %s",
        (delegate_identifier, delegate_identifier)
    )
    delegate_row = cursor.fetchone()

    if not delegate_row:
        cursor.close()
        conn.close()
        return jsonify({"error": f"No registered ReAnchor account found for '{delegate_identifier}'"}), 404

    delegate_user_id, delegate_username = delegate_row[0], delegate_row[1]

    if delegate_user_id == owner_id:
        cursor.close()
        conn.close()
        return jsonify({"error": "You cannot delegate to yourself"}), 400

    # Check for existing active or pending delegation
    cursor.execute(
        """
        SELECT delegate_id, status FROM delegates
        WHERE owner_user_id = %s AND delegate_user_id = %s AND status != 'revoked'
        """,
        (owner_id, delegate_user_id)
    )
    existing = cursor.fetchone()
    if existing:
        cursor.close()
        conn.close()
        return jsonify({"error": f"Delegation to '{delegate_username}' is already {existing[1]}"}), 400

    # Ensure DMS settings are enabled with default 30 days inactivity
    cursor.execute(
        """
        INSERT INTO dms_settings (user_id, enabled, inactivity_days, grace_period_days)
        VALUES (%s, 1, 30, 3)
        ON DUPLICATE KEY UPDATE enabled = 1
        """,
        (owner_id,)
    )

    cursor.execute(
        """
        INSERT INTO delegates
            (owner_user_id, delegate_user_id, scope, status)
        VALUES
            (%s, %s, %s, 'pending')
        """,
        (owner_id, delegate_user_id, scope)
    )

    conn.commit()
    delegate_id = cursor.lastrowid
    cursor.close()
    conn.close()

    log_audit(owner_id, "owner", owner_id, "delegate_added",
              f"delegate_id={delegate_id}, delegate_username={delegate_username}, scope={scope}")

    return jsonify({
        "status": "ok",
        "delegate_id": delegate_id,
        "delegate_username": delegate_username,
        "message": f"Delegate invitation sent to '{delegate_username}'. Awaiting their acceptance."
    }), 200


@dms_bp.route("/delegate/list", methods=["GET"])
def list_delegates():
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    user_id = session["user_id"]
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Outgoing: Delegates chosen by current user
    cursor.execute(
        """
        SELECT d.delegate_id, d.delegate_user_id, u.username, u.email, d.scope, d.status, d.created_at
        FROM delegates d
        JOIN users u ON u.user_id = d.delegate_user_id
        WHERE d.owner_user_id = %s AND d.status != 'revoked'
        ORDER BY d.created_at DESC
        """,
        (user_id,)
    )
    outgoing = [
        {
            "delegate_id": r[0],
            "delegate_user_id": r[1],
            "username": r[2],
            "email": r[3],
            "scope": r[4],
            "status": r[5],
            "created_at": r[6].isoformat() if hasattr(r[6], "isoformat") else str(r[6])
        }
        for r in cursor.fetchall()
    ]

    # 2. Incoming: Where current user is the chosen delegate
    cursor.execute(
        """
        SELECT d.delegate_id, d.owner_user_id, u.username, u.email, d.scope, d.status, d.created_at,
               (SELECT status FROM dms_triggers WHERE user_id = d.owner_user_id AND status IN ('pending', 'confirmed') ORDER BY trigger_id DESC LIMIT 1) as trigger_status
        FROM delegates d
        JOIN users u ON u.user_id = d.owner_user_id
        WHERE d.delegate_user_id = %s AND d.status != 'revoked'
        ORDER BY d.created_at DESC
        """,
        (user_id,)
    )
    incoming = [
        {
            "delegate_id": r[0],
            "owner_user_id": r[1],
            "owner_username": r[2],
            "owner_email": r[3],
            "scope": r[4],
            "status": r[5],
            "created_at": r[6].isoformat() if hasattr(r[6], "isoformat") else str(r[6]),
            "switch_status": r[7] if r[7] else "active"
        }
        for r in cursor.fetchall()
    ]

    cursor.close()
    conn.close()

    return jsonify({
        "outgoing": outgoing,
        "incoming": incoming
    }), 200


@dms_bp.route("/delegate/accept/<int:delegate_id>", methods=["POST"])
def accept_delegate(delegate_id):
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    delegate_user_id = session["user_id"]
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE delegates
        SET status = 'active'
        WHERE delegate_id = %s AND delegate_user_id = %s AND status = 'pending'
        """,
        (delegate_id, delegate_user_id)
    )

    conn.commit()
    updated = cursor.rowcount
    cursor.close()
    conn.close()

    if not updated:
        return jsonify({"error": "No pending invite found"}), 404

    log_audit(delegate_user_id, "delegate", delegate_user_id, "delegate_accepted", f"delegate_id={delegate_id}")
    return jsonify({"status": "ok", "message": "Delegation accepted successfully"}), 200


@dms_bp.route("/delegate/reject/<int:delegate_id>", methods=["POST"])
def reject_delegate(delegate_id):
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    delegate_user_id = session["user_id"]
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE delegates
        SET status = 'revoked'
        WHERE delegate_id = %s AND delegate_user_id = %s AND status = 'pending'
        """,
        (delegate_id, delegate_user_id)
    )

    conn.commit()
    updated = cursor.rowcount
    cursor.close()
    conn.close()

    if not updated:
        return jsonify({"error": "No pending invite found"}), 404

    return jsonify({"status": "ok", "message": "Delegation rejected"}), 200


@dms_bp.route("/delegate/revoke/<int:delegate_id>", methods=["POST"])
def revoke_delegate(delegate_id):
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    owner_id = session["user_id"]
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE delegates
        SET status = 'revoked'
        WHERE delegate_id = %s AND owner_user_id = %s
        """,
        (delegate_id, owner_id)
    )

    cursor.execute(
        """
        UPDATE delegate_access_tokens
        SET revoked = 1
        WHERE delegate_id = %s
        """,
        (delegate_id,)
    )

    conn.commit()
    cursor.close()
    conn.close()

    log_audit(owner_id, "owner", owner_id, "delegate_revoked", f"delegate_id={delegate_id}")
    return jsonify({"status": "ok"}), 200


# ---------------------------------------------------
# Trigger Cancellation (Owner Proves Life via TOTP)
# ---------------------------------------------------

@dms_bp.route("/dms/cancel-trigger", methods=["POST"])
def cancel_trigger():
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    user_id = session["user_id"]
    data = request.form if request.form else request.get_json(silent=True) or {}
    otp = data.get("otp", "").strip()

    if not otp:
        return jsonify({"error": "Verification code required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT secret FROM totp_credentials WHERE user_id = %s AND enabled = 1",
        (user_id,)
    )
    row = cursor.fetchone()

    if not row:
        # Fallback to password check if TOTP not enabled
        cursor.execute("SELECT password_hash FROM users WHERE user_id = %s", (user_id,))
        prow = cursor.fetchone()
        try:
            ph.verify(prow[0], otp)
        except Exception:
            cursor.close()
            conn.close()
            return jsonify({"error": "2FA verification code or password invalid"}), 401
    else:
        totp = pyotp.TOTP(row[0])
        if not totp.verify(otp, valid_window=1):
            cursor.close()
            conn.close()
            return jsonify({"error": "Invalid verification code"}), 401

    cursor.execute(
        """
        UPDATE dms_triggers
        SET status = 'cancelled', resolved_at = CURRENT_TIMESTAMP
        WHERE user_id = %s AND status = 'pending'
        """,
        (user_id,)
    )
    conn.commit()
    cancelled = cursor.rowcount

    # Also update last activity
    cursor.execute(
        "UPDATE users SET last_activity = CURRENT_TIMESTAMP WHERE user_id = %s",
        (user_id,)
    )
    conn.commit()
    cursor.close()
    conn.close()

    if cancelled:
        log_audit(user_id, "owner", user_id, "trigger_cancelled", "Trigger cancelled with 2FA verification")

    return jsonify({
        "status": "ok",
        "cancelled": bool(cancelled),
        "message": "Dead Man's Switch trigger cancelled. Timer reset to 30 days."
    }), 200


# ---------------------------------------------------
# Transferred Data Retrieval for Delegate
# ---------------------------------------------------

@dms_bp.route("/delegate/transferred-data/<int:delegate_id>", methods=["GET"])
def get_transferred_data(delegate_id):
    """
    Called by the authorized delegate when a Dead Man's Switch
    has reached 'confirmed' status to access the owner's transferred data.
    """
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    delegate_user_id = session["user_id"]
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT owner_user_id, scope, status
        FROM delegates
        WHERE delegate_id = %s AND delegate_user_id = %s
        """,
        (delegate_id, delegate_user_id)
    )
    del_row = cursor.fetchone()

    if not del_row or del_row[2] != "active":
        cursor.close()
        conn.close()
        return jsonify({"error": "No active delegation found"}), 403

    owner_id, scope, _ = del_row

    # Verify that the switch is actually confirmed
    cursor.execute(
        """
        SELECT trigger_id, confirm_at, resolved_at
        FROM dms_triggers
        WHERE user_id = %s AND status = 'confirmed'
        ORDER BY trigger_id DESC LIMIT 1
        """,
        (owner_id,)
    )
    trigger_row = cursor.fetchone()

    if not trigger_row:
        cursor.close()
        conn.close()
        return jsonify({
            "error": "Access denied: Dead Man's Switch has not been confirmed for this account."
        }), 403

    trigger_id = trigger_row[0]

    # Fetch transferred vault data for this owner
    cursor.execute(
        """
        SELECT vault_id, title, secret_content, category, updated_at
        FROM vault_data
        WHERE user_id = %s
        ORDER BY updated_at DESC
        """,
        (owner_id,)
    )
    vault_items = [
        {
            "vault_id": r[0],
            "title": r[1],
            "secret_content": r[2],
            "category": r[3],
            "updated_at": r[4].isoformat() if hasattr(r[4], "isoformat") else str(r[4])
        }
        for r in cursor.fetchall()
    ]

    # Look up owner's username
    cursor.execute("SELECT username, email FROM users WHERE user_id = %s", (owner_id,))
    owner_info = cursor.fetchone()
    owner_username = owner_info[0] if owner_info else "Owner"

    cursor.close()
    conn.close()

    log_audit(owner_id, "delegate", delegate_user_id, "data_transferred_accessed",
              f"delegate_id={delegate_id}, trigger_id={trigger_id}")

    return jsonify({
        "status": "ok",
        "owner_username": owner_username,
        "scope": scope,
        "trigger_id": trigger_id,
        "items": vault_items
    }), 200


# ---------------------------------------------------
# Token-Based Scoped Access Decorator
# ---------------------------------------------------

def require_delegate_token(required_scope):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return jsonify({"error": "Missing delegate token"}), 401

            raw_token = auth_header.split(" ", 1)[1]
            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT dat.token_id, dat.token_hash, dat.scope,
                       dat.expires_at, dat.revoked, d.owner_user_id
                FROM delegate_access_tokens dat
                JOIN delegates d ON d.delegate_id = dat.delegate_id
                WHERE dat.revoked = 0 AND dat.expires_at > CURRENT_TIMESTAMP
                """
            )
            candidates = cursor.fetchall()
            cursor.close()
            conn.close()

            for token_id, token_hash, scope, expires_at, revoked, owner_user_id in candidates:
                try:
                    ph.verify(token_hash, raw_token)
                except VerifyMismatchError:
                    continue

                if required_scope not in scope.split(","):
                    return jsonify({"error": "Token lacks required scope"}), 403

                g.delegate_owner_id = owner_user_id
                g.delegate_scope = scope
                return f(*args, **kwargs)

            return jsonify({"error": "Invalid or expired delegate token"}), 401
        return wrapper
    return decorator


# ---------------------------------------------------
# Audit Log Endpoint
# ---------------------------------------------------

@dms_bp.route("/audit-log", methods=["GET"])
def audit_log():
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    user_id = session["user_id"]
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT actor_type, actor_id, action, details, created_at
        FROM audit_log
        WHERE user_id = %s
        ORDER BY created_at DESC
        LIMIT 50
        """,
        (user_id,)
    )
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    return jsonify([
        {
            "actor_type": r[0],
            "actor_id": r[1],
            "action": r[2],
            "details": r[3],
            "created_at": r[4].isoformat() if hasattr(r[4], "isoformat") else str(r[4])
        }
        for r in rows
    ]), 200


# ---------------------------------------------------
# Hackathon Demo / Simulation Tools
# ---------------------------------------------------

@dms_bp.route("/dms/simulate-inactive", methods=["POST"])
def simulate_inactive():
    """
    Demo Tool: Sets last_activity to 31 days in the past
    so the 30-day inactivity threshold is instantly exceeded.
    """
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    user_id = session["user_id"]
    simulated_date = datetime.now() - timedelta(days=31)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET last_activity = %s WHERE user_id = %s",
        (simulated_date, user_id)
    )
    conn.commit()
    cursor.close()
    conn.close()

    # Trigger switch evaluation immediately
    check_dead_man_switches()

    log_audit(user_id, "system", None, "demo_simulate_inactive", "Set last_activity to 31 days ago")

    return jsonify({
        "status": "ok",
        "message": "Inactivity period simulated (31 days ago). Switch contest window is now active!"
    }), 200


@dms_bp.route("/dms/simulate-confirm", methods=["POST"])
def simulate_confirm():
    """
    Demo Tool: Instantly promotes a pending switch trigger
    to 'confirmed' so the delegate can test accessing transferred data.
    """
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401

    user_id = session["user_id"]
    conn = get_db_connection()
    cursor = conn.cursor()

    # Ensure a trigger exists
    cursor.execute(
        """
        SELECT trigger_id FROM dms_triggers
        WHERE user_id = %s AND status IN ('pending', 'confirmed')
        ORDER BY trigger_id DESC LIMIT 1
        """,
        (user_id,)
    )
    row = cursor.fetchone()

    if not row:
        cursor.execute(
            """
            INSERT INTO dms_triggers (user_id, status, confirm_at, resolved_at)
            VALUES (%s, 'confirmed', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """,
            (user_id,)
        )
    else:
        cursor.execute(
            """
            UPDATE dms_triggers
            SET status = 'confirmed', resolved_at = CURRENT_TIMESTAMP
            WHERE trigger_id = %s
            """,
            (row[0],)
        )

    conn.commit()
    cursor.close()
    conn.close()

    log_audit(user_id, "system", None, "demo_simulate_confirm", "Dead Man's Switch confirmed via demo control")

    return jsonify({
        "status": "ok",
        "message": "Dead Man's Switch CONFIRMED! Transferred data is now unlocked for your delegate."
    }), 200
