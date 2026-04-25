import os
import requests
import importlib.util
import chardet

from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, flash
from functools import wraps
from werkzeug.security import gen_salt
from werkzeug.utils import secure_filename

# NEW: to dynamically load role dashboards from Python files
from supabase_fake import sb

sb_admin = sb

API_URL = "https://api.somaedgex-cloud.online"

load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret")

# ----------------- App -----------------
app = Flask(__name__)
app.secret_key = SECRET_KEY

# ----------------- File Upload Config -----------------
UPLOAD_FOLDER = os.path.join("static", "task_files")
ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "png", "jpg", "jpeg"}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ----------------- Direct API helpers (replaces .table().eq().execute()) -----------------
def _hdrs():
    """Auth headers for every API call."""
    token = session.get("access_token", "")
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Prefer": "return=representation",
    }


def db_select(table, **filters):
    """SELECT * FROM table WHERE col=val ..."""
    params = {k: f"eq.{v}" for k, v in filters.items()}
    try:
        r = requests.get(f"{API_URL}/rest/v1/{table}", params=params, headers=_hdrs(), timeout=10)
        data = r.json()
        return data if isinstance(data, list) else []
    except Exception:
        return []


def db_select_one(table, **filters):
    """Return single row or None."""
    results = db_select(table, **filters)
    return results[0] if results else None


def db_insert(table, data):
    """INSERT INTO table returning first row."""
    try:
        r = requests.post(f"{API_URL}/rest/v1/{table}", json=data, headers=_hdrs(), timeout=10)
        result = r.json()
        return result[0] if isinstance(result, list) and result else result
    except Exception:
        return None


def db_update(table, data, **filters):
    """UPDATE table SET ... WHERE col=val."""
    params = {k: f"eq.{v}" for k, v in filters.items()}
    try:
        requests.patch(f"{API_URL}/rest/v1/{table}", json=data, params=params, headers=_hdrs(), timeout=10)
    except Exception:
        pass


def db_delete(table, **filters):
    """DELETE FROM table WHERE col=val."""
    params = {k: f"eq.{v}" for k, v in filters.items()}
    try:
        requests.delete(f"{API_URL}/rest/v1/{table}", params=params, headers=_hdrs(), timeout=10)
    except Exception:
        pass


def signup_user(email, password):
    """Create auth user via custom API. Returns (user_id, error_msg)."""
    try:
        r = requests.post(
            f"{API_URL}/auth/v1/signup",
            json={"email": email, "password": password, "email_confirm": True},
            timeout=10,
        )
        data = r.json()
        if "error" in data or r.status_code >= 400:
            msg = data.get("error_description") or data.get("error") or "Signup failed"
            return None, msg
        user_id = (data.get("user") or {}).get("id")
        if not user_id:
            return None, "No user ID returned"
        return user_id, None
    except Exception as e:
        return None, str(e)


def delete_auth_user(user_id):
    """Delete auth user via custom API (best-effort)."""
    try:
        requests.delete(
            f"{API_URL}/auth/v1/admin/users/{user_id}",
            headers=_hdrs(),
            timeout=10,
        )
    except Exception:
        pass


# ----------------- Helpers -----------------
def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if "access_token" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapped


def get_current_user():
    token = session.get("access_token")
    if not token:
        return None
    try:
        resp = sb.auth.get_user(token)
        return resp.user if resp and resp.user else None
    except Exception:
        return None


def get_profile():
    user = get_current_user()
    if not user:
        return None
    return db_select_one("profiles", id=user.id)


# ----------------- Routes -----------------
@app.route("/")
def index():
    prof = get_profile()
    if prof:
        role = prof.get("role")
        # Admin \u2192 admin dashboard
        if role == "company_admin":
            return redirect(url_for("admin_dashboard"))
        # If user has a role_id \u2192 go to that role dashboard (manager etc.)
        if prof.get("role_id"):
            return redirect(url_for("role_dashboard", role_id=prof["role_id"]))
        # Fallback \u2192 generic employee dashboard
        return redirect(url_for("employee_dashboard"))
    # Not
