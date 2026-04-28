import os
import importlib.util

import json
import sqlite3

import chardet
import requests
from dotenv import load_dotenv
from flask import (Flask, flash, redirect, render_template, request, session, url_for)
from functools import wraps
from werkzeug.security import gen_salt
from werkzeug.utils import secure_filename

# ─────────────────────────────────────────────
# 0. Environment + App Init
# ─────────────────────────────────────────────
load_dotenv()

API_URL    = "https://api.somaedgex-cloud.online"
SECRET_KEY = os.getenv("SECRET_KEY", "jaishreeram")

# ✅ FIX #6 — ALLOWED_ROLES used everywhere instead of hardcoded strings
ALLOWED_ROLES = ["company_admin", "manager"]

app = Flask(__name__)
app.secret_key = SECRET_KEY

app.config.update(
    SESSION_COOKIE_SECURE   = True,
    SESSION_COOKIE_HTTPONLY = True,
    SESSION_COOKIE_SAMESITE = "None",
)


print("DB PATH:", os.path.abspath("database.db"))
# ─────────────────────────────────────────────
# 1. File Upload
# ─────────────────────────────────────────────
UPLOAD_FOLDER      = os.path.join("static", "task_files")
ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "png", "jpg", "jpeg"}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ─────────────────────────────────────────────
# 2. Database Init  (SQLite – local tables only)
# ─────────────────────────────────────────────
DB_PATH = "dashboard.db"
db = sqlite3.connect(DB_PATH, check_same_thread=False)
db.row_factory = sqlite3.Row

db.execute("""
    CREATE TABLE IF NOT EXISTS dashboard_templates (
        id      INTEGER PRIMARY KEY AUTOINCREMENT,
        role_id TEXT UNIQUE,
        layout  TEXT
    )
""")

db.execute("""
    CREATE TABLE IF NOT EXISTS role_dashboards (
        id      INTEGER PRIMARY KEY AUTOINCREMENT,
        role_id TEXT UNIQUE,
        html    TEXT
    )
""")

db.commit()


# ─────────────────────────────────────────────
# 2b. API helpers  (no Supabase, ever)
# ─────────────────────────────────────────────

def _auth_headers() -> dict:
    """Build Authorization header from session token."""
    token = session.get("access_token", "")
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
    }


def _safe_json(resp) -> dict:
    """Parse JSON safely; return {} on failure."""
    try:
        return resp.json()
    except Exception:
        return {}


def api_get(path: str, params: dict = None):
    """GET -> parsed JSON, or None on any failure."""
    try:
        resp = requests.get(
            f"{API_URL}{path}",
            headers=_auth_headers(),
            params=params,
            timeout=10,
        )
        print(f"[api_get] {path} params={params} -> {resp.status_code}")  # ✅ FIX #7 — log params too
        if resp.status_code in (200, 201):
            return _safe_json(resp)
    except Exception as exc:
        print(f"[api_get] ERROR {path}: {exc}")
    return None


def api_post(path: str, body: dict = None):
    """POST -> (status_code, json_data)."""
    try:
        print(f"[api_post] {path} body={body}")  # ✅ FIX #7 — log request body
        resp = requests.post(
            f"{API_URL}{path}",
            json=body or {},
            headers=_auth_headers(),
            timeout=10,
        )
        print(f"[api_post] {path} -> {resp.status_code} | response={_safe_json(resp)}")  # ✅ FIX #7
        return resp.status_code, _safe_json(resp)
    except Exception as exc:
        print(f"[api_post] ERROR {path}: {exc}")
        return 0, {"error": str(exc)}


def api_put(path: str, body: dict = None):
    """PUT -> (status_code, json_data)."""
    try:
        print(f"[api_put] {path} body={body}")  # ✅ FIX #7
        resp = requests.put(
            f"{API_URL}{path}",
            json=body or {},
            headers=_auth_headers(),
            timeout=10,
        )
        print(f"[api_put] {path} -> {resp.status_code} | response={_safe_json(resp)}")
        return resp.status_code, _safe_json(resp)
    except Exception as exc:
        print(f"[api_put] ERROR {path}: {exc}")
        return 0, {"error": str(exc)}


def api_delete(path: str):
    """DELETE -> (status_code, json_data)."""
    try:
        resp = requests.delete(
            f"{API_URL}{path}",
            headers=_auth_headers(),
            timeout=10,
        )
        print(f"[api_delete] {path} -> {resp.status_code}")
        return resp.status_code, _safe_json(resp)
    except Exception as exc:
        print(f"[api_delete] ERROR {path}: {exc}")
        return 0, {"error": str(exc)}


def _unwrap(raw) -> list:
    """Normalise API list responses regardless of envelope wrapping."""
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        for key in ("data", "profiles", "tasks", "roles", "results"):
            val = raw.get(key)
            if isinstance(val, list):
                return val
    return []


# ─────────────────────────────────────────────
# 3. Auth helpers
# ─────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if "access_token" not in session:
            print("[login_required] no token in session -> redirect login")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapped


def get_current_user():
    token = session.get("access_token")
    if not token:
        return None
    return {"id": token}


def get_profile():
    token = session.get("access_token")
    if not token:
        return None
    try:
        res  = requests.get(f"{API_URL}/debug/profile/{token}", timeout=10)
        data = res.json()
        print(f"[get_profile] token={token} -> status={res.status_code} data={data}")  # ✅ FIX #7
        prof = data.get("profile")
        if prof:
            print(f"[get_profile] role={prof.get('role')} company_id={prof.get('company_id')}")  # ✅ FIX #7
        return prof
    except Exception as e:
        print(f"[get_profile] ERROR: {e}")
        return None


# ─────────────────────────────────────────────
# 3b. Role Dashboard HTML helper
# ─────────────────────────────────────────────

def get_role_dashboard(role, company_id):
    res = api_get("/role-dashboard", params={
        "role": role,
        "company_id": company_id
    })

    data = _unwrap(res)
    return data.get("html") if data else None
# ─────────────────────────────────────────────
# 4. Routes
# ─────────────────────────────────────────────

@app.route("/")
def index():
    print(f"[index] session={dict(session)}")
    if "access_token" not in session:
        return render_template("index.html")

    prof = get_profile()
    print(f"[index] profile={prof}")

    if not prof:
        return redirect(url_for("admin_dashboard"))

    role = prof.get("role", "")
    print(f"[index] role={role}")  # ✅ FIX #7

    # ✅ FIX #1 — redirect both company_admin AND manager to admin dashboard
    if role in ALLOWED_ROLES:
        return redirect(url_for("admin_dashboard"))
    if prof.get("role_id"):
        return redirect(url_for("role_dashboard", role_id=prof["role_id"]))
    return redirect(url_for("employee_dashboard"))


@app.route("/debug/db")
def debug_db():
    rows = db.execute("SELECT * FROM role_dashboards").fetchall()
    return {"data": [dict(r) for r in rows]}
    
# ─── Register ───

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        company_name = request.form.get("company_name", "").strip()
        admin_name   = request.form.get("admin_name",   "").strip()
        email        = request.form.get("email",        "").strip()
        password     = request.form.get("password",     "")

        if not (company_name and admin_name and email and password):
            flash("All fields are required.", "danger")
            return redirect(url_for("register"))

        status, data = api_post("/auth/v1/signup", {
            "email":        email,
            "password":     password,
            "company_name": company_name,
            "admin_name":   admin_name,
        })

        print(f"[register] signup status={status} data={data}")

        if status in (200, 201):
            flash("Registered successfully. Please log in.", "success")
            return redirect(url_for("login"))

        error_msg = (
            data.get("message")
            or data.get("error_description")
            or data.get("error")
            or "Registration failed. Please try again."
        )
        if "already" in str(error_msg).lower() or "exists" in str(error_msg).lower():
            flash("An account with this email already exists. Please log in.", "warning")
            return redirect(url_for("login"))

        flash(f"Sign up error: {error_msg}", "danger")
        return redirect(url_for("register"))

    return render_template("register.html")


# ─── Login ───

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email    = request.form.get("email")
        password = request.form.get("password")

        if not email or not password:
            flash("Email and password required", "danger")
            return redirect(url_for("login"))

        try:
            res  = requests.post(
                f"{API_URL}/auth/v1/token",
                json={"email": email, "password": password},
                timeout=10,
            )
            data = res.json()
            print(f"[login] status={res.status_code} response={data}")  # ✅ FIX #7
        except Exception as e:
            flash("API error: " + str(e), "danger")
            return redirect(url_for("login"))

        if "error" in data:
            flash(data["error"], "danger")
            return redirect(url_for("login"))

        token = data.get("access_token")
        if not token:
            flash("Login failed (no token)", "danger")
            return redirect(url_for("login"))

        session.clear()
        session["access_token"] = token
        print(f"[login] token saved to session")  # ✅ FIX #7

        return redirect("/admin")

    return render_template("login.html")


# ─── Logout ───

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ─────────────────────────────────────────────
# 5. Admin Dashboard
# ─────────────────────────────────────────────

@app.route("/admin")
@login_required
def admin_dashboard():
    print(f"[admin_dashboard] session={dict(session)}")

    prof = get_profile()
    print(f"[admin_dashboard] profile={prof}")

    if not prof:
        return f"""
        ❌ PROFILE NOT FOUND<br>
        Session: {dict(session)}<br>
        👉 Try: /debug/profile/{session.get('access_token')}
        """, 500

    role = prof.get("role", "unknown")
    print(f"[admin_dashboard] role={role}")  # ✅ FIX #7

    # ✅ FIX #1 — warn but do NOT block — allow both roles to see dashboard
    if role not in ALLOWED_ROLES:
        print(f"⚠️ WARNING: role '{role}' is not in ALLOWED_ROLES — showing dashboard anyway")

    company_id = prof.get("company_id")
    print(f"[admin_dashboard] company_id={company_id}")  # ✅ FIX #7

    # ✅ FIX #5 — Fetch REAL data (no dummy data)
    # Try /profiles first; fallback to /employees if empty or broken
    try:
        users = _unwrap(api_get("/profiles", params={"company_id": company_id})) or []
        print(f"[admin_dashboard] users from /profiles: {len(users)}")
        if not users:
            print(f"[admin_dashboard] /profiles returned empty — falling back to /employees")
            users = _unwrap(api_get("/employees", params={"company_id": company_id})) or []
            print(f"[admin_dashboard] users from /employees fallback: {len(users)}")
    except Exception as e:
        print(f"[admin_dashboard] USERS ERROR: {e}")
        users = []

    try:
        tasks = _unwrap(api_get("/tasks", params={"company_id": company_id}))
        print(f"[admin_dashboard] tasks fetched: {len(tasks)}")
    except Exception as e:
        print(f"[admin_dashboard] TASKS ERROR: {e}")
        tasks = []

    try:
        roles = _unwrap(api_get("/roles", params={"company_id": company_id}))
        print(f"[admin_dashboard] roles fetched: {len(roles)}")
    except Exception as e:
        print(f"[admin_dashboard] ROLES ERROR: {e}")
        roles = []

    # ✅ FIX #3 — pass employees (role=employee) separately for task assignment dropdown
    employees = [u for u in users if u.get("role") == "employee"]

    return render_template(
        "admin_dashboard.html",
        profile=prof,
        users=users,
        tasks=tasks,
        roles=roles,
        employees=employees,           # ✅ FIX #3 — for task assignment dropdown
        allowed_roles=ALLOWED_ROLES,   # ✅ FIX #6 — pass to template for conditional UI
    )


# ─────────────────────────────────────────────
# 6. Role Dashboard
# ─────────────────────────────────────────────

@app.route("/role/<role_id>")
@login_required
def role_dashboard(role_id):
    prof = get_profile()
    if not prof:
        return redirect(url_for("login"))

    role = prof.get("role", "")
    print(f"[role_dashboard] role={role} role_id={role_id}")  # ✅ FIX #7

    # ✅ FIX #1 — both admin and manager redirect to admin dashboard
    if role in ALLOWED_ROLES:
        return redirect(url_for("admin_dashboard"))

    if str(prof.get("role_id", "")) != str(role_id):
        if prof.get("role_id"):
            return redirect(url_for("role_dashboard", role_id=prof["role_id"]))
        return redirect(url_for("employee_dashboard"))

    company_id = prof.get("company_id") or ""
    users = _unwrap(api_get("/profiles", params={"company_id": company_id}))
    tasks = _unwrap(api_get("/tasks",    params={"company_id": company_id}))
    roles = _unwrap(api_get("/roles",    params={"company_id": company_id}))

    # ✅ FIX #3 — employees for task assignment dropdown
    employees = [u for u in users if u.get("role") == "employee"]

    # Load optional Python dashboard renderer
    html     = None
    role_dir = os.path.join("dashboard_codes", str(role_id))
    if os.path.isdir(role_dir):
        py_files = [f for f in os.listdir(role_dir) if f.endswith(".py")]
        if py_files:
            module_path = os.path.join(role_dir, py_files[0])
            try:
                spec = importlib.util.spec_from_file_location(f"dashboard_{role_id}", module_path)
                mod  = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                if hasattr(mod, "render_dashboard"):
                    html = mod.render_dashboard(prof, users, tasks, roles)
            except Exception as exc:
                flash(f"Dashboard render error: {exc}", "danger")

    if html is None:
        uid        = str(prof.get("id", ""))
        user_tasks = [t for t in tasks if str(t.get("assigned_to", "")) == uid]
        total      = len(user_tasks)
        completed  = sum(1 for t in user_tasks if (t.get("status") or "").lower() == "completed")
        percent    = int((completed / total) * 100) if total else 0
        return render_template(
            "employee_dashboard.html",
            profile=prof,
            tasks=user_tasks,
            percent=percent,
            employees=employees,
            allowed_roles=ALLOWED_ROLES,
        )

    return html


# ─────────────────────────────────────────────
# 7. Edit Dashboard (Admin + Manager)
# ─────────────────────────────────────────────
@app.route("/admin/edit_dashboard/<role_id>", methods=["GET", "POST"])
@login_required
def edit_dashboard(role_id):
    prof = get_profile()
    user_role = (prof or {}).get("role", "")

    if not prof or user_role not in ALLOWED_ROLES:
        return "Unauthorized", 403

    # Get role info
    role_data = api_get(f"/roles/{role_id}")
    role_obj = role_data if isinstance(role_data, dict) else {
        "id": role_id,
        "name": f"Role {role_id}"
    }

    role_name = role_obj.get("name")
    company_id = prof.get("company_id")

    # 🔥 LOAD from API (NOT SQLite)
    res = api_get("/role-dashboard", params={
        "role": role_name,
        "company_id": company_id
    })

    data = _unwrap(res)
    html_code = data.get("html") if data else ""

    print("[LOAD API]", role_name, company_id, "len:", len(html_code))

    # 🔥 SAVE to API
    if request.method == "POST":
        html_code = request.form.get("html_code", "").strip()

        print("[SAVE API]", role_name, company_id, "len:", len(html_code))

        api_post("/role-dashboard", body={
            "role": role_name,
            "company_id": company_id,
            "html": html_code
        })

        flash("Dashboard saved!", "success")
        return redirect(url_for("edit_dashboard", role_id=role_id))

    return render_template(
        "edit_dashboard.html",
        role=role_obj,
        html_code=html_code
    )
# ─────────────────────────────────────────────
# 8. Create Role (Admin + Manager)
# ─────────────────────────────────────────────

@app.route("/admin/create_role", methods=["POST"])
@login_required
def create_role():
    prof = get_profile()
    role = (prof or {}).get("role", "")
    print(f"[create_role] role={role}")  # ✅ FIX #7

    # ✅ FIX #1
    if not prof or role not in ALLOWED_ROLES:
        return "Unauthorized", 403

    role_name = request.form.get("role_name", "").strip()
    if not role_name:
        flash("Role name is required.", "danger")
        return redirect(url_for("admin_dashboard"))

    status, data = api_post("/roles", {
        "company_id": prof.get("company_id"),
        "name":       role_name,
    })

    if status in (200, 201):
        flash(f"Role '{role_name}' created.", "success")
    else:
        error = data.get("message") or data.get("error") or "Role creation failed."
        flash(f"{error}", "danger")

    return redirect(url_for("admin_dashboard"))


# ─────────────────────────────────────────────
# 9. Create Employee (Admin + Manager)
# ─────────────────────────────────────────────

@app.route("/admin/create_employee", methods=["POST"])
@login_required
def create_employee():
    prof = get_profile()
    role = (prof or {}).get("role", "")
    print(f"[create_employee] role={role}")  # ✅ FIX #7

    # ✅ FIX #1
    if not prof or role not in ALLOWED_ROLES:
        return "Unauthorized", 403

    # ✅ FIX #2 — correct field names: name → full_name, role_id → role
    name       = request.form.get("name",     "").strip()   # form field "name"
    email      = request.form.get("email",    "").strip()
    password   = request.form.get("password") or gen_salt(8)
    role_id    = request.form.get("role_id")                # form field "role_id"
    company_id = prof.get("company_id")

    print(f"[create_employee] name={name} email={email} role_id={role_id} company_id={company_id}")  # ✅ FIX #7

    if not (name and email and role_id):
        flash("All fields are required.", "danger")
        return redirect(url_for("admin_dashboard"))

    # ✅ FIX #2 — send correct fields: full_name, email, password, role, company_id
    status, data = api_post("/employees", {
        "full_name":  name,
        "email":      email,
        "password":   password,
        "role":       role_id,
        "company_id": company_id,
    })

    print(f"[create_employee] api response status={status} data={data}")  # ✅ FIX #7

    if status not in (200, 201):
        error = data.get("message") or data.get("error") or "Create failed."
        flash(f"Employee creation failed: {error}", "danger")
        return redirect(url_for("admin_dashboard"))

    flash(f"Employee created. Password: {password}", "success")
    return redirect(url_for("admin_dashboard"))


# ─────────────────────────────────────────────
# 10. Delete Employee (Admin + Manager)
# ─────────────────────────────────────────────

@app.route("/admin/delete_employee/<user_id>", methods=["POST"])
@login_required
def delete_employee(user_id):
    prof = get_profile()
    role = (prof or {}).get("role", "")
    print(f"[delete_employee] role={role} user_id={user_id}")  # ✅ FIX #7

    # ✅ FIX #1
    if not prof or role not in ALLOWED_ROLES:
        return "Unauthorized", 403

    status, data = api_delete(f"/employees/{user_id}")

    if status not in (200, 204):
        flash(data.get("error", "Delete failed"), "danger")
    else:
        flash("Employee deleted", "success")

    return redirect(url_for("admin_dashboard"))


# ─────────────────────────────────────────────
# 11. Create Task (Admin + Manager)
# ─────────────────────────────────────────────

@app.route("/admin/create_task", methods=["POST"])
@login_required
def create_task():
    prof = get_profile()
    role = (prof or {}).get("role", "")
    print(f"[create_task] role={role}")  # ✅ FIX #7

    # ✅ FIX #1
    if not prof or role not in ALLOWED_ROLES:
        return "Unauthorized", 403

    title       = request.form.get("title",       "").strip()
    description = request.form.get("description", "")
    # ✅ FIX #3 — assigned_to must come from employee dropdown
    assigned_to = request.form.get("assigned_to") or None
    priority    = request.form.get("priority")    or "Medium"
    deadline    = request.form.get("deadline")    or None

    print(f"[create_task] title={title} assigned_to={assigned_to} priority={priority}")  # ✅ FIX #7

    file_url  = None
    task_file = request.files.get("task_file")
    if task_file and task_file.filename:
        fname     = f"{gen_salt(6)}_{secure_filename(task_file.filename)}"
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], fname)
        task_file.save(file_path)
        file_url = f"/static/task_files/{fname}"

    # ✅ FIX #4 — always save company_id, assigned_to, status
    status, data = api_post("/tasks", {
        "title":       title,
        "description": description,
        "company_id":  prof.get("company_id"),
        "assigned_to": assigned_to,
        "priority":    priority,
        "deadline":    deadline,
        "status":      "Pending",
        "file_url":    file_url,
    })

    print(f"[create_task] api response status={status} data={data}")  # ✅ FIX #7

    if status in (200, 201):
        flash("Task created.", "success")
    else:
        error = data.get("message") or data.get("error") or "Task creation failed."
        flash(f"{error}", "danger")

    return redirect(url_for("admin_dashboard"))


# ─────────────────────────────────────────────
# 12. Delete Task (Admin + Manager)
# ─────────────────────────────────────────────

@app.route("/admin/delete_task/<task_id>", methods=["POST"])
def admin_delete_task(task_id):
    api_delete(f"/tasks/{task_id}")
    return redirect(url_for("admin_dashboard"))


# ─────────────────────────────────────────────
# 13. Reports  (Admin + Manager)
# ─────────────────────────────────────────────

@app.route("/admin/reports")
@login_required
def reports_page():
    prof = get_profile()
    role = (prof or {}).get("role", "")
    print(f"[reports_page] role={role}")  # ✅ FIX #7

    # ✅ FIX #1
    if not prof or role not in ALLOWED_ROLES:
        return "Unauthorized", 403

    company_id = prof.get("company_id") or ""
    tasks      = _unwrap(api_get("/tasks", params={"company_id": company_id}))

    total     = len(tasks)
    completed = sum(1 for t in tasks if (t.get("status") or "").lower() == "completed")
    pending   = total - completed

    tasks_per_employee: dict = {}
    for t in tasks:
        assigned = str(t.get("assigned_to") or "Unassigned")
        tasks_per_employee[assigned] = tasks_per_employee.get(assigned, 0) + 1
    
    return render_template(
        "reports.html",
        total=total,
        completed=completed,
        pending=pending,
        tasks_per_employee=tasks_per_employee,
    )


# ─────────────────────────────────────────────
# 14. Employee Dashboard
# ─────────────────────────────────────────────

@app.route("/employee")
@login_required
def employee_dashboard():
    prof = get_profile()
    if not prof:
        return redirect(url_for("login"))

    user_id = prof.get("id")
    company_id = prof.get("company_id")
    role = prof.get("role")

    print(f"[employee_dashboard] user_id={user_id}, role={role}, company_id={company_id}")

    # ✅ Fetch tasks
    tasks = _unwrap(api_get("/tasks", params={"assigned_to": user_id})) or []

    total = len(tasks)
    completed = sum(1 for t in tasks if (t.get("status") or "").lower() == "completed")
    percent = int((completed / total) * 100) if total else 0

    # 🔥 LOAD DASHBOARD FROM API (robust)
    dashboard_html = None
    try:
        res = api_get("/role-dashboard", params={
            "role": role,
            "company_id": company_id
        })

        print("[API RESPONSE]", res)

        data = _unwrap(res) if res else None

        if isinstance(data, dict):
            dashboard_html = data.get("html")

    except Exception as e:
        print("[DASHBOARD LOAD ERROR]", e)

    print("[FINAL HTML]", dashboard_html[:80] if dashboard_html else "None")

    return render_template(
        "employee_dashboard_multi.html",
        profile=prof,
        tasks=tasks,
        percent=percent,
        allowed_roles=ALLOWED_ROLES,
        dashboard_html=dashboard_html or "",
    )

# ─────────────────────────────────────────────
# 15. Manager Routes (Admin + Manager)
# ─────────────────────────────────────────────

@app.route("/manager/create_task", methods=["POST"])
@login_required
def manager_create_task():
    prof = get_profile()
    role = (prof or {}).get("role", "")
    print(f"[manager_create_task] role={role}")  # ✅ FIX #7

    # ✅ FIX #1 — allow both company_admin and manager
    if not prof or role not in ALLOWED_ROLES:
        return "Unauthorized", 403

    title       = request.form.get("title", "").strip()
    description = request.form.get("description", "")
    # ✅ FIX #3 — assigned_to from employee dropdown
    assigned_to = request.form.get("assigned_to") or None
    priority    = request.form.get("priority")    or "Medium"
    deadline    = request.form.get("deadline")    or None

    print(f"[manager_create_task] title={title} assigned_to={assigned_to}")  # ✅ FIX #7

    if not title:
        flash("Task title is required.", "danger")
        return redirect(url_for("admin_dashboard"))

    file_url  = None
    task_file = request.files.get("task_file")
    if task_file and task_file.filename:
        fname     = f"{gen_salt(6)}_{secure_filename(task_file.filename)}"
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], fname)
        task_file.save(file_path)
        file_url = f"/static/task_files/{fname}"

    # ✅ FIX #4 — always save company_id, assigned_to, status
    status, data = api_post("/tasks", {
        "title":       title,
        "description": description,
        "company_id":  prof.get("company_id"),
        "assigned_to": assigned_to,
        "priority":    priority,
        "deadline":    deadline,
        "status":      "Pending",
        "file_url":    file_url,
    })

    print(f"[manager_create_task] api response status={status} data={data}")  # ✅ FIX #7

    if status in (200, 201):
        flash("Task created.", "success")
    else:
        error = data.get("message") or data.get("error") or "Task creation failed."
        flash(f"{error}", "danger")

    return redirect(url_for("admin_dashboard"))


@app.route("/manager/create_employee", methods=["POST"])
@login_required
def manager_create_employee():
    prof = get_profile()
    role = (prof or {}).get("role", "")
    print(f"[manager_create_employee] role={role}")  # ✅ FIX #7

    # ✅ FIX #1 — allow both company_admin and manager
    if not prof or role not in ALLOWED_ROLES:
        return "Unauthorized", 403

    # ✅ FIX #2 — correct field names: form "name" → full_name, form "role_id" → role
    name       = request.form.get("name",     "").strip()   # form field is "name"
    email      = request.form.get("email",    "").strip()
    password   = request.form.get("password") or gen_salt(8)
    role_id    = request.form.get("role_id")                # form field is "role_id"
    company_id = prof.get("company_id")

    print(f"[manager_create_employee] name={name} email={email} role_id={role_id} company_id={company_id}")  # ✅ FIX #7

    if not (name and email and role_id):
        flash("Name, email and role are required.", "danger")
        return redirect(url_for("admin_dashboard"))

    # ✅ FIX #2 — send correct fields: full_name (not name), role (not role_id key)
    status, data = api_post("/employees", {
        "full_name":  name,
        "email":      email,
        "password":   password,
        "role":       role_id,
        "company_id": company_id,
    })

    print(f"[manager_create_employee] api response status={status} data={data}")  # ✅ FIX #7

    if status not in (200, 201):
        error = data.get("message") or data.get("error") or "Failed to create user."
        flash(f"Employee creation failed: {error}", "danger")
        return redirect(url_for("admin_dashboard"))

    user_id = (
        (data.get("user") or {}).get("id")
        or data.get("id")
        or data.get("user_id")
    )

    if user_id:
        api_post("/profiles", {
            "id":         user_id,
            "full_name":  name,
            "company_id": company_id,
            "role":       "employee",
            "role_id":    role_id,
        })

    flash(f"Employee created (password: {password}) — share securely.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/manager/upload_task_file/<task_id>", methods=["POST"])
@login_required
def manager_upload_task_file(task_id):
    prof = get_profile()
    role = (prof or {}).get("role", "")
    print(f"[manager_upload_task_file] role={role} task_id={task_id}")  # ✅ FIX #7

    # ✅ FIX #1 — allow both company_admin and manager
    if not prof or role not in ALLOWED_ROLES:
        return "Unauthorized", 403

    task_raw = api_get(f"/tasks/{task_id}")
    task     = task_raw
    if isinstance(task_raw, dict):
        task = task_raw.get("data") or (task_raw if task_raw.get("id") else None)

    if not task or not isinstance(task, dict):
        flash("Task not found.", "danger")
        return redirect(url_for("admin_dashboard"))

    if str(task.get("company_id", "")) != str(prof.get("company_id", "")):
        flash("You cannot modify tasks from another company.", "danger")
        return redirect(url_for("admin_dashboard"))

    task_file = request.files.get("task_file")
    if not task_file or not task_file.filename:
        flash("Please choose a file to upload.", "danger")
        return redirect(url_for("admin_dashboard"))

    fname     = f"{gen_salt(6)}_{secure_filename(task_file.filename)}"
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], fname)
    task_file.save(file_path)
    file_url  = f"/static/task_files/{fname}"

    status, data = api_put(f"/tasks/{task_id}", {
        "file_url": file_url,
        "status":   "Completed",
    })

    if status in (200, 201, 204):
        flash("Task file uploaded.", "success")
    else:
        error = data.get("message") or data.get("error") or "Update failed."
        flash(f"Failed to update task file: {error}", "danger")

    return redirect(url_for("admin_dashboard"))


# ─────────────────────────────────────────────
# 16. Appeal
# ─────────────────────────────────────────────

@app.route("/appeal/send", methods=["POST"])
@login_required
def send_appeal():
    prof = get_profile()
    if not prof:
        return "Unauthorized", 403

    title   = request.form.get("title",   "").strip()
    message = request.form.get("message", "").strip()
    file    = request.files.get("file")

    file_url = None
    if file and file.filename:
        ext      = file.filename.rsplit(".", 1)[-1]
        fname    = f"{gen_salt(10)}.{ext}"
        savepath = os.path.join(app.config["UPLOAD_FOLDER"], fname)
        file.save(savepath)
        file_url = f"/static/task_files/{fname}"

    status, data = api_post("/appeals", {
        "user_id":    prof.get("id"),
        "company_id": prof.get("company_id"),
        "title":      title,
        "message":    message,
        "file_url":   file_url,
    })

    if status in (200, 201):
        flash("Appeal submitted successfully.", "success")
    else:
        error = data.get("message") or data.get("error") or "Appeal submission failed."
        flash(f"{error}", "danger")

    return redirect(url_for("employee_dashboard"))


# ─────────────────────────────────────────────
# 17. Marketing
# ─────────────────────────────────────────────

@app.route("/marketing/create_task", methods=["POST"])
@login_required
def marketing_create_task():
    prof = get_profile()
    if not prof or str(prof.get("role_id", "")) != "2":
        return "Unauthorized", 403

    # ✅ FIX #3 — assigned_to from dropdown
    assigned_to = request.form.get("assigned_to") or None
    print(f"[marketing_create_task] assigned_to={assigned_to}")  # ✅ FIX #7

    # ✅ FIX #4 — include company_id, assigned_to, status
    status, data = api_post("/tasks", {
        "title":       request.form.get("title", "").strip(),
        "description": request.form.get("description", ""),
        "assigned_to": assigned_to,
        "company_id":  prof.get("company_id"),
        "status":      "Pending",
        "deadline":    request.form.get("deadline"),
    })

    if status in (200, 201):
        flash("Task assigned successfully", "success")
    else:
        error = data.get("message") or data.get("error") or "Task creation failed."
        flash(f"{error}", "danger")

    return redirect(url_for("role_dashboard", role_id=2))


# ─────────────────────────────────────────────
# 18. Run
# ─────────────────────────────────────────────

if __name__ == "__main__":
    app.run(debug=True)
