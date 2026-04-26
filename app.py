import os
import importlib.util

import chardet
import requests
from dotenv import load_dotenv
from flask import (Flask, flash, redirect, render_template,request, session, url_for)
from functools import wraps
from werkzeug.security import gen_salt
from werkzeug.utils import secure_filename

# ─────────────────────────────────────────────
# 0. Environment + App Init
# ─────────────────────────────────────────────
load_dotenv()

API_URL    = "https://api.somaedgex-cloud.online"
SECRET_KEY = os.getenv("SECRET_KEY", "jaishreeram")

app = Flask(__name__)
app.secret_key = SECRET_KEY

# FIX #2 — Session / Cookie config for Render (HTTPS)
# SameSite=None + Secure=True is REQUIRED for cross-origin cookies on HTTPS.
app.config.update(
    SESSION_COOKIE_SECURE   = True,   # only sent over HTTPS
    SESSION_COOKIE_HTTPONLY = True,   # JS cannot read it
    SESSION_COOKIE_SAMESITE = "None", # allow cross-site (required on Render)
)

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
# 2. API helpers  (no Supabase, ever)
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
        print(f"[api_get] {path} -> {resp.status_code}")
        if resp.status_code in (200, 201):
            return _safe_json(resp)
    except Exception as exc:
        print(f"[api_get] ERROR {path}: {exc}")
    return None


def api_post(path: str, body: dict = None):
    """POST -> (status_code, json_data)."""
    try:
        resp = requests.post(
            f"{API_URL}{path}",
            json=body or {},
            headers=_auth_headers(),
            timeout=10,
        )
        print(f"[api_post] {path} -> {resp.status_code}")
        return resp.status_code, _safe_json(resp)
    except Exception as exc:
        print(f"[api_post] ERROR {path}: {exc}")
        return 0, {"error": str(exc)}


def api_put(path: str, body: dict = None):
    """PUT -> (status_code, json_data)."""
    try:
        resp = requests.put(
            f"{API_URL}{path}",
            json=body or {},
            headers=_auth_headers(),
            timeout=10,
        )
        print(f"[api_put] {path} -> {resp.status_code}")
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
# 3. Auth helpers  (NO Supabase anywhere)
# ─────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if "access_token" not in session:
            print("[login_required] no token in session -> redirect login")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapped


# FIX #6 — get_current_user: token IS the user_id, zero API calls
def get_current_user():
    token = session.get("access_token")
    if not token:
        return None

    return {"id": token}


# FIX #7 — get_profile: derive uid from session directly, no separate user call
import requests

def get_profile():
    token = session.get("access_token")

    if not token:
        return None

    try:
        # 🔥 call your Node API debug endpoint
        res = requests.get(f"https://api.somaedgex-cloud.online/debug/profile/{token}")

        data = res.json()

        print("PROFILE API:", data)

        return data.get("profile")

    except Exception as e:
        print("PROFILE ERROR:", e)
        return None

# ─────────────────────────────────────────────
# 4. Routes
# ─────────────────────────────────────────────

# FIX #8 — Index: token check first, profile second
@app.route("/")
def index():
    print(f"[index] session={dict(session)}")
    if "access_token" not in session:
        return render_template("index.html")

    prof = get_profile()
    print(f"[index] profile={prof}")

    if not prof:
        # Token exists but profile lookup failed — send to admin anyway
        # so the user isn't silently stuck on the homepage.
        return redirect(url_for("admin_dashboard"))

    role = prof.get("role", "")
    if role == "company_admin":
        return redirect(url_for("admin_dashboard"))
    if prof.get("role_id"):
        return redirect(url_for("role_dashboard", role_id=prof["role_id"]))
    return redirect(url_for("employee_dashboard"))


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

        # FIX #4 — single signup call; backend handles companies + profiles
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

# FIX #3 — Login flow: call /auth/v1/token, set session, redirect /admin
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if not email or not password:
            flash("Email and password required", "danger")
            return redirect(url_for("login"))

        try:
            res = requests.post(
                "https://api.somaedgex-cloud.online/auth/v1/token",
                json={"email": email, "password": password}
            )

            data = res.json()
            print("LOGIN RESPONSE:", data)   # 🔥 DEBUG
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

        print("SESSION SAVED:", session)   # 🔥 DEBUG

        # 🔥 FORCE DASHBOARD
        return redirect("/admin")

    return render_template("login.html")


# ─── Logout ───

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ─────────────────────────────────────────────
# 5. Admin Dashboard  (FIX #9)
# ─────────────────────────────────────────────

@app.route("/admin")
@login_required
def admin_dashboard():
    print(f"[admin_dashboard] session={dict(session)}")

    prof = get_profile()
    print(f"[admin_dashboard] profile={prof}")

    # ❌ STOP REDIRECT LOOP — SHOW ERROR INSTEAD
    if not prof:
        return f"""
        ❌ PROFILE NOT FOUND

        Session: {dict(session)}

        👉 Check:
        - Is profile created in DB?
        - Try: /debug/profile/{session.get('access_token')}
        """, 500

    # ⚠️ ROLE CHECK (DO NOT BLOCK)
    if prof.get("role") != "company_admin":
        print("⚠️ WARNING: Not admin role:", prof)

    company_id = prof.get("company_id")

    # 🔥 SAFE FETCH (NO CRASH IF API NOT READY)
    try:
        users = _unwrap(api_get("/profiles", params={"company_id": company_id})) or []
    except Exception as e:
        print("USERS ERROR:", e)
        users = []

    try:
        tasks = _unwrap(api_get("/tasks", params={"company_id": company_id})) or []
    except Exception as e:
        print("TASKS ERROR:", e)
        tasks = []

    try:
        roles = _unwrap(api_get("/roles", params={"company_id": company_id})) or []
    except Exception as e:
        print("ROLES ERROR:", e)
        roles = []

    return render_template(
        "admin_dashboard.html",
        profile=prof,
        users=users,
        tasks=tasks,
        roles=roles,
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

    if prof.get("role") == "company_admin":
        return redirect(url_for("admin_dashboard"))

    if str(prof.get("role_id", "")) != str(role_id):
        if prof.get("role_id"):
            return redirect(url_for("role_dashboard", role_id=prof["role_id"]))
        return redirect(url_for("employee_dashboard"))

    company_id = prof.get("company_id") or ""
    users = _unwrap(api_get("/profiles", params={"company_id": company_id}))
    tasks = _unwrap(api_get("/tasks",    params={"company_id": company_id}))
    roles = _unwrap(api_get("/roles",    params={"company_id": company_id}))

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
        )

    return html


# ─────────────────────────────────────────────
# 7. Edit Dashboard (Admin)
# ─────────────────────────────────────────────

@app.route("/admin/edit_dashboard/<role_id>", methods=["GET", "POST"])
@login_required
def edit_dashboard(role_id):
    prof = get_profile()
    if not prof or prof.get("role") != "company_admin":
        return "Unauthorized", 403

    role_data = api_get(f"/roles/{role_id}")
    if isinstance(role_data, dict):
        role = (
            role_data.get("data")
            if isinstance(role_data.get("data"), dict)
            else (role_data if role_data.get("id") else {"id": role_id, "name": f"Role {role_id}"})
        )
    else:
        role = {"id": role_id, "name": f"Role {role_id}"}

    role_dir = os.path.join("dashboard_codes", str(role_id))
    os.makedirs(role_dir, exist_ok=True)
    files = os.listdir(role_dir)

    if request.method == "POST":
        current_file = request.form.get("current_file") or (files[0] if files else None)

        if "new_file" in request.files:
            uploaded = request.files["new_file"]
            if uploaded.filename:
                fname = secure_filename(uploaded.filename)
                uploaded.save(os.path.join(role_dir, fname))
                flash(f"Uploaded {fname}", "success")
                current_file = fname

        if "file_content" in request.form and current_file:
            with open(os.path.join(role_dir, current_file), "w", encoding="utf-8") as fh:
                fh.write(request.form["file_content"])
            flash(f"Saved {current_file}", "success")
            return redirect(url_for("edit_dashboard", role_id=role_id, file=current_file))
    else:
        current_file = request.args.get("file") or (files[0] if files else None)

    file_content = ""
    if current_file:
        fpath = os.path.join(role_dir, current_file)
        try:
            raw          = open(fpath, "rb").read()
            detected     = chardet.detect(raw)
            file_content = raw.decode(detected.get("encoding") or "utf-8")
        except Exception as exc:
            file_content = f"Cannot read file: {exc}"

    return render_template(
        "edit_dashboard_multi.html",
        role=role,
        files=files,
        current_file=current_file,
        file_content=file_content,
    )


# ─────────────────────────────────────────────
# 8. Create Role
# ─────────────────────────────────────────────

@app.route("/admin/create_role", methods=["POST"])
@login_required
def create_role():
    prof = get_profile()
    if not prof or prof.get("role") != "company_admin":
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
# 9. Create Employee (Admin)
# ─────────────────────────────────────────────

@app.route("/admin/create_employee", methods=["POST"])
@login_required
def create_employee():
    prof = get_profile()
    if not prof or prof.get("role") != "company_admin":
        return "Unauthorized", 403

    name       = request.form.get("name",     "").strip()
    email      = request.form.get("email",    "").strip()
    password   = request.form.get("password") or gen_salt(8)
    role_id    = request.form.get("role_id")
    company_id = prof.get("company_id")

    if not (name and email):
        flash("Name and email are required.", "danger")
        return redirect(url_for("admin_dashboard"))

    status, data = api_post("/employees", {
        "full_name": request.form.get("full_name"),
    "email": request.form.get("email"),
    "password": request.form.get("password"),
    "role": request.form.get("role"),
    "company_id": prof["company_id"]
    })

    if status not in (200, 201):
        error = data.get("message") or data.get("error") or "Failed to create user."
        flash(f"{error}", "danger")
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


# ─────────────────────────────────────────────
# 10. Delete Employee (Admin)
# ─────────────────────────────────────────────

@app.route("/admin/delete_employee/<user_id>", methods=["POST"])
@login_required
def admin_delete_employee(user_id):
    prof = get_profile()
    if not prof or prof.get("role") != "company_admin":
        return "Unauthorized", 403

    company_id = prof.get("company_id")

    emp_raw = api_get(f"/profiles/{user_id}")
    emp     = emp_raw
    if isinstance(emp_raw, dict):
        emp = emp_raw.get("data") or (emp_raw if emp_raw.get("id") else None)

    if not emp or not isinstance(emp, dict):
        flash("Employee not found.", "danger")
        return redirect(url_for("admin_dashboard"))

    if str(emp.get("company_id", "")) != str(company_id):
        flash("You cannot delete employees from another company.", "danger")
        return redirect(url_for("admin_dashboard"))

    if emp.get("role") == "company_admin":
        flash("You cannot delete a company admin.", "danger")
        return redirect(url_for("admin_dashboard"))

    status, data = api_delete(f"/profiles/{user_id}")
    if status not in (200, 201, 204):
        error = data.get("message") or data.get("error") or "Delete failed."
        flash(f"{error}", "danger")
        return redirect(url_for("admin_dashboard"))

    # Best-effort cleanup — ignore failures
    api_delete(f"/auth/v1/users/{user_id}")
    api_put("/tasks/unassign", {"assigned_to": user_id})

    flash("Employee deleted.", "success")
    return redirect(url_for("admin_dashboard"))


# ─────────────────────────────────────────────
# 11. Create Task (Admin)
# ─────────────────────────────────────────────

@app.route("/admin/create_task", methods=["POST"])
@login_required
def create_task():
    prof = get_profile()
    if not prof or prof.get("role") != "company_admin":
        return "Unauthorized", 403

    title       = request.form.get("title",       "").strip()
    description = request.form.get("description", "")
    assigned_to = request.form.get("assigned_to") or None
    priority    = request.form.get("priority")    or "Medium"
    deadline    = request.form.get("deadline")    or None

    file_url  = None
    task_file = request.files.get("task_file")
    if task_file and task_file.filename:
        fname     = f"{gen_salt(6)}_{secure_filename(task_file.filename)}"
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], fname)
        task_file.save(file_path)
        file_url = f"/static/task_files/{fname}"

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

    if status in (200, 201):
        flash("Task created.", "success")
    else:
        error = data.get("message") or data.get("error") or "Task creation failed."
        flash(f"{error}", "danger")

    return redirect(url_for("admin_dashboard"))


# ─────────────────────────────────────────────
# 12. Delete Task (Admin)
# ─────────────────────────────────────────────

@app.route("/admin/delete_task/<task_id>", methods=["POST"])
@login_required
def admin_delete_task(task_id):
    prof = get_profile()
    if not prof or prof.get("role") != "company_admin":
        return "Unauthorized", 403

    company_id = prof.get("company_id")

    task_raw = api_get(f"/tasks/{task_id}")
    task     = task_raw
    if isinstance(task_raw, dict):
        task = task_raw.get("data") or (task_raw if task_raw.get("id") else None)

    if not task or not isinstance(task, dict):
        flash("Task not found.", "danger")
        return redirect(url_for("admin_dashboard"))

    if str(task.get("company_id", "")) != str(company_id):
        flash("You cannot delete tasks from another company.", "danger")
        return redirect(url_for("admin_dashboard"))

    status, data = api_delete(f"/tasks/{task_id}")
    if status in (200, 201, 204):
        flash("Task deleted.", "success")
    else:
        error = data.get("message") or data.get("error") or "Delete failed."
        flash(f"{error}", "danger")

    return redirect(url_for("admin_dashboard"))


# ─────────────────────────────────────────────
# 13. Reports  (FIX #10)
# ─────────────────────────────────────────────

@app.route("/admin/reports")
@login_required
def reports_page():
    prof = get_profile()
    if not prof or prof.get("role") != "company_admin":
        return "Unauthorized", 403

    company_id = prof.get("company_id") or ""
    tasks      = _unwrap(api_get("/tasks", params={"company_id": company_id}))

    # FIX #10 — safe even when tasks list is empty
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

    user_id = prof.get("id", "")
    tasks   = _unwrap(api_get("/tasks", params={"assigned_to": user_id}))

    total     = len(tasks)
    completed = sum(1 for t in tasks if (t.get("status") or "").lower() == "completed")
    percent   = int((completed / total) * 100) if total else 0

    return render_template(
        "employee_dashboard.html",
        profile=prof,
        tasks=tasks,
        percent=percent,
    )


# ─────────────────────────────────────────────
# 15. Manager Routes
# ─────────────────────────────────────────────

@app.route("/manager/create_task", methods=["POST"])
@login_required
def manager_create_task():
    prof = get_profile()
    if not prof or prof.get("role") != "manager":
        return "Unauthorized", 403

    title       = request.form.get("title", "").strip()
    description = request.form.get("description", "")
    assigned_to = request.form.get("assigned_to") or None
    priority    = request.form.get("priority")    or "Medium"
    deadline    = request.form.get("deadline")    or None

    if not title:
        flash("Task title is required.", "danger")
        return redirect(f"/role/{prof.get('role_id')}")

    file_url  = None
    task_file = request.files.get("task_file")
    if task_file and task_file.filename:
        fname     = f"{gen_salt(6)}_{secure_filename(task_file.filename)}"
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], fname)
        task_file.save(file_path)
        file_url = f"/static/task_files/{fname}"

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

    if status in (200, 201):
        flash("Task created by manager.", "success")
    else:
        error = data.get("message") or data.get("error") or "Task creation failed."
        flash(f"{error}", "danger")

    return redirect(f"/role/{prof.get('role_id')}")


@app.route("/manager/create_employee", methods=["POST"])
@login_required
def manager_create_employee():
    prof = get_profile()
    if not prof or prof.get("role") != "manager":
        return "Unauthorized", 403

    name       = request.form.get("name",     "").strip()
    email      = request.form.get("email",    "").strip()
    password   = request.form.get("password") or gen_salt(8)
    role_id    = request.form.get("role_id")
    company_id = prof.get("company_id")

    if not (name and email and role_id):
        flash("Name, email and role are required.", "danger")
        return redirect(f"/role/{prof.get('role_id')}")

    status, data = api_post("/employees", {
        "full_name": request.form.get("full_name"),
    "email": request.form.get("email"),
    "password": request.form.get("password"),
    "role": request.form.get("role"),
    "company_id": prof["company_id"]
    })

    if status not in (200, 201):
        error = data.get("message") or data.get("error") or "Failed to create user."
        flash(f"Manager failed to create user: {error}", "danger")
        return redirect(f"/role/{prof.get('role_id')}")

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

    flash(f"Employee created by manager (password: {password}) — share securely.", "success")
    return redirect(f"/role/{prof.get('role_id')}")


@app.route("/manager/upload_task_file/<task_id>", methods=["POST"])
@login_required
def manager_upload_task_file(task_id):
    prof = get_profile()
    if not prof or prof.get("role") != "manager":
        return "Unauthorized", 403

    task_raw = api_get(f"/tasks/{task_id}")
    task     = task_raw
    if isinstance(task_raw, dict):
        task = task_raw.get("data") or (task_raw if task_raw.get("id") else None)

    if not task or not isinstance(task, dict):
        flash("Task not found.", "danger")
        return redirect(f"/role/{prof.get('role_id')}")

    if str(task.get("company_id", "")) != str(prof.get("company_id", "")):
        flash("You cannot modify tasks from another company.", "danger")
        return redirect(f"/role/{prof.get('role_id')}")

    if str(task.get("assigned_to") or "") != str(prof.get("id") or ""):
        flash("You can only upload files for your own tasks.", "danger")
        return redirect(f"/role/{prof.get('role_id')}")

    task_file = request.files.get("task_file")
    if not task_file or not task_file.filename:
        flash("Please choose a file to upload.", "danger")
        return redirect(f"/role/{prof.get('role_id')}")

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

    return redirect(f"/role/{prof.get('role_id')}")


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

    status, data = api_post("/tasks", {
        "title":       request.form.get("title", "").strip(),
        "description": request.form.get("description", ""),
        "assigned_to": request.form.get("assigned_to"),
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
    # debug=True for local; Render uses gunicorn so this block is ignored there.
    app.run(debug=True)
