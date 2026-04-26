import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, flash
from functools import wraps
from werkzeug.security import gen_salt
from werkzeug.utils import secure_filename
import chardet
import importlib.util
import requests

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret")
API_URL = "https://api.somaedgex-cloud.online"

app = Flask(__name__)
app.secret_key = SECRET_KEY

# ----------------- File Upload Config -----------------
UPLOAD_FOLDER = os.path.join("static", "task_files")
ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "png", "jpg", "jpeg"}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ----------------- API Helpers -----------------

def _auth_headers():
    """Return Authorization header using the session token."""
    token = session.get("access_token", "")
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def api_get(path, params=None):
    """GET request to the backend API. Returns parsed JSON or None on failure."""
    try:
        resp = requests.get(f"{API_URL}{path}", headers=_auth_headers(), params=params, timeout=10)
        if resp.status_code in (200, 201):
            return resp.json()
    except Exception:
        pass
    return None


def api_post(path, body=None):
    """POST request to the backend API. Returns (status_code, json_data)."""
    try:
        resp = requests.post(f"{API_URL}{path}", json=body or {}, headers=_auth_headers(), timeout=10)
        try:
            data = resp.json()
        except Exception:
            data = {}
        return resp.status_code, data
    except Exception as e:
        return 0, {"error": str(e)}


def api_put(path, body=None):
    """PUT/PATCH request to the backend API. Returns (status_code, json_data)."""
    try:
        resp = requests.put(f"{API_URL}{path}", json=body or {}, headers=_auth_headers(), timeout=10)
        try:
            data = resp.json()
        except Exception:
            data = {}
        return resp.status_code, data
    except Exception as e:
        return 0, {"error": str(e)}


def api_delete(path):
    """DELETE request to the backend API. Returns (status_code, json_data)."""
    try:
        resp = requests.delete(f"{API_URL}{path}", headers=_auth_headers(), timeout=10)
        try:
            data = resp.json()
        except Exception:
            data = {}
        return resp.status_code, data
    except Exception as e:
        return 0, {"error": str(e)}


# ----------------- Auth/User Helpers -----------------

def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if "access_token" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapped


def get_current_user():
    """Fetch the current user from GET /auth/v1/user using the session token."""
    token = session.get("access_token")
    if not token:
        return None
    try:
        resp = requests.get(
            f"{API_URL}/auth/v1/user",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10
        )
        if resp.status_code == 200:
            data = resp.json()
            # Normalise: ensure data is a dict with an "id" field
            if isinstance(data, dict) and data.get("id"):
                return data
    except Exception:
        pass
    return None


def get_profile():
    """
    Fetch the current user's profile from GET /profiles/<user_id>.
    Falls back to GET /profiles?user_id=<id> if single-resource endpoint not available.
    Returns a dict or None.
    """
    user = get_current_user()
    if not user:
        return None
    uid = user.get("id") or user.get("user_id")
    if not uid:
        return None

    # Try /profiles/<uid> first
    data = api_get(f"/profiles/{uid}")
    if isinstance(data, dict) and data.get("id"):
        return data

    # Fallback: list endpoint filtered by user_id
    if isinstance(data, list) and data:
        return data[0]

    # Second fallback: query param style
    data2 = api_get("/profiles", params={"user_id": uid})
    if isinstance(data2, list) and data2:
        return data2[0]
    if isinstance(data2, dict) and data2.get("id"):
        return data2

    return None


# ----------------- Routes -----------------

@app.route("/")
def index():
    prof = get_profile()
    if prof:
        role = prof.get("role")
        if role == "company_admin":
            return redirect(url_for("admin_dashboard"))
        if prof.get("role_id"):
            return redirect(url_for("role_dashboard", role_id=prof["role_id"]))
        return redirect(url_for("employee_dashboard"))
    return render_template("index.html")


# --------- Register / Login / Logout ---------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        company_name = request.form.get("company_name", "").strip()
        admin_name   = request.form.get("admin_name", "").strip()
        email        = request.form.get("email", "").strip()
        password     = request.form.get("password", "")

        if not (company_name and admin_name and email and password):
            flash("All fields are required.", "danger")
            return redirect(url_for("register"))

        # POST /auth/v1/signup  — sends everything the backend needs
        status, data = api_post("/auth/v1/signup", {
            "email":        email,
            "password":     password,
            "company_name": company_name,
            "admin_name":   admin_name
        })

        if status in (200, 201):
            flash("Registered successfully. Please log in.", "success")
            return redirect(url_for("login"))

        # Surface a helpful error
        error_msg = (
            data.get("message")
            or data.get("error_description")
            or data.get("error")
            or "Registration failed. Please try again."
        )
        if "already" in error_msg.lower() or "exists" in error_msg.lower():
            flash("An account with this email already exists. Please log in.", "warning")
            return redirect(url_for("login"))

        flash(f"Sign up error: {error_msg}", "danger")
        return redirect(url_for("register"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not (email and password):
            flash("Email and password are required.", "danger")
            return redirect(url_for("login"))

        try:
            resp = requests.post(
                f"{API_URL}/auth/v1/token",
                json={"email": email, "password": password},
                timeout=10
            )
            try:
                data = resp.json()
            except Exception:
                data = {}
        except Exception as e:
            flash(f"❌ Login request failed: {e}", "danger")
            return redirect(url_for("login"))

        if resp.status_code not in (200, 201):
            error_msg = (
                data.get("message")
                or data.get("error_description")
                or data.get("error")
                or "Invalid email or password."
            )
            flash(f"❌ Login failed: {error_msg}", "danger")
            return redirect(url_for("login"))

        # Accept token at top level or nested under session/data
        token = (
            data.get("access_token")
            or (data.get("session") or {}).get("access_token")
            or (data.get("data") or {}).get("access_token")
        )

        if not token:
            flash("❌ Login failed: no access token returned.", "danger")
            return redirect(url_for("login"))

        session["access_token"] = token
        return redirect(url_for("index"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------- Admin Dashboard ----------------

@app.route("/admin")
@login_required
def admin_dashboard():
    prof = get_profile()
    if not prof or prof.get("role") != "company_admin":
        return "Unauthorized", 403

    company_id = prof.get("company_id")

    users = api_get(f"/profiles", params={"company_id": company_id}) or []
    tasks = api_get(f"/tasks",    params={"company_id": company_id}) or []
    roles = api_get(f"/roles",    params={"company_id": company_id}) or []

    # Normalise: some APIs wrap results in a key
    if isinstance(users, dict): users = users.get("data") or users.get("profiles") or []
    if isinstance(tasks, dict): tasks = tasks.get("data") or tasks.get("tasks") or []
    if isinstance(roles, dict): roles = roles.get("data") or roles.get("roles") or []

    return render_template(
        "admin_dashboard.html",
        profile=prof,
        users=users,
        tasks=tasks,
        roles=roles
    )


# ---------------- Role Dashboard ----------------

@app.route("/role/<role_id>")
@login_required
def role_dashboard(role_id):
    prof = get_profile()
    if not prof:
        return redirect(url_for("login"))

    if prof.get("role") == "company_admin":
        return redirect(url_for("admin_dashboard"))

    if str(prof.get("role_id")) != str(role_id):
        if prof.get("role_id"):
            return redirect(url_for("role_dashboard", role_id=prof["role_id"]))
        return redirect(url_for("employee_dashboard"))

    company_id = prof.get("company_id")

    users = api_get("/profiles", params={"company_id": company_id}) or []
    tasks = api_get("/tasks",    params={"company_id": company_id}) or []
    roles = api_get("/roles",    params={"company_id": company_id}) or []

    if isinstance(users, dict): users = users.get("data") or users.get("profiles") or []
    if isinstance(tasks, dict): tasks = tasks.get("data") or tasks.get("tasks") or []
    if isinstance(roles, dict): roles = roles.get("data") or roles.get("roles") or []

    # Load optional Python dashboard renderer
    html = None
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
            except Exception as e:
                flash(f"Dashboard render error: {e}", "danger")

    if html is None:
        user_tasks = [t for t in tasks if str(t.get("assigned_to")) == str(prof.get("id"))]
        total     = len(user_tasks)
        completed = sum(1 for t in user_tasks if (t.get("status") or "").lower() == "completed")
        percent   = int((completed / total) * 100) if total else 0
        return render_template(
            "employee_dashboard.html",
            profile=prof,
            tasks=user_tasks,
            percent=percent
        )

    return html


# ---------------- Edit Dashboard ----------------

@app.route("/admin/edit_dashboard/<role_id>", methods=["GET", "POST"])
@login_required
def edit_dashboard(role_id):
    prof = get_profile()
    if not prof or prof.get("role") != "company_admin":
        return "Unauthorized", 403

    # Fetch role info from API
    role_data = api_get(f"/roles/{role_id}")
    if isinstance(role_data, dict) and role_data.get("data"):
        role = role_data["data"]
    elif isinstance(role_data, dict) and role_data.get("id"):
        role = role_data
    else:
        role = {"id": role_id, "name": f"Role {role_id}"}

    role_dir = os.path.join("dashboard_codes", str(role_id))
    os.makedirs(role_dir, exist_ok=True)
    files = os.listdir(role_dir)

    if request.method == "POST":
        current_file = request.form.get("current_file") or (files[0] if files else None)

        if "new_file" in request.files:
            uploaded_file = request.files["new_file"]
            if uploaded_file.filename != "":
                filename = secure_filename(uploaded_file.filename)
                uploaded_file.save(os.path.join(role_dir, filename))
                flash(f"✅ Uploaded file {filename}", "success")
                current_file = filename

        if "file_content" in request.form and current_file:
            save_path = os.path.join(role_dir, current_file)
            with open(save_path, "w", encoding="utf-8") as f:
                f.write(request.form["file_content"])
            flash(f"✅ Saved {current_file}", "success")
            return redirect(url_for("edit_dashboard", role_id=role_id, file=current_file))
    else:
        current_file = request.args.get("file") or (files[0] if files else None)

    file_content = ""
    if current_file:
        file_path = os.path.join(role_dir, current_file)
        try:
            raw      = open(file_path, "rb").read()
            detected = chardet.detect(raw)
            file_content = raw.decode(detected["encoding"] or "utf-8")
        except Exception as e:
            file_content = f"Cannot read file: {e}"

    return render_template(
        "edit_dashboard_multi.html",
        role=role,
        files=files,
        current_file=current_file,
        file_content=file_content
    )


# ---------------- Create Role ----------------

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
        "name":       role_name
    })

    if status in (200, 201):
        flash(f"✅ Role '{role_name}' created.", "success")
    else:
        error = data.get("message") or data.get("error") or "Role creation failed."
        flash(f"❌ {error}", "danger")

    return redirect(url_for("admin_dashboard"))


# ---------------- Create Employee (Admin) ----------------

@app.route("/admin/create_employee", methods=["POST"])
@login_required
def create_employee():
    prof = get_profile()
    if not prof or prof.get("role") != "company_admin":
        return "Unauthorized", 403

    name       = request.form.get("name", "").strip()
    email      = request.form.get("email", "").strip()
    password   = request.form.get("password") or gen_salt(8)
    role_id    = request.form.get("role_id")
    company_id = prof.get("company_id")

    if not (name and email):
        flash("Name and email are required.", "danger")
        return redirect(url_for("admin_dashboard"))

    # 1) Create auth user via signup
    status, data = api_post("/auth/v1/signup", {
        "email":      email,
        "password":   password,
        "admin_name": name,
        "company_id": company_id,
        "role":       "employee",
        "role_id":    role_id
    })

    if status not in (200, 201):
        error = data.get("message") or data.get("error") or "Failed to create user."
        flash(f"❌ {error}", "danger")
        return redirect(url_for("admin_dashboard"))

    user_id = (
        (data.get("user") or {}).get("id")
        or data.get("id")
        or data.get("user_id")
    )

    # 2) Create profile if we have a user_id
    if user_id:
        api_post("/profiles", {
            "id":         user_id,
            "full_name":  name,
            "company_id": company_id,
            "role":       "employee",
            "role_id":    role_id
        })

    flash(f"✅ Employee created (password: {password}) — share securely.", "success")
    return redirect(url_for("admin_dashboard"))


# ---------------- Delete Employee (Admin) ----------------

@app.route("/admin/delete_employee/<user_id>", methods=["POST"])
@login_required
def admin_delete_employee(user_id):
    prof = get_profile()
    if not prof or prof.get("role") != "company_admin":
        return "Unauthorized", 403

    company_id = prof.get("company_id")

    # Verify employee belongs to this company
    emp = api_get(f"/profiles/{user_id}")
    if isinstance(emp, dict) and emp.get("data"):
        emp = emp["data"]

    if not emp or not isinstance(emp, dict):
        flash("Employee not found.", "danger")
        return redirect(url_for("admin_dashboard"))

    if str(emp.get("company_id")) != str(company_id):
        flash("You cannot delete employees from another company.", "danger")
        return redirect(url_for("admin_dashboard"))

    if emp.get("role") == "company_admin":
        flash("You cannot delete a company admin.", "danger")
        return redirect(url_for("admin_dashboard"))

    # Delete profile
    status, data = api_delete(f"/profiles/{user_id}")
    if status not in (200, 201, 204):
        error = data.get("message") or data.get("error") or "Delete failed."
        flash(f"❌ {error}", "danger")
        return redirect(url_for("admin_dashboard"))

    # Optionally delete auth user (placeholder — add endpoint if available)
    api_delete(f"/auth/v1/users/{user_id}")

    # Unassign their tasks
    api_put(f"/tasks/unassign", {"assigned_to": user_id})

    flash("✅ Employee deleted.", "success")
    return redirect(url_for("admin_dashboard"))


# ---------------- Create Task (Admin) ----------------

@app.route("/admin/create_task", methods=["POST"])
@login_required
def create_task():
    prof = get_profile()
    if not prof or prof.get("role") != "company_admin":
        return "Unauthorized", 403

    title       = request.form.get("title", "").strip()
    description = request.form.get("description", "")
    assigned_to = request.form.get("assigned_to") or None
    priority    = request.form.get("priority") or "Medium"
    deadline    = request.form.get("deadline") or None

    file_url = None
    task_file = request.files.get("task_file")
    if task_file and task_file.filename != "":
        filename  = f"{gen_salt(6)}_{secure_filename(task_file.filename)}"
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        task_file.save(file_path)
        file_url = f"/static/task_files/{filename}"

    status, data = api_post("/tasks", {
        "title":       title,
        "description": description,
        "company_id":  prof.get("company_id"),
        "assigned_to": assigned_to,
        "priority":    priority,
        "deadline":    deadline,
        "status":      "Pending",
        "file_url":    file_url
    })

    if status in (200, 201):
        flash("✅ Task created.", "success")
    else:
        error = data.get("message") or data.get("error") or "Task creation failed."
        flash(f"❌ {error}", "danger")

    return redirect(url_for("admin_dashboard"))


# ---------------- Delete Task (Admin) ----------------

@app.route("/admin/delete_task/<task_id>", methods=["POST"])
@login_required
def admin_delete_task(task_id):
    prof = get_profile()
    if not prof or prof.get("role") != "company_admin":
        return "Unauthorized", 403

    company_id = prof.get("company_id")

    task = api_get(f"/tasks/{task_id}")
    if isinstance(task, dict) and task.get("data"):
        task = task["data"]

    if not task or not isinstance(task, dict):
        flash("Task not found.", "danger")
        return redirect(url_for("admin_dashboard"))

    if str(task.get("company_id")) != str(company_id):
        flash("You cannot delete tasks from another company.", "danger")
        return redirect(url_for("admin_dashboard"))

    status, data = api_delete(f"/tasks/{task_id}")
    if status in (200, 201, 204):
        flash("✅ Task deleted.", "success")
    else:
        error = data.get("message") or data.get("error") or "Delete failed."
        flash(f"❌ {error}", "danger")

    return redirect(url_for("admin_dashboard"))


# ---------------- Reports ----------------

@app.route("/admin/reports")
@login_required
def reports_page():
    prof = get_profile()
    if not prof or prof.get("role") != "company_admin":
        return "Unauthorized", 403

    company_id = prof.get("company_id")
    tasks_raw  = api_get("/tasks", params={"company_id": company_id}) or []

    if isinstance(tasks_raw, dict):
        tasks = tasks_raw.get("data") or tasks_raw.get("tasks") or []
    else:
        tasks = tasks_raw

    total     = len(tasks)
    completed = sum(1 for t in tasks if (t.get("status") or "").lower() == "completed")
    pending   = total - completed

    tasks_per_employee = {}
    for t in tasks:
        assigned = t.get("assigned_to") or "Unassigned"
        tasks_per_employee[assigned] = tasks_per_employee.get(assigned, 0) + 1

    return render_template(
        "reports.html",
        total=total,
        completed=completed,
        pending=pending,
        tasks_per_employee=tasks_per_employee
    )


# ---------------- Employee Dashboard ----------------

@app.route("/employee")
@login_required
def employee_dashboard():
    prof = get_profile()
    if not prof:
        return redirect(url_for("login"))

    user_id   = prof.get("id")
    tasks_raw = api_get("/tasks", params={"assigned_to": user_id}) or []

    if isinstance(tasks_raw, dict):
        tasks = tasks_raw.get("data") or tasks_raw.get("tasks") or []
    else:
        tasks = tasks_raw

    total     = len(tasks)
    completed = sum(1 for t in tasks if (t.get("status") or "").lower() == "completed")
    percent   = int((completed / total) * 100) if total > 0 else 0

    return render_template(
        "employee_dashboard.html",
        profile=prof,
        tasks=tasks,
        percent=percent
    )


# ---------------- Manager: Create Task ----------------

@app.route("/manager/create_task", methods=["POST"])
@login_required
def manager_create_task():
    prof = get_profile()
    if not prof or prof.get("role") != "manager":
        return "Unauthorized", 403

    title       = request.form.get("title", "").strip()
    description = request.form.get("description", "")
    assigned_to = request.form.get("assigned_to") or None
    priority    = request.form.get("priority") or "Medium"
    deadline    = request.form.get("deadline") or None

    if not title:
        flash("Task title is required.", "danger")
        return redirect(f"/role/{prof.get('role_id')}")

    file_url = None
    task_file = request.files.get("task_file")
    if task_file and task_file.filename != "":
        filename  = f"{gen_salt(6)}_{secure_filename(task_file.filename)}"
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        task_file.save(file_path)
        file_url = f"/static/task_files/{filename}"

    status, data = api_post("/tasks", {
        "title":       title,
        "description": description,
        "company_id":  prof.get("company_id"),
        "assigned_to": assigned_to,
        "priority":    priority,
        "deadline":    deadline,
        "status":      "Pending",
        "file_url":    file_url
    })

    if status in (200, 201):
        flash("✅ Task created by manager.", "success")
    else:
        error = data.get("message") or data.get("error") or "Task creation failed."
        flash(f"❌ {error}", "danger")

    return redirect(f"/role/{prof.get('role_id')}")


# ---------------- Manager: Create Employee ----------------

@app.route("/manager/create_employee", methods=["POST"])
@login_required
def manager_create_employee():
    prof = get_profile()
    if not prof or prof.get("role") != "manager":
        return "Unauthorized", 403

    name       = request.form.get("name", "").strip()
    email      = request.form.get("email", "").strip()
    password   = request.form.get("password") or gen_salt(8)
    role_id    = request.form.get("role_id")
    company_id = prof.get("company_id")

    if not (name and email and role_id):
        flash("Name, email and role are required.", "danger")
        return redirect(f"/role/{prof.get('role_id')}")

    status, data = api_post("/auth/v1/signup", {
        "email":      email,
        "password":   password,
        "admin_name": name,
        "company_id": company_id,
        "role":       "employee",
        "role_id":    role_id
    })

    if status not in (200, 201):
        error = data.get("message") or data.get("error") or "Failed to create user."
        flash(f"❌ Manager failed to create user: {error}", "danger")
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
            "role_id":    role_id
        })

    flash(f"✅ Employee created by manager (password: {password}) — share securely.", "success")
    return redirect(f"/role/{prof.get('role_id')}")


# ---------------- Manager: Upload Completed Task File ----------------

@app.route("/manager/upload_task_file/<task_id>", methods=["POST"])
@login_required
def manager_upload_task_file(task_id):
    prof = get_profile()
    if not prof or prof.get("role") != "manager":
        return "Unauthorized", 403

    task = api_get(f"/tasks/{task_id}")
    if isinstance(task, dict) and task.get("data"):
        task = task["data"]

    if not task or not isinstance(task, dict):
        flash("Task not found.", "danger")
        return redirect(f"/role/{prof.get('role_id')}")

    if str(task.get("company_id")) != str(prof.get("company_id")):
        flash("You cannot modify tasks from another company.", "danger")
        return redirect(f"/role/{prof.get('role_id')}")

    if str(task.get("assigned_to") or "") != str(prof.get("id") or ""):
        flash("You can only upload files for your own tasks.", "danger")
        return redirect(f"/role/{prof.get('role_id')}")

    task_file = request.files.get("task_file")
    if not task_file or task_file.filename == "":
        flash("Please choose a file to upload.", "danger")
        return redirect(f"/role/{prof.get('role_id')}")

    filename  = f"{gen_salt(6)}_{secure_filename(task_file.filename)}"
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    task_file.save(file_path)
    file_url  = f"/static/task_files/{filename}"

    status, data = api_put(f"/tasks/{task_id}", {
        "file_url": file_url,
        "status":   "Completed"
    })

    if status in (200, 201, 204):
        flash("✅ Task file uploaded.", "success")
    else:
        error = data.get("message") or data.get("error") or "Update failed."
        flash(f"❌ Failed to update task file: {error}", "danger")

    return redirect(f"/role/{prof.get('role_id')}")


# ---------------- Appeal ----------------

@app.route("/appeal/send", methods=["POST"])
@login_required
def send_appeal():
    prof = get_profile()
    if not prof:
        return "Unauthorized", 403

    title   = request.form.get("title", "").strip()
    message = request.form.get("message", "").strip()
    file    = request.files.get("file")

    file_name = None
    file_url  = None

    # Save file locally (no Supabase storage)
    if file and file.filename:
        ext       = file.filename.rsplit(".", 1)[-1]
        file_name = f"{gen_salt(10)}.{ext}"
        save_path = os.path.join(app.config["UPLOAD_FOLDER"], file_name)
        file.save(save_path)
        file_url = f"/static/task_files/{file_name}"

    status, data = api_post("/appeals", {
        "user_id":    prof.get("id"),
        "company_id": prof.get("company_id"),
        "title":      title,
        "message":    message,
        "file_url":   file_url
    })

    if status in (200, 201):
        flash("✅ Appeal submitted successfully.", "success")
    else:
        error = data.get("message") or data.get("error") or "Appeal submission failed."
        flash(f"❌ {error}", "danger")

    return redirect(url_for("employee_dashboard"))


# ---------------- Marketing: Create Task ----------------

@app.route("/marketing/create_task", methods=["POST"])
@login_required
def marketing_create_task():
    prof = get_profile()
    if not prof or str(prof.get("role_id")) != "2":
        return "Unauthorized", 403

    status, data = api_post("/tasks", {
        "title":       request.form.get("title", "").strip(),
        "description": request.form.get("description", ""),
        "assigned_to": request.form.get("assigned_to"),
        "company_id":  prof.get("company_id"),
        "status":      "Pending",
        "deadline":    request.form.get("deadline")
    })

    if status in (200, 201):
        flash("Task assigned successfully", "success")
    else:
        error = data.get("message") or data.get("error") or "Task creation failed."
        flash(f"❌ {error}", "danger")

    return redirect(url_for("role_dashboard", role_id=2))


# ---------------- Run ----------------

if __name__ == "__main__":
    app.run(debug=True)
