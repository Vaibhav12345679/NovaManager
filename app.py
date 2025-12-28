import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, flash
from supabase import create_client, Client
from functools import wraps
from werkzeug.security import gen_salt
from werkzeug.utils import secure_filename
import chardet  # pip install chardet

# NEW: for catching DB errors like duplicate key
from postgrest.exceptions import APIError

# NEW: to dynamically load role dashboards from Python files
import importlib.util

# ----------------- Load .env -----------------
load_dotenv()
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret")

if not (SUPABASE_URL and SUPABASE_ANON_KEY and SUPABASE_SERVICE_ROLE_KEY):
    raise RuntimeError("❌ Fill .env with SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY")

# ----------------- Clients -----------------
sb: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
sb_admin: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

app = Flask(__name__)
app.secret_key = SECRET_KEY

# ----------------- File Upload Config -----------------
UPLOAD_FOLDER = os.path.join("static", "task_files")
ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "png", "jpg", "jpeg"}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

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
    uid = user.id
    try:
        res = sb_admin.table("profiles").select("*").eq("id", uid).maybe_single().execute()
        return res.data
    except Exception:
        return None

# ----------------- Routes -----------------
@app.route("/")
def index():
    prof = get_profile()
    if prof:
        role = prof.get("role")
        # Admin → admin dashboard
        if role == "company_admin":
            return redirect(url_for("admin_dashboard"))
        # If user has a role_id → go to that role dashboard (manager etc.)
        if prof.get("role_id"):
            return redirect(url_for("role_dashboard", role_id=prof["role_id"]))
        # Fallback → generic employee dashboard
        return redirect(url_for("employee_dashboard"))
    # Not logged in → landing page
    return render_template("index.html")

# --------- Register/Login/Logout ---------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        company_name = request.form.get("company_name")
        admin_name = request.form.get("admin_name")
        email = request.form.get("email")
        password = request.form.get("password")

        # Required fields check
        if not (company_name and admin_name and email and password):
            flash("All fields are required.", "danger")
            return redirect(url_for("register"))

        # 1) Create auth user using SERVICE ROLE (admin) so it's confirmed
        try:
            created = sb_admin.auth.admin.create_user({
                "email": email,
                "password": password,
                "email_confirm": True
            })
        except Exception as e:
            msg = str(e)
            if "already registered" in msg.lower() or "already exists" in msg.lower():
                flash("An account with this email already exists. Please log in.", "warning")
                return redirect(url_for("login"))
            flash("Sign up error: " + msg, "danger")
            return redirect(url_for("register"))

        user = getattr(created, "user", None)
        if not user:
            flash("Signup failed (no user returned).", "danger")
            return redirect(url_for("register"))

        user_id = user.id

        # 2) Insert into companies (handle duplicate company email)
        try:
            comp = sb_admin.table("companies").insert({
                "name": company_name,
                "admin_user_id": user_id,
                "email": email
            }).execute()
        except APIError as e:
            if e.code == "23505":
                flash("A company with this email already exists. Please log in instead.", "warning")
                # optional: delete user to avoid orphan
                try:
                    sb_admin.auth.admin.delete_user(user_id)
                except Exception:
                    pass
                return redirect(url_for("login"))
            flash(f"Company creation failed: {e.message}", "danger")
            # optional: delete user
            try:
                sb_admin.auth.admin.delete_user(user_id)
            except Exception:
                pass
            return redirect(url_for("register"))
        except Exception as e:
            flash("Company creation failed: " + str(e), "danger")
            try:
                sb_admin.auth.admin.delete_user(user_id)
            except Exception:
                pass
            return redirect(url_for("register"))

        if not comp.data:
            flash("Company creation failed.", "danger")
            try:
                sb_admin.auth.admin.delete_user(user_id)
            except Exception:
                pass
            return redirect(url_for("register"))

        company_id = comp.data[0]["id"]

        # 3) Create admin profile
        try:
            sb_admin.table("profiles").insert({
                "id": user_id,
                "full_name": admin_name,
                "company_id": company_id,
                "role": "company_admin"
            }).execute()
        except Exception as e:
            flash("Profile creation failed: " + str(e), "danger")
            # you could also clean up company + user here if you want strict consistency
            return redirect(url_for("register"))

        flash("Registered. Please login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if not (email and password):
            flash("Email and password are required.", "danger")
            return redirect(url_for("login"))

        try:
            res = sb.auth.sign_in_with_password({"email": email, "password": password})
        except Exception as e:
            flash("❌ Login failed: " + str(e), "danger")
            return redirect(url_for("login"))

        if not res or not getattr(res, "session", None):
            flash("❌ Login failed. Please check your email and password.", "danger")
            return redirect(url_for("login"))

        session["access_token"] = res.session.access_token
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

    company_id = prof["company_id"]
    users_resp = sb_admin.table("profiles").select("*").eq("company_id", company_id).execute()
    tasks_resp = sb_admin.table("tasks").select("*").eq("company_id", company_id).execute()
    roles_resp = sb_admin.table("roles").select("*").eq("company_id", company_id).execute()

    return render_template(
        "admin_dashboard.html",
        profile=prof,
        users=users_resp.data or [],
        tasks=tasks_resp.data or [],
        roles=roles_resp.data or []
    )

@app.route("/role/<role_id>")
@login_required
def role_dashboard(role_id):
    prof = get_profile()
    if not prof:
        return redirect(url_for("login"))

    # Admins should use /admin
    if prof.get("role") == "company_admin":
        return redirect(url_for("admin_dashboard"))

    # Ensure user only accesses their own role dashboard
    if str(prof.get("role_id")) != str(role_id):
        if prof.get("role_id"):
            return redirect(url_for("role_dashboard", role_id=prof["role_id"]))
        return redirect(url_for("employee_dashboard"))

    company_id = prof["company_id"]

    users = (
        sb_admin.table("profiles")
        .select("*")
        .eq("company_id", company_id)
        .execute()
        .data or []
    )

    tasks = (
        sb_admin.table("tasks")
        .select("*")
        .eq("company_id", company_id)
        .execute()
        .data or []
    )

    roles = (
        sb_admin.table("roles")
        .select("*")
        .eq("company_id", company_id)
        .execute()
        .data or []
    )

    # Load dashboard python renderer
    html = None
    role_dir = os.path.join("dashboard_codes", str(role_id))

    if os.path.isdir(role_dir):
        py_files = [f for f in os.listdir(role_dir) if f.endswith(".py")]
        if py_files:
            module_path = os.path.join(role_dir, py_files[0])
            try:
                spec = importlib.util.spec_from_file_location(f"dashboard_{role_id}", module_path)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)

                if hasattr(mod, "render_dashboard"):
                    html = mod.render_dashboard(prof, users, tasks, roles)

            except Exception as e:
                flash(f"Dashboard render error: {e}", "danger")

    # Fallback → employee dashboard
    if html is None:
        user_tasks = [t for t in tasks if str(t.get("assigned_to")) == str(prof["id"])]
        total = len(user_tasks)
        completed = sum(1 for t in user_tasks if (t.get("status") or "").lower() == "completed")
        percent = int((completed / total) * 100) if total else 0

        return render_template(
            "employee_dashboard.html",
            profile=prof,
            tasks=user_tasks,
            percent=percent
        )

    return html


@app.route("/admin/edit_dashboard/<role_id>", methods=["GET", "POST"])
@login_required
def edit_dashboard(role_id):
    prof = get_profile()
    if not prof or prof.get("role") != "company_admin":
        return "Unauthorized", 403

    # Get role
    role_resp = sb_admin.table("roles").select("*").eq("id", role_id).maybe_single().execute()
    role = role_resp.data
    if not role:
        return "Role not found", 404

    role_dir = os.path.join("dashboard_codes", role_id)
    os.makedirs(role_dir, exist_ok=True)

    # List all files in role folder
    files = os.listdir(role_dir)

    # Determine which file to edit
    if request.method == "POST":
        # If coming from the file select dropdown
        current_file = request.form.get("current_file") or (files[0] if files else None)

        # Handle file upload
        if "new_file" in request.files:
            uploaded_file = request.files["new_file"]
            if uploaded_file.filename != "":
                filename = secure_filename(uploaded_file.filename)
                uploaded_file.save(os.path.join(role_dir, filename))
                flash(f"✅ Uploaded file {filename}", "success")
                current_file = filename  # Automatically switch to the uploaded file

        # Handle saving edits
        if "file_content" in request.form and current_file:
            save_path = os.path.join(role_dir, current_file)
            with open(save_path, "w", encoding="utf-8") as f:
                f.write(request.form["file_content"])
            flash(f"✅ Saved {current_file}", "success")
            return redirect(url_for("edit_dashboard", role_id=role_id, file=current_file))
    else:
        # GET request
        current_file = request.args.get("file") or (files[0] if files else None)

    # Load file content safely
    file_content = ""
    if current_file:
        file_path = os.path.join(role_dir, current_file)
        try:
            raw = open(file_path, "rb").read()
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

    role_name = request.form.get("role_name")
    sb_admin.table("roles").insert({
        "company_id": prof["company_id"],
        "name": role_name
    }).execute()
    flash(f"✅ Role '{role_name}' created.", "success")
    return redirect(url_for("admin_dashboard"))

# ---------------- Create Employee (Admin) ----------------
@app.route("/admin/create_employee", methods=["POST"])
@login_required
def create_employee():
    prof = get_profile()
    if not prof or prof.get("role") != "company_admin":
        return "Unauthorized", 403

    name = request.form.get("name")
    email = request.form.get("email")
    password = request.form.get("password") or gen_salt(8)
    role_id = request.form.get("role_id")
    company_id = prof["company_id"]

    created = sb_admin.auth.admin.create_user({
        "email": email,
        "password": password,
        "email_confirm": True
    })

    if not created or not created.user:
        flash("❌ Failed to create user.", "danger")
        return redirect(url_for("admin_dashboard"))

    user_id = created.user.id

    sb_admin.table("profiles").insert({
        "id": user_id,
        "full_name": name,
        "company_id": company_id,
        "role": "employee",
        "role_id": role_id
    }).execute()

    flash(f"✅ Employee created (password: {password}) — share securely.", "success")
    return redirect(url_for("admin_dashboard"))

# ---------------- Delete Employee (Admin) ----------------
@app.route("/admin/delete_employee/<user_id>", methods=["POST"])
@login_required
def admin_delete_employee(user_id):
    prof = get_profile()
    if not prof or prof.get("role") != "company_admin":
        return "Unauthorized", 403

    company_id = prof["company_id"]

    # Make sure the employee belongs to this company and is not an admin
    try:
        resp = (
            sb_admin.table("profiles")
            .select("*")
            .eq("id", user_id)
            .maybe_single()
            .execute()
        )
        emp = resp.data
    except Exception:
        emp = None

    if not emp:
        flash("Employee not found.", "danger")
        return redirect(url_for("admin_dashboard"))

    if emp.get("company_id") != company_id:
        flash("You cannot delete employees from another company.", "danger")
        return redirect(url_for("admin_dashboard"))

    if emp.get("role") == "company_admin":
        flash("You cannot delete a company admin from here.", "danger")
        return redirect(url_for("admin_dashboard"))

    # 1) Delete profile row
    try:
        sb_admin.table("profiles").delete().eq("id", user_id).execute()
    except Exception as e:
        flash("Failed to delete employee profile: " + str(e), "danger")
        return redirect(url_for("admin_dashboard"))

    # 2) Delete auth user (optional but recommended)
    try:
        sb_admin.auth.admin.delete_user(user_id)
    except Exception:
        flash("Employee auth user could not be deleted, but profile was removed.", "warning")

    # 3) Optionally unassign their tasks
    try:
        sb_admin.table("tasks").update({"assigned_to": None}).eq("assigned_to", user_id).execute()
    except Exception:
        pass  # not critical

    flash("✅ Employee deleted.", "success")
    return redirect(url_for("admin_dashboard"))

# ---------------- Create Task (Admin) ----------------
@app.route("/admin/create_task", methods=["POST"])
@login_required
def create_task():
    prof = get_profile()
    if not prof or prof.get("role") != "company_admin":
        return "Unauthorized", 403

    title = request.form.get("title")
    description = request.form.get("description")
    assigned_to = request.form.get("assigned_to") or None
    priority = request.form.get("priority") or "Medium"
    deadline = request.form.get("deadline") or None

    file_url = None
    task_file = request.files.get("task_file")
    if task_file and task_file.filename != "":
        filename = f"{gen_salt(6)}_{secure_filename(task_file.filename)}"
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        task_file.save(file_path)
        file_url = f"/static/task_files/{filename}"

    sb_admin.table("tasks").insert({
        "title": title,
        "description": description,
        "company_id": prof["company_id"],
        "assigned_to": assigned_to,
        "priority": priority,
        "deadline": deadline,
        "status": "Pending",
        "file_url": file_url
    }).execute()

    flash("✅ Task created.", "success")
    return redirect(url_for("admin_dashboard"))

# ---------------- Delete Task (Admin) ----------------
@app.route("/admin/delete_task/<task_id>", methods=["POST"])
@login_required
def admin_delete_task(task_id):
    prof = get_profile()
    if not prof or prof.get("role") != "company_admin":
        return "Unauthorized", 403

    company_id = prof["company_id"]

    # Check task belongs to this company
    try:
        resp = (
            sb_admin.table("tasks")
            .select("*")
            .eq("id", task_id)
            .maybe_single()
            .execute()
        )
        task = resp.data
    except Exception:
        task = None

    if not task:
        flash("Task not found.", "danger")
        return redirect(url_for("admin_dashboard"))

    if task.get("company_id") != company_id:
        flash("You cannot delete tasks from another company.", "danger")
        return redirect(url_for("admin_dashboard"))

    try:
        sb_admin.table("tasks").delete().eq("id", task_id).execute()
    except Exception as e:
        flash("Failed to delete task: " + str(e), "danger")
        return redirect(url_for("admin_dashboard"))

    flash("✅ Task deleted.", "success")
    return redirect(url_for("admin_dashboard"))

# ---------------- Reports ----------------
@app.route("/admin/reports")
@login_required
def reports_page():
    prof = get_profile()
    if not prof or prof.get("role") != "company_admin":
        return "Unauthorized", 403

    company_id = prof["company_id"]
    tasks_resp = sb_admin.table("tasks").select("*").eq("company_id", company_id).execute()
    tasks = tasks_resp.data or []

    total = len(tasks)
    completed = sum(1 for t in tasks if (t.get("status") or "").lower() == "completed")
    pending = total - completed

    tasks_per_employee = {}
    for t in tasks:
        assigned = t.get("assigned_to") or "Unassigned"
        tasks_per_employee[assigned] = tasks_per_employee.get(assigned, 0) + 1

    return render_template("reports.html",
                           total=total, completed=completed, pending=pending,
                           tasks_per_employee=tasks_per_employee)

# ---------------- Employee Dashboard ----------------
@app.route("/employee")
@login_required
def employee_dashboard():
    prof = get_profile()
    if not prof:
        return redirect(url_for("login"))

    user_id = prof["id"]

    tasks_resp = (
        sb_admin.table("tasks")
        .select("*")
        .eq("assigned_to", user_id)
        .execute()
    )

    tasks = tasks_resp.data or []
    total = len(tasks)
    completed = sum(1 for t in tasks if (t.get("status") or "").lower() == "completed")
    percent = int((completed / total) * 100) if total > 0 else 0

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

    title = request.form.get("title")
    description = request.form.get("description")
    assigned_to = request.form.get("assigned_to") or None
    priority = request.form.get("priority") or "Medium"
    deadline = request.form.get("deadline") or None

    if not title:
        flash("Task title is required.", "danger")
        return redirect(f"/role/{prof.get('role_id')}")

    file_url = None
    task_file = request.files.get("task_file")
    if task_file and task_file.filename != "":
        filename = f"{gen_salt(6)}_{secure_filename(task_file.filename)}"
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        task_file.save(file_path)
        file_url = f"/static/task_files/{filename}"

    try:
        sb_admin.table("tasks").insert({
            "title": title,
            "description": description,
            "company_id": prof["company_id"],
            "assigned_to": assigned_to,
            "priority": priority,
            "deadline": deadline,
            "status": "Pending",
            "file_url": file_url
        }).execute()
    except Exception as e:
        flash("Manager task creation failed: " + str(e), "danger")
        return redirect(f"/role/{prof.get('role_id')}")

    flash("✅ Task created by manager.", "success")
    return redirect(f"/role/{prof.get('role_id')}")

# ---------------- Manager: Create Employee ----------------
@app.route("/manager/create_employee", methods=["POST"])
@login_required
def manager_create_employee():
    prof = get_profile()
    if not prof or prof.get("role") != "manager":
        return "Unauthorized", 403

    name = request.form.get("name")
    email = request.form.get("email")
    password = request.form.get("password") or gen_salt(8)
    role_id = request.form.get("role_id")
    company_id = prof["company_id"]

    if not (name and email and role_id):
        flash("Name, email and role are required.", "danger")
        return redirect(f"/role/{prof.get('role_id')}")

    try:
        created = sb_admin.auth.admin.create_user({
            "email": email,
            "password": password,
            "email_confirm": True
        })
    except Exception as e:
        flash("❌ Manager failed to create user: " + str(e), "danger")
        return redirect(f"/role/{prof.get('role_id')}")

    if not created or not created.user:
        flash("❌ Manager failed to create user.", "danger")
        return redirect(f"/role/{prof.get('role_id')}")

    user_id = created.user.id

    try:
        sb_admin.table("profiles").insert({
            "id": user_id,
            "full_name": name,
            "company_id": company_id,
            "role": "employee",   # manager can't create admins
            "role_id": role_id
        }).execute()
    except Exception as e:
        flash("Profile creation failed: " + str(e), "danger")
        try:
            sb_admin.auth.admin.delete_user(user_id)
        except Exception:
            pass
        return redirect(f"/role/{prof.get('role_id')}")

    flash(f"✅ Employee created by manager (password: {password}) — share securely.", "success")
    return redirect(f"/role/{prof.get('role_id')}")

# ---------------- Manager: Upload Completed Task File ----------------
@app.route("/manager/upload_task_file/<task_id>", methods=["POST"])
@login_required
def manager_upload_task_file(task_id):
    prof = get_profile()
    if not prof or prof.get("role") != "manager":
        return "Unauthorized", 403

    # check that this task belongs to same company and is assigned to this manager
    try:
        resp = sb_admin.table("tasks").select("*").eq("id", task_id).maybe_single().execute()
        task = resp.data
    except Exception:
        task = None

    if not task:
        flash("Task not found.", "danger")
        return redirect(f"/role/{prof.get('role_id')}")

    if task.get("company_id") != prof["company_id"]:
        flash("You cannot modify tasks from another company.", "danger")
        return redirect(f"/role/{prof.get('role_id')}")

    if str(task.get("assigned_to") or "") != str(prof.get("id") or ""):
        flash("You can only upload files for your own tasks.", "danger")
        return redirect(f"/role/{prof.get('role_id')}")

    task_file = request.files.get("task_file")
    if not task_file or task_file.filename == "":
        flash("Please choose a file to upload.", "danger")
        return redirect(f"/role/{prof.get('role_id')}")

    filename = f"{gen_salt(6)}_{secure_filename(task_file.filename)}"
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    task_file.save(file_path)
    file_url = f"/static/task_files/{filename}"

    try:
        sb_admin.table("tasks").update({
            "file_url": file_url,
            "status": "Completed"
        }).eq("id", task_id).execute()
    except Exception as e:
        flash("Failed to update task file: " + str(e), "danger")
        return redirect(f"/role/{prof.get('role_id')}")

    flash("✅ Task file uploaded.", "success")
    return redirect(f"/role/{prof.get('role_id')}")
# ------------------------- Appeal-----------------------------

@app.route("/appeal/send", methods=["POST"])
@login_required
def send_appeal():
    prof = get_profile()
    if not prof or prof.get("role_id") != 2:
        return "Unauthorized", 403

    message = request.form.get("message")
    file = request.files.get("file")

    file_url = None
    file_name = None

    if file and file.filename:
        filename = secure_filename(file.filename)
        unique = f"{gen_salt(8)}_{filename}"
        path = f"appeals/{prof['company_id']}/{unique}"

        sb_admin.storage.from_("appeals").upload(
            path,
            file.read(),
            {"content-type": file.content_type}
        )

        file_url = sb_admin.storage.from_("appeals").get_public_url(path)
        file_name = filename

    sb_admin.table("appeals").insert({
        "company_id": prof["company_id"],
        "sender_id": prof["id"],
        "sender_role": "marketing_lead",
        "message": message,
        "file_url": file_url,
        "file_name": file_name
    }).execute()

    flash("✅ Appeal sent", "success")
    return redirect(request.referrer)

@app.route("/appeal/reply/<appeal_id>", methods=["POST"])
@login_required
def reply_appeal(appeal_id):
    prof = get_profile()
    if not prof or prof.get("role") != "company_admin":
        return "Unauthorized", 403

    reply_message = request.form.get("reply_message")
    reply_file = request.files.get("reply_file")

    reply_file_url = None

    if reply_file and reply_file.filename:
        filename = secure_filename(reply_file.filename)
        unique = f"{gen_salt(8)}_{filename}"
        path = f"appeals/replies/{unique}"

        sb_admin.storage.from_("appeals").upload(
            path,
            reply_file.read(),
            {"content-type": reply_file.content_type}
        )

        reply_file_url = sb_admin.storage.from_("appeals").get_public_url(path)

    sb_admin.table("appeals").update({
        "reply_message": reply_message,
        "reply_file_url": reply_file_url,
        "status": "replied",
        "replied_at": "now()"
    }).eq("id", appeal_id).execute()

    flash("✅ Reply sent", "success")
    return redirect(url_for("admin_dashboard"))


# ---------------- Run ----------------
if __name__ == "__main__":
    app.run(debug=True)

