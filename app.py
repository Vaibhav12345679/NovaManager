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

# NEW: for dynamic role dashboards
from importlib.machinery import SourceFileLoader

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
    """
    Home page:
    - Always show index.html
    - If logged in, also fetch company name to show brand.
    """
    prof = get_profile()
    company = None

    if prof and prof.get("company_id"):
        try:
            comp_resp = (
                sb_admin
                .table("companies")
                .select("name")
                .eq("id", prof["company_id"])
                .maybe_single()
                .execute()
            )
            if comp_resp.data:
                company = comp_resp.data.get("name")
        except Exception:
            company = None

    return render_template("index.html", profile=prof, company=company)

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

        # store token
        session["access_token"] = res.session.access_token

        # 🔥 Now redirect to respective dashboard
        prof = get_profile()
        if not prof:
            # if somehow no profile, just go home
            return redirect(url_for("index"))

        role = prof.get("role")
        role_id = prof.get("role_id")

        if role == "company_admin":
            return redirect(url_for("admin_dashboard"))
        elif role == "manager":
            # manager dashboard via panel system if role_id exists
            if role_id:
                return redirect(url_for("role_dashboard", role_id=role_id))
            # fallback if no role_id set
            return redirect(url_for("employee_dashboard"))
        else:
            # normal employee
            if role_id:
                return redirect(url_for("role_dashboard", role_id=role_id))
            return redirect(url_for("employee_dashboard"))

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

# ---------------- Role-based Dynamic Dashboard (PANELS) ----------------
@app.route("/role/<role_id>")
@login_required
def role_dashboard(role_id):
    """
    Dynamic dashboard per role.

    Looks for Python files in:
      dashboard_codes/<role_id>/

    First .py file found is loaded as a module and must define:
      def render_dashboard(profile, users, tasks, roles) -> str:
          return "<html>...</html>"
    """
    prof = get_profile()
    if not prof:
        return redirect(url_for("login"))

    company_id = prof["company_id"]

    # Permissions:
    # - company_admin can view any role dashboard
    # - normal employee/manager can only view their own role_id dashboard
    if prof.get("role") != "company_admin" and str(prof.get("role_id")) != str(role_id):
        return "Unauthorized", 403

    # Real data from Supabase
    users = sb_admin.table("profiles").select("*").eq("company_id", company_id).execute().data or []
    tasks = sb_admin.table("tasks").select("*").eq("company_id", company_id).execute().data or []
    roles = sb_admin.table("roles").select("*").eq("company_id", company_id).execute().data or []

    # Folder for this role
    role_dir = os.path.join("dashboard_codes", str(role_id))
    if not os.path.isdir(role_dir):
        return f"No dashboard code uploaded for this role (folder {role_dir} not found).", 404

    # Pick the first .py file in that folder
    py_files = [f for f in os.listdir(role_dir) if f.endswith(".py")]
    if not py_files:
        return "No .py dashboard file found in this role folder.", 404

    module_path = os.path.join(role_dir, py_files[0])

    try:
        mod = SourceFileLoader(f"role_module_{role_id}", module_path).load_module()
    except Exception as e:
        return f"Error loading dashboard module: {e}", 500

    if not hasattr(mod, "render_dashboard"):
        return "Dashboard module has no render_dashboard(profile, users, tasks, roles) function", 500

    try:
        html = mod.render_dashboard(prof, users, tasks, roles)
    except Exception as e:
        return f"Error rendering dashboard: {e}", 500

    return html

# ---------------- Edit Dashboard Code (Admin only) ----------------
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

# ---------------- Create Employee ----------------
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

# ---------------- Create Task ----------------
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

# ---------------- Employee Dashboard (fallback) ----------------
@app.route("/employee")
@login_required
def employee_dashboard():
    prof = get_profile()
    if not prof:
        return redirect(url_for("login"))

    user_id = prof["id"]
    tasks_resp = sb_admin.table("tasks").select("*").eq("assigned_to", user_id).execute()
    tasks = tasks_resp.data or []
    total = len(tasks)
    completed = sum(1 for t in tasks if (t.get("status") or "").lower() == "completed")
    percent = int((completed / total) * 100) if total > 0 else 0

    return render_template("employee_dashboard.html", profile=prof, tasks=tasks, percent=percent)

# ---------------- Run ----------------
if __name__ == "__main__":
    app.run(debug=True)

