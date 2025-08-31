import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, flash
from supabase import create_client, Client
from functools import wraps
from werkzeug.security import gen_salt
from werkzeug.utils import secure_filename

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
        if role == "company_admin":
            return redirect(url_for("admin_dashboard"))
        elif prof.get("role_id"):  # custom role
            role_info = sb_admin.table("roles").select("*").eq("id", prof["role_id"]).maybe_single().execute()
            if role_info.data:
                return redirect(role_info.data["dashboard_route"])
        else:
            return redirect(url_for("employee_dashboard"))
    return render_template("index.html")

# --------- Register/Login/Logout ---------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        company_name = request.form.get("company_name")
        admin_name = request.form.get("admin_name")
        email = request.form.get("email")
        password = request.form.get("password")

        try:
            signup = sb.auth.sign_up({"email": email, "password": password})
        except Exception as e:
            flash("Sign up error: " + str(e), "danger")
            return redirect(url_for("register"))

        user = signup.user if signup and signup.user else None
        if not user:
            flash("Signup failed.", "danger")
            return redirect(url_for("register"))

        user_id = user.id
        comp = sb_admin.table("companies").insert({
            "name": company_name,
            "admin_user_id": user_id,
            "email": email
        }).execute()
        if not comp.data:
            flash("Company creation failed.", "danger")
            return redirect(url_for("register"))
        company_id = comp.data[0]["id"]

        sb_admin.table("profiles").insert({
            "id": user_id,
            "full_name": admin_name,
            "company_id": company_id,
            "role": "company_admin"
        }).execute()

        flash("Registered. Please login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        try:
            res = sb.auth.sign_in_with_password({"email": email, "password": password})
        except Exception as e:
            flash("❌ Login failed: " + str(e), "danger")
            return redirect(url_for("login"))

        if not res or not res.session:
            flash("❌ Login failed.", "danger")
            return redirect(url_for("login"))

        session["access_token"] = res.session.access_token
        return redirect(url_for("index"))

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# --------- Admin Dashboard ---------
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

# --------- Create Role ---------
@app.route("/admin/create_role", methods=["POST"])
@login_required
def create_role():
    prof = get_profile()
    if not prof or prof.get("role") != "company_admin":
        return "Unauthorized", 403

    role_name = request.form.get("role_name")
    dashboard_route = request.form.get("dashboard_route")
    sb_admin.table("roles").insert({
        "company_id": prof["company_id"],
        "name": role_name,
        "dashboard_route": dashboard_route
    }).execute()
    flash(f"✅ Role '{role_name}' created.", "success")
    return redirect(url_for("admin_dashboard"))

# --------- Create Employee with Role ---------
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

# --------- Task Creation with File Upload ---------
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

    # Handle file upload
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

# --------- Reports Page ---------
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

# --------- Manager/Employee Dashboards ---------
@app.route("/manager")
@login_required
def manager_dashboard():
    prof = get_profile()
    if not prof or prof.get("role") != "manager":
        return "Unauthorized", 403

    company_id = prof["company_id"]
    users_resp = sb_admin.table("profiles").select("*").eq("company_id", company_id).execute()
    tasks_resp = sb_admin.table("tasks").select("*").eq("company_id", company_id).execute()

    return render_template("manager_dashboard.html",
                           profile=prof,
                           users=users_resp.data or [],
                           tasks=tasks_resp.data or [])

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

# --------- Update Task Status ---------
@app.route("/update_task/<task_id>", methods=["POST"])
@login_required
def update_task(task_id):
    prof = get_profile()
    if not prof:
        return redirect(url_for("login"))

    status = request.form.get("status")
    resp = sb_admin.table("tasks").select("*").eq("id", task_id).maybe_single().execute()
    task = resp.data
    if not task:
        flash("❌ Task not found.", "danger")
        return redirect(url_for("employee_dashboard"))

    if task.get("assigned_to") != prof["id"]:
        flash("❌ Unauthorized.", "danger")
        return redirect(url_for("employee_dashboard"))

    sb_admin.table("tasks").update({"status": status}).eq("id", task_id).execute()
    flash("✅ Task updated.", "success")
    return redirect(url_for("employee_dashboard"))

# --------- Company Tasks (all) ---------
@app.route("/tasks")
@login_required
def tasks_page():
    prof = get_profile()
    if not prof:
        return redirect(url_for("login"))

    tasks_resp = sb_admin.table("tasks").select("*").eq("company_id", prof["company_id"]).execute()
    users_resp = sb_admin.table("profiles").select("*").eq("company_id", prof["company_id"]).execute()
    users_dict = {u["id"]: u["full_name"] for u in (users_resp.data or [])}

    return render_template("tasks.html",
                           tasks=tasks_resp.data or [],
                           profile=prof,
                           users_dict=users_dict)



# ----------------- Run -----------------
if __name__ == "__main__":
    app.run(debug=True)
