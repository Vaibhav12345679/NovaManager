import os
import requests
import importlib.util
import chardet

from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, flash
from functools import wraps
from werkzeug.security import gen_salt
from werkzeug.utils import secure_filename
from postgrest.exceptions import APIError

# ── Custom backend ──────────────────────────────────────────────────────────
from supabase_fake import supabase as sb
sb_admin = sb

API_URL = "https://api.somaedgex-cloud.online"

# ── App setup ────────────────────────────────────────────────────────────────
load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret")

app = Flask(__name__)
app.secret_key = SECRET_KEY

# ── File upload config ───────────────────────────────────────────────────────
UPLOAD_FOLDER = os.path.join("static", "task_files")
ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "png", "jpg", "jpeg"}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ── Auth helpers ─────────────────────────────────────────────────────────────
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


# ── Routes ───────────────────────────────────────────────────────────────────
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


# ── Register ─────────────────────────────────────────────────────────────────
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        company_name = request.form.get("company_name")
        admin_name   = request.form.get("admin_name")
        email        = request.form.get("email")
        password     = request.form.get("password")

        if not (company_name and admin_name and email and password):
            flash("All fields are required.", "danger")
            return redirect(url_for("register"))

        # 1) Create auth user via custom API ──────────────────────────────────
        try:
            resp = requests.post(
                f"{API_URL}/auth/v1/signup",
                json={"email": email, "password": password, "email_confirm": True},
                timeout=10,
            )
            data = resp.json()
        except Exception as e:
            flash("Sign up request failed: " + str(e), "danger")
            return redirect(url_for("register"))

        if "error" in data or resp.status_code >= 400:
            msg = data.get("error_description") or data.get("error") or "Unknown error"
            if "already registered" in msg.lower() or "already exists" in msg.lower():
                flash("An account with this email already exists. Please log in.", "warning")
                return redirect(url_for("login"))
            flash("Sign up error: " + msg, "danger")
            return redirect(url_for("register"))

        user_id = (data.get("user") or {}).get("id")
        if not user_id:
            flash("Signup failed (no user ID returned).", "danger")
            return redirect(url_for("register"))

        # 2) Insert company ────────────────────────────────────────────────────
        try:
            comp = sb_admin.table("companies").insert({
                "name": company_name,
                "admin_user_id": user_id,
                "email": email,
            }).execute()
        except APIError as e:
            if e.code == "23505":
                flash("A company with this email already exists. Please log in.", "warning")
                return redirect(url_for("login"))
            flash(f"Company creation failed: {e.message}", "danger")
            return redirect(url_for("register"))
        except Exception as e:
            flash("Company creation failed: " + str(e), "danger")
            return redirect(url_for("register"))

        # Safe extraction – handle list or dict response
        comp_data = getattr(comp, "data", comp) or []
        company   = comp_data[0] if isinstance(comp_data, list) and comp_data else comp_data
        company_id = (company.get("id") if isinstance(company, dict) else None) or "temp-id"

        # 3) Create admin profile ──────────────────────────────────────────────
        try:
            sb_admin.table("profiles").insert({
                "id":         user_id,
                "full_name":  admin_name,
                "company_id": company_id,
                "role":       "company_admin",
            }).execute()
        except Exception as e:
            flash("Profile creation failed: " + str(e), "danger")
            return redirect(url_for("register"))

        flash("Registered successfully. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


# ── Login ─────────────────────────────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email    = request.form.get("email")
        password = request.form.get("password")

        if not (email and password):
            flash("Email and password are required.", "danger")
            return redirect(url_for("login"))

        try:
            res = sb.auth.sign_in_with_password({"email": email, "password": password})
        except Exception as e:
            flash("❌ Login failed: " + str(e), "danger")
            return redirect(url_for("login"))

        if not res or not res.session:
            flash("❌ Login failed. Please check your email and password.", "danger")
            return redirect(url_for("login"))

        token = res.session.access_token
        session["access_token"] = token
        sb.set_token(token)

        return redirect(url_for("index"))

    return render_template("login.html")


# ── Logout ────────────────────────────────────────────────────────────────────
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ── Admin dashboard ───────────────────────────────────────────────────────────
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
        roles=roles_resp.data or [],
    )


# ── Role dashboard ────────────────────────────────────────────────────────────
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

    company_id = prof["company_id"]

    users = sb_admin.table("profiles").select("*").eq("company_id", company_id).execute().data or []
    tasks = sb_admin.table("tasks").select("*").eq("company_id", company_id).execute().data or []
    roles = sb_admin.table("roles").select("*").eq("company_id", company_id).execute().data or []

    # Try to load custom role dashboard renderer
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
            except Exception as e:
                flash(f"Dashboard render error: {e}", "danger")

    # Fallback → generic employee view
    if html is None:
        user_tasks = [t for t in tasks if str(t.get("assigned_to")) == str(prof["id"])]
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


# ── Edit dashboard (admin) ────────────────────────────────────────────────────
@app.route("/admin/edit_dashboard/<role_id>", methods=["GET", "POST"])
@login_required
def edit_dashboard(role_id):
    prof = get_profile()
    if not prof or prof.get("role") != "company_admin":
        return "Unauthorized", 403

    role_resp = sb_admin.table("roles").select("*").eq("id", role_id).maybe_single().execute()
    role = role_resp.data
    if not role:
        return "Role not found", 404

    role_dir = os.path.join("dashboard_codes", role_id)
    os.makedirs(role_dir, exist_ok=True)
    files = os.listdir(role_dir)

    if request.method == "POST":
        current_file = request.form.get("current_file") or (files[0] if files else None)

        if "new_file" in request.files:
            uploaded = request.files["new_file"]
            if uploaded.filename:
                filename     = secure_filename(uploaded.filename)
                current_file = filename
                uploaded.save(os.path.join(role_dir, filename))
                flash(f"✅ Uploaded {filename}", "success")

        if "file_content" in request.form and current_file:
            with open(os.path.join(role_dir, current_file), "w", encoding="utf-8") as f:
                f.write(request.form["file_content"])
            flash(f"✅ Saved {current_file}", "success")
            return redirect(url_for("edit_dashboard", role_id=role_id, file=current_file))
    else:
        current_file = request.args.get("file") or (files[0] if files else None)

    file_content = ""
    if current_file:
        try:
            raw          = open(os.path.join(role_dir, current_file), "rb").read()
            detected     = chardet.detect(raw)
            file_content = raw.decode(detected["encoding"] or "utf-8")
        except Exception as e:
            file_content = f"Cannot read file: {e}"

    return render_template(
        "edit_dashboard_multi.html",
        role=role,
        files=files,
        current_file=current_file,
        file_content=file_content,
    )


# ── Create role ───────────────────────────────────────────────────────────────
@app.route("/admin/create_role", methods=["POST"])
@login_required
def create_role():
    prof = get_profile()
    if not prof or prof.get("role") != "company_admin":
        return "Unauthorized", 403

    role_name = request.form.get("role_name")
    sb_admin.table("roles").insert({
        "company_id": prof["company_id"],
        "name":       role_name,
    }).execute()
    flash(f"✅ Role '{role_name}' created.", "success")
    return redirect(url_for("admin_dashboard"))


# ── Create employee (admin) ───────────────────────────────────────────────────
@app.route("/admin/create_employee", methods=["POST"])
@login_required
def create_employee():
    prof = get_profile()
    if not prof or prof.get("role") != "company_admin":
        return "Unauthorized", 403

    name       = request.form.get("name")
    email      = request.form.get("email")
    password   = request.form.get("password") or gen_salt(8)
    role_id    = request.form.get("role_id")
    company_id = prof["company_id"]

    # Create user via custom API
    try:
        resp = requests.post(
            f"{API_URL}/auth/v1/signup",
            json={"email": email, "password": password, "email_confirm": True},
            timeout=10,
        )
        data = resp.json()
    except Exception as e:
        flash("❌ Failed to create user: " + str(e), "danger")
        return redirect(url_for("admin_dashboard"))

    if "error" in data or resp.status_code >= 400:
        msg = data.get("error_description") or data.get("error") or "Unknown error"
        flash("❌ Failed to create user: " + msg, "danger")
        return redirect(url_for("admin_dashboard"))

    user_id = (data.get("user") or {}).get("id")
    if not user_id:
        flash("❌ Failed to create user (no ID returned).", "danger")
        return redirect(url_for("admin_dashboard"))

    sb_admin.table("profiles").insert({
        "id":         user_id,
        "full_name":  name,
        "company_id": company_id,
        "role":       "employee",
        "role_id":    role_id,
    }).execute()

    flash(f"✅ Employee created (password: {password}) — share securely.", "success")
    return redirect(url_for("admin_dashboard"))


# ── Delete employee (admin) ───────────────────────────────────────────────────
@app.route("/admin/delete_employee/<user_id>", methods=["POST"])
@login_required
def admin_delete_employee(user_id):
    prof = get_profile()
    if not prof or prof.get("role") != "company_admin":
        return "Unauthorized", 403

    company_id = prof["company_id"]

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

    # Delete profile
    try:
        sb_admin.table("profiles").delete().eq("id", user_id).execute()
    except Exception as e:
        flash("Failed to delete profile: " + str(e), "danger")
        return redirect(url_for("admin_dashboard"))

    # Delete auth user via custom API (best-effort)
    try:
        requests.delete(
            f"{API_URL}/auth/v1/admin/users/{user_id}",
            headers={"Authorization": f"Bearer {session.get('access_token')}"},
            timeout=10,
        )
    except Exception:
        flash("Profile removed but auth user could not be deleted.", "warning")

    # Unassign tasks (best-effort)
    try:
        sb_admin.table("tasks").update({"assigned_to": None}).eq("assigned_to", user_id).execute()
    except Exception:
        pass

    flash("✅ Employee deleted.", "success")
    return redirect(url_for("admin_dashboard"))


# ── Employee dashboard (fallback) ─────────────────────────────────────────────
@app.route("/dashboard")
@login_required
def employee_dashboard():
    prof = get_profile()
    if not prof:
        return redirect(url_for("login"))

    company_id = prof["company_id"]
    all_tasks  = sb_admin.table("tasks").select("*").eq("company_id", company_id).execute().data or []
    user_tasks = [t for t in all_tasks if str(t.get("assigned_to")) == str(prof["id"])]
    total      = len(user_tasks)
    completed  = sum(1 for t in user_tasks if (t.get("status") or "").lower() == "completed")
    percent    = int((completed / total) * 100) if total else 0

    return render_template(
        "employee_dashboard.html",
        profile=prof,
        tasks=user_tasks,
        percent=percent,
    )


if __name__ == "__main__":
    app.run(debug=True)
