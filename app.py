import os
import requests
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, flash
from functools import wraps
from werkzeug.security import gen_salt
from werkzeug.utils import secure_filename
from supabase_fake import sb, sb_admin

# ----------------- CONFIG -----------------
load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret")

app = Flask(__name__)
app.secret_key = SECRET_KEY

UPLOAD_FOLDER = os.path.join("static", "task_files")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# ----------------- HELPERS -----------------
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

        if hasattr(resp, "user") and resp.user:
            return resp.user

        if isinstance(resp, dict):
            return resp

        return None
    except:
        return None

def get_profile():
    user = get_current_user()
    if not user:
        return None

    uid = user["id"] if isinstance(user, dict) else getattr(user, "id", None)

    try:
        res = sb_admin.table("profiles").select().eq("id", uid).maybe_single().execute()
        return res.data
    except:
        return None

# ----------------- HOME -----------------
@app.route("/")
def index():
    prof = get_profile()

    if prof:
        if prof.get("role") == "company_admin":
            return redirect(url_for("admin_dashboard"))

        if prof.get("role_id"):
            return redirect(url_for("role_dashboard", role_id=prof["role_id"]))

        return redirect(url_for("employee_dashboard"))

    return render_template("index.html")

# ----------------- REGISTER -----------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        company_name = request.form.get("company_name")
        admin_name = request.form.get("admin_name")
        email = request.form.get("email")
        password = request.form.get("password")

        res = requests.post(
            "https://api.somaedgex-cloud.online/auth/v1/signup",
            json={"email": email, "password": password}
        )

        data = res.json()

        if "error" in data:
            flash(data["error"], "danger")
            return redirect(url_for("register"))

        user_id = data.get("user", {}).get("id") or email

        comp = sb_admin.table("companies").insert({
            "name": company_name,
            "admin_user_id": user_id,
            "email": email
        }).execute()

        company_id = comp.data[0].get("id") if comp.data else email

        sb_admin.table("profiles").insert({
            "id": user_id,
            "full_name": admin_name,
            "company_id": company_id,
            "role": "company_admin"
        }).execute()

        flash("Registered successfully", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

# ----------------- LOGIN -----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        res = sb.auth.sign_in_with_password({
            "email": email,
            "password": password
        })

        if not res or not res.session:
            flash("Login failed", "danger")
            return redirect(url_for("login"))

        token = res.session.access_token
        session["access_token"] = token

        sb.set_token(token)
        sb_admin.set_token(token)

        return redirect(url_for("index"))

    return render_template("login.html")

# ----------------- LOGOUT -----------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ----------------- ADMIN -----------------
@app.route("/admin")
@login_required
def admin_dashboard():
    prof = get_profile()
    if not prof or prof.get("role") != "company_admin":
        return "Unauthorized", 403

    company_id = prof["company_id"]

    users = sb_admin.table("profiles").select().eq("company_id", company_id).execute().data or []
    tasks = sb_admin.table("tasks").select().eq("company_id", company_id).execute().data or []
    roles = sb_admin.table("roles").select().eq("company_id", company_id).execute().data or []

    return render_template("admin_dashboard.html",
                           profile=prof,
                           users=users,
                           tasks=tasks,
                           roles=roles)

# ----------------- ROLE DASHBOARD -----------------
@app.route("/role/<role_id>")
@login_required
def role_dashboard(role_id):
    prof = get_profile()
    if not prof:
        return redirect(url_for("login"))

    company_id = prof["company_id"]

    users = sb_admin.table("profiles").select().eq("company_id", company_id).execute().data or []
    tasks = sb_admin.table("tasks").select().eq("company_id", company_id).execute().data or []
    roles = sb_admin.table("roles").select().eq("company_id", company_id).execute().data or []

    return render_template("role_dashboard.html",
                           profile=prof,
                           users=users,
                           tasks=tasks,
                           roles=roles)

# ----------------- CREATE TASK -----------------
@app.route("/admin/create_task", methods=["POST"])
@login_required
def create_task():
    prof = get_profile()

    title = request.form.get("title")
    description = request.form.get("description")

    sb_admin.table("tasks").insert({
        "title": title,
        "description": description,
        "company_id": prof["company_id"],
        "status": "Pending"
    }).execute()

    flash("Task created", "success")
    return redirect(url_for("admin_dashboard"))

# ----------------- EMPLOYEE -----------------
@app.route("/employee")
@login_required
def employee_dashboard():
    prof = get_profile()

    tasks = sb_admin.table("tasks").select().execute().data or []

    return render_template("employee_dashboard.html",
                           profile=prof,
                           tasks=tasks)

# ----------------- REPORTS (FIXED YOUR ERROR) -----------------
@app.route("/admin/reports")
@login_required
def reports_page():
    prof = get_profile()
    if not prof or prof.get("role") != "company_admin":
        return "Unauthorized", 403

    company_id = prof["company_id"]

    tasks = sb_admin.table("tasks").select().eq("company_id", company_id).execute().data or []

    total = len(tasks)
    completed = sum(1 for t in tasks if (t.get("status") or "").lower() == "completed")
    pending = total - completed

    return render_template("reports.html",
                           total=total,
                           completed=completed,
                           pending=pending)

# ----------------- RUN -----------------
if __name__ == "__main__":
    app.run(debug=True)
