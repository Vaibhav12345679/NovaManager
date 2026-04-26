import os
import requests
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, flash
from functools import wraps
from supabase_fake import sb_admin

# ---------------- CONFIG ----------------
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret")

# ---------------- HELPERS ----------------
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
    return {"id": token}  # token = user_id

def get_profile():
    user = get_current_user()
    if not user:
        return None

    uid = user["id"]

    try:
        res = sb_admin.table("profiles").select("*").eq("id", uid).maybe_single().execute()
        return res.data
    except Exception as e:
        print("PROFILE ERROR:", e)
        return None

# ---------------- HOME ----------------
@app.route("/")
def index():
    prof = get_profile()

    if prof:
        if prof.get("role") == "company_admin":
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("employee_dashboard"))

    return render_template("index.html")

# ---------------- REGISTER ----------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        company_name = request.form.get("company_name")
        admin_name = request.form.get("admin_name")
        email = request.form.get("email")
        password = request.form.get("password")

        if not all([company_name, admin_name, email, password]):
            flash("All fields are required", "danger")
            return redirect(url_for("register"))

        try:
            res = requests.post(
                "https://api.somaedgex-cloud.online/auth/v1/signup",
                json={
                    "email": email,
                    "password": password,
                    "company_name": company_name,
                    "admin_name": admin_name
                }
            )
            data = res.json()
        except Exception as e:
            flash("API error: " + str(e), "danger")
            return redirect(url_for("register"))

        if "error" in data:
            flash(data["error"], "danger")
            return redirect(url_for("register"))

        user_id = data.get("user", {}).get("id")
        if not user_id:
            flash("Signup failed", "danger")
            return redirect(url_for("register"))

        # create company
        comp = sb_admin.table("companies").insert({
            "name": company_name,
            "admin_user_id": user_id,
            "email": email
        }).execute()

        if not comp.data:
            flash("Company creation failed", "danger")
            return redirect(url_for("register"))

        company_id = comp.data[0]["id"]

        # create profile
        sb_admin.table("profiles").insert({
            "id": user_id,
            "full_name": admin_name,
            "company_id": company_id,
            "role": "company_admin"
        }).execute()

        flash("Registered successfully", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

# ---------------- LOGIN ----------------
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
        except Exception as e:
            flash("API error: " + str(e), "danger")
            return redirect(url_for("login"))

        if "error" in data:
            flash(data["error"], "danger")
            return redirect(url_for("login"))

        session["access_token"] = data.get("access_token")

        return redirect(url_for("index"))

    return render_template("login.html")

# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------------- ADMIN ----------------
@app.route("/admin")
@login_required
def admin_dashboard():
    prof = get_profile()
    if not prof or prof.get("role") != "company_admin":
        return "Unauthorized", 403

    company_id = prof["company_id"]

    users = sb_admin.table("profiles").select("*").eq("company_id", company_id).execute().data or []
    tasks = sb_admin.table("tasks").select("*").eq("company_id", company_id).execute().data or []
    roles = sb_admin.table("roles").select("*").eq("company_id", company_id).execute().data or []

    return render_template("admin_dashboard.html",
                           profile=prof,
                           users=users,
                           tasks=tasks,
                           roles=roles)

# ---------------- EMPLOYEE ----------------
@app.route("/employee")
@login_required
def employee_dashboard():
    prof = get_profile()
    if not prof:
        return redirect(url_for("login"))

    tasks = sb_admin.table("tasks").select("*").eq("company_id", prof["company_id"]).execute().data or []

    return render_template("employee_dashboard.html",
                           profile=prof,
                           tasks=tasks)

# ---------------- REPORTS ----------------
@app.route("/admin/reports")
@login_required
def reports_page():
    prof = get_profile()
    if not prof or prof.get("role") != "company_admin":
        return "Unauthorized", 403

    company_id = prof["company_id"]
    tasks = sb_admin.table("tasks").select("*").eq("company_id", company_id).execute().data or []

    total = len(tasks)
    completed = sum(1 for t in tasks if (t.get("status") or "").lower() == "completed")
    pending = total - completed

    return render_template("reports.html",
                           total=total,
                           completed=completed,
                           pending=pending)

# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True)
