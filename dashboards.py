from flask import Flask, render_template, request, redirect, url_for, session, flash
from supabase import create_client, Client
import os

app = Flask(__name__)
app.secret_key = "supersecretkey"  # replace later with env

# --- Supabase Setup ---
url = os.environ.get("SUPABASE_URL")
key = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(url, key)


# 🔹 Update Task Route
@app.route("/update_task/<int:task_id>", methods=["POST"])
def update_task(task_id):
    if "user_id" not in session:
        flash("Please log in first.", "danger")
        return redirect(url_for("login"))

    new_status = request.form.get("status")

    # Update Supabase task
    supabase.table("tasks").update({"status": new_status}).eq("id", task_id).execute()

    flash("Task updated successfully!", "success")
    return redirect(url_for("employee_dashboard"))
