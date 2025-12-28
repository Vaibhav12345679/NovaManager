def render_dashboard(profile, users, tasks, roles):
    user_id = str(profile["id"])

    # ---------------- SOCIAL MEDIA DATA (CHANGE HERE) ----------------
    social_accounts = [
        {
            "name": "Instagram",
            "url": "https://www.instagram.com/",
            "username": "tech_of_the_world.in",
            "password": "india.techoftheworld"
        },
        {
            "name": "Facebook",
            "url": "https://www.facebook.com/",
            "username": "alderady request is sent ",
            "password": "if not accepted contact contact@techoftheworld.great-site.net for resending the invitation link"
        },
        {
            "name": "X (Twitter)",
            "url": "https://x.com/",
            "username": "not yet registerd",
            "password": "india.techoftheworld"
        }
    ]
    # ----------------------------------------------------------------

    my_tasks = [
        t for t in tasks
        if str(t.get("assigned_to") or "") == user_id
    ]

    def task_card(t):
        return f"""
        <div style="background:#111827;border:1px solid #1f2937;
            border-radius:12px;padding:16px;margin-bottom:14px;color:#e5e7eb;">
            <h3>{t.get("title","Untitled Task")}</h3>
            <p style="color:#9ca3af;">{t.get("description","")}</p>

            <div style="font-size:13px;">
                <b>Priority:</b> {t.get("priority","-")} <br>
                <b>Status:</b> {t.get("status","Pending")} <br>
                <b>Deadline:</b> {t.get("deadline","Not set")}
            </div>

            <form method="POST" action="/upload_task_file" enctype="multipart/form-data" style="margin-top:10px;">
                <input type="hidden" name="task_id" value="{t.get("id")}">
                <input type="file" name="file" required>
                <button style="margin-top:6px;background:#2563eb;color:white;
                    padding:6px 14px;border-radius:8px;border:none;">
                    Upload Work
                </button>
            </form>
        </div>
        """

    tasks_html = "".join(task_card(t) for t in my_tasks) or \
        "<p style='color:#9ca3af;'>No tasks assigned.</p>"

    social_html = ""
    for s in social_accounts:
        social_html += f"""
        <div style="background:#0f172a;border:1px solid #1e293b;
            border-radius:12px;padding:16px;margin-bottom:14px;">
            
            <h3 style="color:#f9fafb;">{s["name"]}</h3>

            <a href="{s["url"]}" target="_blank"
               style="display:inline-block;margin:6px 0;
               background:#22c55e;color:black;
               padding:6px 14px;border-radius:8px;
               text-decoration:none;font-weight:600;">
               Manage
            </a>

            <div style="margin-top:10px;font-size:13px;color:#e5e7eb;">
                <b>Username:</b> {s["username"]}<br>
                <b>Password:</b> {s["password"]}
            </div>
        </div>
        """

    return f"""
    <div style="background:#020617;min-height:100vh;padding:24px;
        font-family:Inter,system-ui;">

        <h1 style="color:#f9fafb;">Marketing Lead Dashboard</h1>
        <p style="color:#9ca3af;">Welcome <b>{profile.get("full_name")}</b></p>

        <hr style="border-color:#1f2937;margin:20px 0;">

        <h2 style="color:#e5e7eb;">📣 Social Media Accounts</h2>
        {social_html}

        <hr style="border-color:#1f2937;margin:24px 0;">

        <h2 style="color:#e5e7eb;">📌 Tasks From Manager / Admin</h2>
        {tasks_html}

    </div>
    """
