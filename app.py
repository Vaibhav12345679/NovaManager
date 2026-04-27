const express = require("express");
const bcrypt = require("bcrypt");
const sqlite3 = require("sqlite3").verbose();
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

// ------------------ DATABASE ------------------
const db = new sqlite3.Database("./database.db");

// ------------------ CREATE TABLES ------------------
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE,
      password TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS companies (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      admin_user_id TEXT,
      email TEXT
    )
  `);

 // 🔥 FIX OLD ROLE DATA (id → name)
db.run(`
  UPDATE profiles
  SET role = (
    SELECT LOWER(name)
    FROM roles
    WHERE roles.id = CAST(profiles.role AS INTEGER)
  )
  WHERE role NOT IN ('manager', 'company_admin', 'employee')
`);
   
  db.run(`
  CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    company_id INTEGER
   )
 `);

  db.run(`
  CREATE TABLE IF NOT EXISTS tasks (
   id INTEGER PRIMARY KEY AUTOINCREMENT,
   title TEXT,
   description TEXT,
   company_id INTEGER,
   assigned_to INTEGER,
   priority TEXT,
   deadline TEXT,
   file_url TEXT,
   status TEXT
   )
 `);
  
});

// ------------------ SIGNUP ------------------
app.post("/auth/v1/signup", async (req, res) => {
  const { email, password, company_name, admin_name } = req.body;

  if (!email || !password || !company_name || !admin_name) {
    return res.status(400).json({ error: "Missing fields" });
  }

  try {
    const hashed = await bcrypt.hash(password, 10);

    db.run(
      "INSERT INTO users (email, password) VALUES (?, ?)",
      [email, hashed],
      function (err) {
        if (err) {
          return res.status(400).json({ error: "User already exists" });
        }

        const user_id = String(this.lastID);

        // create company
        db.run(
          "INSERT INTO companies (name, admin_user_id, email) VALUES (?, ?, ?)",
          [company_name, user_id, email],
          function (err2) {
            if (err2) {
              return res.status(500).json({ error: "Company creation failed" });
            }

            const company_id = String(this.lastID);

            // create profile
            db.run(
              "INSERT INTO profiles (id, full_name, company_id, role) VALUES (?, ?, ?, ?)",
              [user_id, admin_name, company_id, "company_admin"],
              function (err3) {
                if (err3) {
                  return res.status(500).json({ error: "Profile creation failed" });
                }

                return res.json({
                  user: {
                    id: user_id,
                    email: email
                  },
                  company_id: company_id
                });
              }
            );
          }
        );
      }
    );
  } catch (e) {
    return res.status(500).json({ error: "Server error" });
  }
});

// ------------------ LOGIN ------------------
app.post("/auth/v1/token", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Missing fields" });
  }

  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
    if (err || !user) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    const valid = await bcrypt.compare(password, user.password);

    if (!valid) {
      return res.status(400).json({ error: "Invalid credentials" });
    }

    return res.json({
      access_token: String(user.id),
      user: {
        id: String(user.id),
        email: user.email
      }
    });
  });
});

// ------------------ GET USER ------------------
app.get("/auth/v1/user", (req, res) => {
  const token = req.headers.authorization?.replace("Bearer ", "");

  if (!token) {
    return res.status(401).json({ error: "No token" });
  }

  db.get("SELECT id, email FROM users WHERE id = ?", [token], (err, user) => {
    if (err || !user) {
      return res.status(401).json({ error: "Invalid token" });
    }

    return res.json({
      user: {
        id: String(user.id),
        email: user.email
      }
    });
  });
});

app.get("/debug/profile/:id", (req, res) => {
  const id = req.params.id;

  db.get(
    "SELECT * FROM profiles WHERE id = ?",
    [id],
    (err, row) => {
      if (err) {
        return res.status(500).json({ error: "DB error" });
      }

      return res.json({
        profile: row || null
      });
    }
  );
});

app.post("/roles", (req, res) => {
  const { name, company_id } = req.body;

  if (!name || !company_id) {
    return res.status(400).json({ error: "Missing fields" });
  }

  db.run(
    "INSERT INTO roles (name, company_id) VALUES (?, ?)",
    [name, company_id],
    function (err) {
      if (err) return res.status(500).json({ error: "DB error" });

      res.json({
        id: this.lastID,
        name,
        company_id
      });
    }
  );
});


app.get("/roles", (req, res) => {
  const { company_id } = req.query;

  db.all(
    "SELECT * FROM roles WHERE company_id = ?",
    [company_id],
    (err, rows) => {
      if (err) return res.status(500).json({ error: "DB error" });

      res.json(rows);
    }
  );
});


// ------------------ CREATE EMPLOYEE ------------------
app.post("/employees", async (req, res) => {
  const { full_name, email, password, role, company_id } = req.body;

  if (!full_name || !email || !role || !company_id) {
    return res.status(400).json({ error: "Missing fields" });
  }

  try {
    const finalPassword = password || Math.random().toString(36).slice(-8);
    const hashed = await bcrypt.hash(finalPassword, 10);

    db.run(
      "INSERT INTO users (email, password) VALUES (?, ?)",
      [email, hashed],
      function (err) {
        if (err) {
          return res.status(400).json({ error: "User already exists" });
        }

        const user_id = String(this.lastID);

        // 🔥 GET ROLE NAME FROM role_id
        db.get(
          "SELECT name FROM roles WHERE id = ? AND company_id = ?",
          [role, company_id],
          (errRole, row) => {

            if (errRole || !row) {
              return res.status(400).json({ error: "Invalid role" });
            }

            const roleName = row.name.toLowerCase();

            // 🔥 DEFINE SYSTEM ROLE
            let systemRole = "employee";

            if (roleName === "manager") {
              systemRole = "manager";
            } else if (roleName === "company_admin") {
              systemRole = "company_admin";
            }

            // ✅ SAVE BOTH CORRECTLY
            db.run(
              "INSERT INTO profiles (id, full_name, company_id, role, role_id) VALUES (?, ?, ?, ?, ?)",
              [user_id, full_name, company_id, systemRole, role],
              function (err2) {
                if (err2) {
                  console.log("PROFILE ERROR:", err2);
                  return res.status(500).json({ error: "Profile creation failed" });
                }

                res.json({
                  message: "Employee created",
                  user: { id: user_id, email },
                  role: systemRole,
                  role_id: role
                });
              }
            );
          }
        );
      }
    );
  } catch (e) {
    return res.status(500).json({ error: "Server error" });
  }
});


// ------------------ GET EMPLOYEES ------------------
app.get("/profiles", (req, res) => {
  const { company_id } = req.query;

  if (!company_id) {
    return res.status(400).json({ error: "Missing company_id" });
  }

  db.all(
    "SELECT id, full_name, role, role_id FROM profiles WHERE company_id = ?",
    [company_id],
    (err, rows) => {
      if (err) return res.status(500).json({ error: "DB error" });

      // ✅ FILTER ONLY EMPLOYEES (NOT ADMIN/MANAGER)
      const employees = rows.filter(r => r.role === "employee");

      res.json({ data: employees });
    }
  );
});


// ------------------ DELETE EMPLOYEE ------------------
app.delete("/employees/:id", (req, res) => {
  const user_id = req.params.id;

  db.run("DELETE FROM profiles WHERE id = ?", [user_id], function (err) {
    if (err) return res.status(500).json({ error: "Delete failed" });

    db.run("DELETE FROM users WHERE id = ?", [user_id]);

    res.json({ message: "Employee deleted" });
  });
});


// ================= TASKS =================

// CREATE TASK
app.post("/tasks", (req, res) => {
  let { title, description, company_id, assigned_to } = req.body;

  if (!title || !company_id) {
    return res.status(400).json({ error: "Missing fields" });
  }

  // normalize empty to NULL
  if (!assigned_to) assigned_to = null;

  db.run(
    "INSERT INTO tasks (title, description, company_id, assigned_to, status) VALUES (?, ?, ?, ?, ?)",
    [title, description || "", company_id, assigned_to, "Pending"],
    function (err) {
      if (err) {
        console.log("TASK CREATE ERROR:", err);
        return res.status(500).json({ error: "DB error" });
      }

      return res.json({
        id: this.lastID,
        assigned_to: assigned_to
      });
    }
  );
});


// GET TASKS (WITH ASSIGNEE NAME)
app.get("/tasks", (req, res) => {
  const { company_id, assigned_to } = req.query;

  if (!company_id) {
    return res.status(400).json({ error: "Missing company_id" });
  }

  let query = `
    SELECT 
      tasks.*,
      profiles.full_name AS assigned_name
    FROM tasks
    LEFT JOIN profiles ON tasks.assigned_to = profiles.id
    WHERE tasks.company_id = ?
  `;

  let params = [company_id];

  if (assigned_to) {
    query += " AND tasks.assigned_to = ?";
    params.push(assigned_to);
  }

  db.all(query, params, (err, rows) => {
    if (err) {
      console.log("TASK FETCH ERROR:", err);
      return res.status(500).json({ error: "DB error" });
    }

    res.json(rows);
  });
});


// DELETE TASK (SAFE)
app.delete("/tasks/:id", (req, res) => {
  db.run("DELETE FROM tasks WHERE id = ?", [req.params.id], function (err) {
    if (err) return res.status(500).json({ error: "Delete failed" });

    res.json({ success: true });
  });
});


// ------------------ START SERVER ------------------
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`🚀 API running on http://localhost:${PORT}`);
});
