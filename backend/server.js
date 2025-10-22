const express = require("express");
const path = require("path");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "../frontend")));

const SECRET_KEY = "your_secret_key"; // replace with env variable in production
const dbPath = path.join(__dirname, "todo.db");
let db = null;

// Initialize DB
const initializeDBAndServer = async () => {
  try {
    db = await open({ filename: dbPath, driver: sqlite3.Database });

    await db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
      );
    `);

    await db.exec(`
      CREATE TABLE IF NOT EXISTS todo (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        text TEXT NOT NULL,
        time TEXT,
        isChecked INTEGER DEFAULT 0,
        userId INTEGER,
        FOREIGN KEY(userId) REFERENCES users(id)
      );
    `);

    app.listen(3000, () => console.log("✅ Server running at http://localhost:3000"));
  } catch (e) {
    console.error("DB Error:", e.message);
    process.exit(1);
  }
};

initializeDBAndServer();

// Auth routes
app.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: "All fields required" });

    const hashedPassword = await bcrypt.hash(password, 10);
    await db.run("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", [name, email, hashedPassword]);
    res.json({ message: "Signup successful" });
  } catch (e) {
    if (e.message.includes("UNIQUE constraint failed")) res.status(400).json({ error: "Email already exists" });
    else res.status(500).json({ error: e.message });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await db.get("SELECT * FROM users WHERE email = ?", [email]);
    if (!user) return res.status(400).json({ error: "Invalid credentials" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: "Invalid credentials" });

    const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: "1h" });
    res.json({ token, name: user.name });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Todos (protected)
app.get("/todos/", authenticateToken, async (req, res) => {
  try {
    const todos = await db.all("SELECT * FROM todo WHERE userId = ? ORDER BY id DESC", [req.user.id]);
    res.json(todos.map(t => ({ ...t, isChecked: Boolean(t.isChecked) })));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/todos/", authenticateToken, async (req, res) => {
  try {
    const { text, time, isChecked } = req.body;
    const result = await db.run("INSERT INTO todo (text, time, isChecked, userId) VALUES (?, ?, ?, ?)",
      [text, time || null, isChecked ? 1 : 0, req.user.id]);
    res.json({ id: result.lastID });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put("/todos/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { isChecked, text, time } = req.body;
    if (typeof isChecked !== "undefined") await db.run("UPDATE todo SET isChecked=? WHERE id=? AND userId=?", [isChecked ? 1 : 0, id, req.user.id]);
    if (typeof text !== "undefined") await db.run("UPDATE todo SET text=? WHERE id=? AND userId=?", [text, id, req.user.id]);
    if (typeof time !== "undefined") await db.run("UPDATE todo SET time=? WHERE id=? AND userId=?", [time, id, req.user.id]);
    res.json({ message: "Updated" });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete("/todos/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    await db.run("DELETE FROM todo WHERE id=? AND userId=?", [id, req.user.id]);
    res.json({ message: "Deleted" });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Serve frontend
// Serve frontend for all unmatched routes
app.use((req, res) => {
  res.sendFile(path.join(__dirname, "../frontend/index.html"));
});

