const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const session = require("express-session");
const { Pool } = require("pg");

const app = express();

app.use(cors({
  origin: true,
  credentials: true
}));

app.use(express.json());

app.use(session({
  secret: "change-this-later",
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false // true later when using HTTPS
  }
}));

// Neon DB connection (we add real link later)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

// TEST route
app.get("/", (req, res) => {
  res.send("Backend is running 🚀");
});

// SIGNUP
app.post("/api/signup", async (req, res) => {
  const { name, username, password } = req.body;

  try {
    const hashed = await bcrypt.hash(password, 10);

    await pool.query(
      "INSERT INTO users (name, username, password) VALUES ($1, $2, $3)",
      [name, username, hashed]
    );

    res.json({ message: "Account created" });

  } catch (err) {
    res.status(500).json({ message: "Signup error" });
  }
});

// LOGIN
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE username = $1",
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ message: "User not found" });
    }

    const user = result.rows[0];

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(400).json({ message: "Wrong password" });
    }

    req.session.user = {
      id: user.id,
      name: user.name,
      username: user.username
    };

    res.json({
      message: "Login successful",
      user: req.session.user
    });

  } catch (err) {
    res.status(500).json({ message: "Login error" });
  }
});

// SESSION CHECK
app.get("/api/session", (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ message: "No session" });
  }
  res.json({ user: req.session.user });
});

// LOGOUT
app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ message: "Logged out" });
  });
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});