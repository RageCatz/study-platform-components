const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const cookieParser = require("cookie-parser");
require("dotenv").config();

const app = express();

app.use(cors({
  origin: true,
  credentials: true
}));

app.use(express.json());
app.use(cookieParser());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

const JWT_SECRET = "secretkey";

// TEST ROUTE
app.get("/", (req, res) => {
  res.send("Backend is running");
});

// SIGNUP
app.post("/api/signup", async (req, res) => {
  const { username, password, name, country, year, remember } = req.body;

  if (!username || !password || !name) {
    return res.status(400).json({ message: "Missing fields" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    // Create the user
    await pool.query(
      "INSERT INTO users (username, password, name, country, year) VALUES ($1, $2, $3, $4, $5)",
      [username, hashedPassword, name, country, year]
    );

    // AUTO-LOGIN: Create token and set cookie immediately after signup
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, {
      expiresIn: remember ? "7d" : "1d"
    });

    res.cookie("token", token, {
      httpOnly: true,
      sameSite: "none",
      secure: true,
      maxAge: remember ? 7 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000,
      path: "/"
    });

    res.json({ 
      message: "User created", 
      redirect: "index.html"
    });

  } catch (err) {
    console.error(err);
    res.status(400).json({ message: "User already exists or error" });
  }
});

// LOGIN
app.post("/api/login", async (req, res) => {
  const { username, password, remember } = req.body;

  const result = await pool.query(
    "SELECT * FROM users WHERE username = $1",
    [username]
  );

  const user = result.rows[0];

  if (!user) return res.status(400).json({ message: "User not found" });

  const valid = await bcrypt.compare(password, user.password);

  if (!valid) return res.status(400).json({ message: "Wrong password" });

  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, {
    expiresIn: remember ? "7d" : "1d"
  });

  res.cookie("token", token, {
    httpOnly: true,
    sameSite: "none",
    secure: true,
    maxAge: remember ? 7 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000,
    path: "/"
  });

  res.json({ 
    token, 
    user: { 
      username: user.username, 
      name: user.name 
    },
    redirect: "index.html"
  });
});

// SESSION
app.get("/api/session", async (req, res) => {
  const token = req.cookies.token || req.headers.authorization?.replace("Bearer ", "");

  if (!token) {
    return res.status(401).json({ message: "No session" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const result = await pool.query(
      "SELECT id, username, name, country, year FROM users WHERE id = $1",
      [decoded.id]
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }

    res.json({ user });
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
});

// LOGOUT
app.post("/api/logout", (req, res) => {
  res.clearCookie("token", { path: "/" });
  res.json({ message: "Logged out" });
});

// USER DATA
app.get("/api/user-data", async (req, res) => {
  const token = req.cookies.token || req.headers.authorization?.replace("Bearer ", "");

  if (!token) {
    return res.status(401).json({ message: "Not authenticated" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const data = {
      tasks: [
        { name: "Math homework", status: "pending", priority: "high", dueDate: "2025-01-20" },
        { name: "History essay", status: "in progress", priority: "medium", dueDate: "2025-01-22" }
      ],
      progress: {
        focusMinutesToday: 45,
        totalSessions: 12
      }
    };

    res.json({ data });
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});