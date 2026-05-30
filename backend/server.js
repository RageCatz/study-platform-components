const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
require("dotenv").config();

const app = express();

app.use(cors({
  origin: "*",
  credentials: true
}));

app.use(express.json());

// Neon database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

// TEST ROUTE
app.get("/", (req, res) => {
  res.send("Backend is running");
});

// SIGNUP
app.post("/api/signup", async (req, res) => {
  const { username, password, name } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    await pool.query(
      "INSERT INTO users (username, password, name) VALUES ($1, $2, $3)",
      [username, hashedPassword, name]
    );

    res.json({ message: "User created" });

  } catch (err) {
    res.status(400).json({ message: "User already exists or error" });
  }
});

// LOGIN
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  const result = await pool.query(
    "SELECT * FROM users WHERE username = $1",
    [username]
  );

  const user = result.rows[0];

  if (!user) return res.status(400).json({ message: "User not found" });

  const valid = await bcrypt.compare(password, user.password);

  if (!valid) return res.status(400).json({ message: "Wrong password" });

  const token = jwt.sign({ id: user.id }, "secretkey");

  res.json({ token, user });
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});