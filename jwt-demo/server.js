const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const path = require("path");

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const SECRET_KEY = process.env.SECRET_KEY || "dev_secret_change_me"; // set SECRET_KEY in real apps

// --- Fake "database" of users ---
// Password for all seeded users is: "password123"
let nextUserId = 3;
const users = [
  {
    id: 1,
    username: "testuser",
    role: "user",
    passwordHash: bcrypt.hashSync("password123", 8),
  },
  {
    id: 2,
    username: "admin",
    role: "admin",
    passwordHash: bcrypt.hashSync("password123", 8),
  },
];

// --- Fake "database" of notes, each owned by one user ---
let nextNoteId = 3;
const notes = [
  { id: 1, userId: 1, text: "testuser's private note" },
  { id: 2, userId: 2, text: "admin's private note" },
];

// --- REGISTER route: creates a new user, so you can log in as several people ---
app.post("/register", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password are required" });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters" });
  }
  if (users.some((u) => u.username === username)) {
    return res.status(409).json({ error: "That username is already taken" });
  }

  const user = {
    id: nextUserId++,
    username,
    role: "user", // new signups are never admins
    passwordHash: bcrypt.hashSync(password, 8),
  };
  users.push(user);

  res.status(201).json({ token: signToken(user) });
});

// --- LOGIN route: checks credentials, returns a real JWT ---
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  const user = users.find((u) => u.username === username);
  if (!user) {
    return res.status(401).json({ error: "Invalid username or password" });
  }

  const passwordMatches = bcrypt.compareSync(password, user.passwordHash);
  if (!passwordMatches) {
    return res.status(401).json({ error: "Invalid username or password" });
  }

  res.json({ token: signToken(user) });
});

// The token carries who you are AND what you're allowed to do (role).
function signToken(user) {
  return jwt.sign(
    { userId: user.id, username: user.username, role: user.role },
    SECRET_KEY,
    { expiresIn: "1h" }
  );
}

// --- Middleware: verifies the JWT sent in the Authorization header ---
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"]; // format: "Bearer <token>"
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "No token provided" });
  }

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: "Invalid or expired token" });
    }
    req.user = decoded;
    next();
  });
}

// --- Middleware: the authorization step — authenticated isn't the same as allowed ---
function requireRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).json({ error: `Requires the "${role}" role` });
    }
    next();
  };
}

// --- PROTECTED route: only accessible with a valid JWT ---
app.get("/profile", authenticateToken, (req, res) => {
  res.json({
    message: `Welcome, ${req.user.username}! This is protected data.`,
    userId: req.user.userId,
    role: req.user.role,
  });
});

// --- PER-USER data: the same URL returns different rows depending on the token ---
app.get("/notes", authenticateToken, (req, res) => {
  res.json(notes.filter((n) => n.userId === req.user.userId));
});

app.post("/notes", authenticateToken, (req, res) => {
  const { text } = req.body;
  if (!text) {
    return res.status(400).json({ error: "Note text is required" });
  }

  const note = { id: nextNoteId++, userId: req.user.userId, text };
  notes.push(note);
  res.status(201).json(note);
});

app.delete("/notes/:id", authenticateToken, (req, res) => {
  const note = notes.find((n) => n.id === Number(req.params.id));

  // Note the ownership check: a valid token for user A must not delete user B's note.
  if (!note || note.userId !== req.user.userId) {
    return res.status(404).json({ error: "Note not found" });
  }

  notes.splice(notes.indexOf(note), 1);
  res.json({ deleted: note.id });
});

// --- ADMIN-ONLY route: a valid token is not enough, the role has to match ---
app.get("/admin/users", authenticateToken, requireRole("admin"), (req, res) => {
  res.json(
    users.map((u) => ({
      id: u.id,
      username: u.username,
      role: u.role,
      noteCount: notes.filter((n) => n.userId === u.id).length,
    }))
  );
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
  console.log(`Log in as testuser / password123  (regular user)`);
  console.log(`Log in as admin    / password123  (admin)`);
});
