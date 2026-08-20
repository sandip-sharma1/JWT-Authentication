const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const path = require("path");

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// Two different secrets: a leaked access secret must not let anyone mint refresh tokens.
const ACCESS_SECRET = process.env.ACCESS_SECRET || "dev_access_secret_change_me";
const REFRESH_SECRET = process.env.REFRESH_SECRET || "dev_refresh_secret_change_me";

// Short access token, long refresh token. That trade-off is the whole point:
// the access token is sent on every request (more exposure) so it must expire fast;
// the refresh token is sent only to /refresh (less exposure) so it can live longer.
const ACCESS_TTL = "2m";
const REFRESH_TTL = "7d";

// --- Fake "database" of users ---
// Password for all seeded users is: "password123"
let nextUserId = 3;
const users = [
  { id: 1, username: "testuser", role: "user", passwordHash: bcrypt.hashSync("password123", 8) },
  { id: 2, username: "admin", role: "admin", passwordHash: bcrypt.hashSync("password123", 8) },
];

// --- Fake "database" of notes, each owned by one user ---
let nextNoteId = 3;
const notes = [
  { id: 1, userId: 1, text: "testuser's private note" },
  { id: 2, userId: 2, text: "admin's private note" },
];

// --- Refresh token store ---
// Access tokens are stateless (that's why they can't be revoked), but refresh
// tokens ARE tracked here, which is what makes real logout and revocation possible.
const refreshTokens = new Map(); // jti -> { userId, used, family }

function issueTokens(user, family = crypto.randomUUID()) {
  const accessToken = jwt.sign(
    { userId: user.id, username: user.username, role: user.role },
    ACCESS_SECRET,
    { expiresIn: ACCESS_TTL }
  );

  // jti = a unique id for this token, so we can look it up and revoke it later.
  const jti = crypto.randomUUID();
  const refreshToken = jwt.sign({ userId: user.id, jti, family }, REFRESH_SECRET, {
    expiresIn: REFRESH_TTL,
  });
  refreshTokens.set(jti, { userId: user.id, used: false, family });

  return { accessToken, refreshToken };
}

function publicUser(user) {
  return { id: user.id, username: user.username, role: user.role };
}

// --- REGISTER ---
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

  res.status(201).json({ ...issueTokens(user), user: publicUser(user) });
});

// --- LOGIN ---
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

  res.json({ ...issueTokens(user), user: publicUser(user) });
});

// --- REFRESH: trade a valid refresh token for a fresh pair ---
app.post("/refresh", (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    return res.status(401).json({ error: "No refresh token provided" });
  }

  let payload;
  try {
    payload = jwt.verify(refreshToken, REFRESH_SECRET);
  } catch {
    return res.status(403).json({ error: "Invalid or expired refresh token" });
  }

  const stored = refreshTokens.get(payload.jti);
  if (!stored) {
    return res.status(403).json({ error: "Refresh token has been revoked" });
  }

  // Reuse detection: a rotated token should never come back. If it does, the
  // token was probably stolen, so we kill every token in that family at once.
  if (stored.used) {
    for (const [jti, entry] of refreshTokens) {
      if (entry.family === stored.family) refreshTokens.delete(jti);
    }
    return res.status(403).json({ error: "Refresh token reuse detected — all sessions revoked" });
  }

  // Rotation: each refresh burns the old token and issues a new one.
  stored.used = true;

  const user = users.find((u) => u.id === payload.userId);
  if (!user) {
    return res.status(403).json({ error: "User no longer exists" });
  }

  res.json({ ...issueTokens(user, stored.family), user: publicUser(user) });
});

// --- LOGOUT: revoke the refresh token server-side ---
// The access token stays valid until it expires — that is the documented
// trade-off of stateless tokens, and why access tokens are kept short.
app.post("/logout", (req, res) => {
  const { refreshToken } = req.body;

  if (refreshToken) {
    try {
      const payload = jwt.verify(refreshToken, REFRESH_SECRET);
      refreshTokens.delete(payload.jti);
    } catch {
      // Already invalid — nothing to revoke.
    }
  }

  res.json({ ok: true });
});

// --- Middleware: verifies the access token from the Authorization header ---
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"]; // format: "Bearer <token>"
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "No token provided" });
  }

  jwt.verify(token, ACCESS_SECRET, (err, decoded) => {
    if (err) {
      // The client watches for this exact code to know it should try /refresh.
      const expired = err.name === "TokenExpiredError";
      return res.status(401).json({
        error: expired ? "Access token expired" : "Invalid token",
        code: expired ? "TOKEN_EXPIRED" : "TOKEN_INVALID",
      });
    }
    req.user = decoded;
    next();
  });
}

// --- Middleware: authenticated isn't the same as allowed ---
function requireRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).json({ error: `Requires the "${role}" role` });
    }
    next();
  };
}

// --- PROTECTED ---
app.get("/profile", authenticateToken, (req, res) => {
  res.json({
    message: `Welcome, ${req.user.username}! This is protected data.`,
    userId: req.user.userId,
    role: req.user.role,
  });
});

// --- PER-USER data: same URL, different rows depending on the token ---
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

  // A valid token proves who you are, not what you own.
  if (!note || note.userId !== req.user.userId) {
    return res.status(404).json({ error: "Note not found" });
  }

  notes.splice(notes.indexOf(note), 1);
  res.json({ deleted: note.id });
});

// --- ADMIN-ONLY ---
app.get("/admin/users", authenticateToken, requireRole("admin"), (req, res) => {
  res.json(
    users.map((u) => ({
      ...publicUser(u),
      noteCount: notes.filter((n) => n.userId === u.id).length,
      activeSessions: [...refreshTokens.values()].filter((t) => t.userId === u.id && !t.used).length,
    }))
  );
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
  console.log(`Access tokens last ${ACCESS_TTL}, refresh tokens ${REFRESH_TTL}`);
  console.log(`Log in as testuser / password123  (regular user)`);
  console.log(`Log in as admin    / password123  (admin)`);
});
