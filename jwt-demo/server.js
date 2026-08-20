const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const path = require("path");
const { db, save } = require("./db");

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// Separate secrets so a leaked access secret can't be used to mint refresh tokens.
const ACCESS_SECRET = process.env.ACCESS_SECRET || "dev_access_secret_change_me";
const REFRESH_SECRET = process.env.REFRESH_SECRET || "dev_refresh_secret_change_me";

if (!process.env.ACCESS_SECRET) {
  console.warn("Warning: using the dev secrets from this file. Set ACCESS_SECRET and");
  console.warn("REFRESH_SECRET before running this anywhere real.");
}

// The access token goes out with every request so it expires fast. The refresh
// token only ever goes to /refresh, so it can safely live much longer.
const ACCESS_TTL = "2m";
const REFRESH_TTL = "7d";

// Seed two accounts the first time this runs.
if (db.users.length === 0) {
  db.users.push(
    { id: 1, username: "testuser", role: "user", passwordHash: bcrypt.hashSync("password123", 8), createdAt: Date.now() },
    { id: 2, username: "admin", role: "admin", passwordHash: bcrypt.hashSync("password123", 8), createdAt: Date.now() }
  );
  db.notes.push(
    { id: 1, userId: 1, text: "testuser's private note" },
    { id: 2, userId: 2, text: "admin's private note" }
  );
  db.nextUserId = 3;
  db.nextNoteId = 3;
  save();
}

// Rate limiting. Without it you can guess passwords as fast as you can send
// requests, which makes the bcrypt hashing fairly pointless.
const attempts = new Map(); // key -> { count, firstAt, lockedUntil }
const MAX_ATTEMPTS = 5;
const WINDOW_MS = 15 * 60 * 1000;
const LOCKOUT_MS = 5 * 60 * 1000;

function rateLimit(req, res, next) {
  // Keyed on IP + username, otherwise one attacker could lock everyone out.
  const key = req.ip + ":" + (req.body.username || "");
  const now = Date.now();
  const entry = attempts.get(key);

  if (entry?.lockedUntil > now) {
    const secs = Math.ceil((entry.lockedUntil - now) / 1000);
    return res.status(429).json({ error: `Too many attempts. Try again in ${secs}s.` });
  }
  if (entry && now - entry.firstAt > WINDOW_MS) attempts.delete(key);

  req.rateKey = key;
  next();
}

function recordFailure(key) {
  const now = Date.now();
  const entry = attempts.get(key) || { count: 0, firstAt: now };
  entry.count++;
  if (entry.count >= MAX_ATTEMPTS) entry.lockedUntil = now + LOCKOUT_MS;
  attempts.set(key, entry);
  return Math.max(0, MAX_ATTEMPTS - entry.count);
}

// Access tokens are stateless, which is exactly why they can't be revoked.
// Refresh tokens get a row in db.sessions, and that's what makes logout,
// the sessions list and "sign out everywhere" possible.
function issueTokens(user, req, family = crypto.randomUUID()) {
  const accessToken = jwt.sign(
    { userId: user.id, username: user.username, role: user.role },
    ACCESS_SECRET,
    { expiresIn: ACCESS_TTL }
  );

  const jti = crypto.randomUUID(); // id for this token so we can revoke it later
  const refreshToken = jwt.sign({ userId: user.id, jti, family }, REFRESH_SECRET, {
    expiresIn: REFRESH_TTL,
  });

  db.sessions.push({
    jti,
    family,
    userId: user.id,
    used: false,
    createdAt: Date.now(),
    userAgent: req.headers["user-agent"] || "unknown",
    ip: req.ip,
  });
  save();

  return { accessToken, refreshToken };
}

function publicUser(user) {
  return { id: user.id, username: user.username, role: user.role };
}

function revokeFamily(family) {
  db.sessions = db.sessions.filter((s) => s.family !== family);
  save();
}

// --- auth routes ---
app.post("/register", rateLimit, (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password are required" });
  }
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
    return res.status(400).json({ error: "Username must be 3–20 letters, numbers or underscores" });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: "Password must be at least 8 characters" });
  }
  if (db.users.some((u) => u.username.toLowerCase() === username.toLowerCase())) {
    return res.status(409).json({ error: "That username is already taken" });
  }

  const user = {
    id: db.nextUserId++,
    username,
    role: "user", // new signups are never admins
    passwordHash: bcrypt.hashSync(password, 8),
    createdAt: Date.now(),
  };
  db.users.push(user);
  save();

  res.status(201).json({ ...issueTokens(user, req), user: publicUser(user) });
});

app.post("/login", rateLimit, (req, res) => {
  const { username, password } = req.body;
  const user = db.users.find((u) => u.username === username);

  // Same message for both cases, otherwise you could probe for valid usernames.
  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    const left = recordFailure(req.rateKey);
    return res.status(401).json({
      error: "Invalid username or password",
      attemptsLeft: left,
    });
  }

  attempts.delete(req.rateKey); // clear the failure count
  res.json({ ...issueTokens(user, req), user: publicUser(user) });
});

app.post("/refresh", (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(401).json({ error: "No refresh token provided" });

  let payload;
  try {
    payload = jwt.verify(refreshToken, REFRESH_SECRET);
  } catch {
    return res.status(403).json({ error: "Invalid or expired refresh token" });
  }

  const session = db.sessions.find((s) => s.jti === payload.jti);
  if (!session) return res.status(403).json({ error: "Session has been revoked" });

  // A rotated token should never show up again. If it does, assume it was stolen
  // and drop the whole family.
  if (session.used) {
    revokeFamily(session.family);
    return res.status(403).json({ error: "Refresh token reuse detected, all sessions revoked" });
  }

  const user = db.users.find((u) => u.id === payload.userId);
  if (!user) return res.status(403).json({ error: "User no longer exists" });

  // Rotate: burn the old one, issue a new one.
  db.sessions = db.sessions.filter((s) => s.jti !== session.jti);
  save();

  res.json({ ...issueTokens(user, req, session.family), user: publicUser(user) });
});

app.post("/logout", (req, res) => {
  const { refreshToken } = req.body;
  if (refreshToken) {
    try {
      const payload = jwt.verify(refreshToken, REFRESH_SECRET);
      db.sessions = db.sessions.filter((s) => s.jti !== payload.jti);
      save();
    } catch {
      // already invalid, nothing to revoke
    }
  }
  res.json({ ok: true });
});

// --- middleware ---
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"]; // "Bearer <token>"
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token provided" });

  jwt.verify(token, ACCESS_SECRET, (err, decoded) => {
    if (err) {
      // The frontend looks for this code to decide whether to hit /refresh.
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

function requireRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).json({ error: `Requires the "${role}" role` });
    }
    next();
  };
}

// --- account ---
app.get("/profile", authenticateToken, (req, res) => {
  const user = db.users.find((u) => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: "User not found" });

  res.json({
    ...publicUser(user),
    createdAt: user.createdAt,
    noteCount: db.notes.filter((n) => n.userId === user.id).length,
  });
});

// Changing the password drops every session. If you're changing it, you probably
// think someone else has it.
app.post("/change-password", authenticateToken, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const user = db.users.find((u) => u.id === req.user.userId);

  if (!user || !bcrypt.compareSync(currentPassword || "", user.passwordHash)) {
    return res.status(401).json({ error: "Current password is incorrect" });
  }
  if (!newPassword || newPassword.length < 8) {
    return res.status(400).json({ error: "New password must be at least 8 characters" });
  }

  user.passwordHash = bcrypt.hashSync(newPassword, 8);
  db.sessions = db.sessions.filter((s) => s.userId !== user.id);
  save();

  res.json({ ...issueTokens(user, req), user: publicUser(user), message: "Password changed, other sessions signed out" });
});

// --- sessions ---
app.get("/sessions", authenticateToken, (req, res) => {
  res.json(
    db.sessions
      .filter((s) => s.userId === req.user.userId)
      .map((s) => ({
        id: s.jti,
        createdAt: s.createdAt,
        userAgent: s.userAgent,
        ip: s.ip,
      }))
  );
});

app.delete("/sessions/:id", authenticateToken, (req, res) => {
  const session = db.sessions.find((s) => s.jti === req.params.id);

  // you can only revoke your own
  if (!session || session.userId !== req.user.userId) {
    return res.status(404).json({ error: "Session not found" });
  }

  db.sessions = db.sessions.filter((s) => s.jti !== session.jti);
  save();
  res.json({ revoked: session.jti });
});

app.post("/sessions/revoke-all", authenticateToken, (req, res) => {
  const before = db.sessions.length;
  db.sessions = db.sessions.filter((s) => s.userId !== req.user.userId);
  save();

  const user = db.users.find((u) => u.id === req.user.userId);
  res.json({ ...issueTokens(user, req), revoked: before - db.sessions.length });
});

// --- notes ---
app.get("/notes", authenticateToken, (req, res) => {
  res.json(db.notes.filter((n) => n.userId === req.user.userId));
});

app.post("/notes", authenticateToken, (req, res) => {
  const { text } = req.body;
  if (!text || !text.trim()) return res.status(400).json({ error: "Note text is required" });
  if (text.length > 500) return res.status(400).json({ error: "Note is too long (500 chars max)" });

  const note = { id: db.nextNoteId++, userId: req.user.userId, text: text.trim(), createdAt: Date.now() };
  db.notes.push(note);
  save();
  res.status(201).json(note);
});

app.put("/notes/:id", authenticateToken, (req, res) => {
  const note = db.notes.find((n) => n.id === Number(req.params.id));
  if (!note || note.userId !== req.user.userId) {
    return res.status(404).json({ error: "Note not found" });
  }
  if (!req.body.text || !req.body.text.trim()) {
    return res.status(400).json({ error: "Note text is required" });
  }

  note.text = req.body.text.trim();
  save();
  res.json(note);
});

app.delete("/notes/:id", authenticateToken, (req, res) => {
  const note = db.notes.find((n) => n.id === Number(req.params.id));

  // Having a valid token doesn't mean you own this note.
  if (!note || note.userId !== req.user.userId) {
    return res.status(404).json({ error: "Note not found" });
  }

  db.notes = db.notes.filter((n) => n.id !== note.id);
  save();
  res.json({ deleted: note.id });
});

// --- admin ---
app.get("/admin/users", authenticateToken, requireRole("admin"), (req, res) => {
  res.json(
    db.users.map((u) => ({
      ...publicUser(u),
      createdAt: u.createdAt,
      noteCount: db.notes.filter((n) => n.userId === u.id).length,
      activeSessions: db.sessions.filter((s) => s.userId === u.id).length,
    }))
  );
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
  console.log(`Access tokens last ${ACCESS_TTL}, refresh tokens ${REFRESH_TTL}`);
  console.log(`${db.users.length} users loaded from data.json`);
  console.log(`Log in as testuser / password123  (regular user)`);
  console.log(`Log in as admin    / password123  (admin)`);
});
