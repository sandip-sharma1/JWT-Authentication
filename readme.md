# JWT Authentication

Notes and a working demo I built while learning how JWT auth actually works.

JWT (JSON Web Token) is a compact, self-contained way to securely transmit
information between parties as a digitally signed JSON object, commonly used for
authentication and authorization in web apps.

It has 3 parts: Header.Payload.Signature

Once a user logs in, the server issues a JWT, and the client sends it with each
request to prove identity, without needing to check a database every time.

The flow:

```
                    LOGIN
                      │
                      ▼
               Verify password
                      │
             ┌────────┴────────┐
             ▼                 ▼
       Short-lived JWT     Refresh token
             │                 │
             │                 └── securely stored/
             │                     rotated/revoked
             ▼
          API calls
             │
             ▼
       Verify signature
             │
       Validate claims
             │
       Check authorization
             │
             ▼
           Allow
```

See `dataflow.png` for the same thing as a proper data flow diagram.

## Running it

```bash
cd jwt-demo
npm install
npm start
```

Then open http://localhost:3000.

Two accounts are seeded on first run, both with the password `password123`:

- `testuser` - regular user
- `admin` - also gets an admin panel

To use different secrets (you should, outside of local testing):

```bash
ACCESS_SECRET=something REFRESH_SECRET=something-else npm start
```

## Which part does what

```
jwt-demo/
├── server.js           all the API routes and auth logic
├── db.js               reads/writes data.json
├── data.json           users, notes, sessions (created on first run, gitignored)
└── public/index.html   the entire frontend, one file
```

### server.js

| Section | What it does |
|---|---|
| `issueTokens()` | signs the access + refresh token pair and records the session |
| `authenticateToken()` | middleware, verifies the access token on every protected route |
| `requireRole()` | middleware, checks the role claim (this is the authorization step) |
| `rateLimit()` | blocks login after 5 failed attempts |

Routes:

| Method | Route | Auth needed | What it does |
|---|---|---|---|
| POST | `/register` | no | creates a user, returns tokens |
| POST | `/login` | no | checks the password, returns tokens |
| POST | `/refresh` | refresh token | rotates the pair, returns new ones |
| POST | `/logout` | refresh token | revokes that one session |
| GET | `/profile` | access token | the logged in user's details |
| POST | `/change-password` | access token | changes it, kills all other sessions |
| GET | `/sessions` | access token | lists your active sessions |
| DELETE | `/sessions/:id` | access token | revokes one session |
| POST | `/sessions/revoke-all` | access token | signs out everywhere else |
| GET/POST | `/notes` | access token | only your own notes |
| PUT/DELETE | `/notes/:id` | access token | only if you own it |
| GET | `/admin/users` | access token + admin | every user, admin only |

### public/index.html

One page, two views. `authView` is the login/signup card, `appView` is everything
after logging in, split into tabs (Notes, Sessions, Account, Token).

The important function is `api()`. Every protected request goes through it, and
if the server says the access token expired it calls `/refresh`, then retries the
original request. That is why you never get logged out mid-click even though the
access token only lasts 2 minutes.

The Token tab shows the live JWT, its decoded payload and a countdown to expiry.
Useful for actually watching the refresh happen.

## What's implemented

| | |
|---|---|
| Passwords | bcrypt hashed, never stored in plaintext |
| Access token | 2 min, stateless, sent on every request |
| Refresh token | 7 days, rotated on every use, tracked server side |
| Reuse detection | replaying a rotated token revokes the whole token family |
| Logout | revokes the refresh token, access token still dies on its own clock |
| Sessions | list your devices, revoke one or all |
| Authorization | `requireRole("admin")` plus per row ownership checks |
| Rate limiting | 5 failed logins, then a 5 minute lockout, keyed on IP + username |
| Persistence | `data.json`, so accounts survive a restart |

## What it isn't

This is a learning project, not something to put in front of real users.

- Runs over plain HTTP, so tokens travel in cleartext
- Tokens live in `localStorage`, which any XSS on the page can read. Real apps
  use httpOnly cookies
- Falls back to hardcoded dev secrets if the env vars aren't set
- The database is a JSON file, rewritten in full on every change
- No email verification, no password reset, no account recovery
