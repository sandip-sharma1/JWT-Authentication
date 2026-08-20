JWT (JSON Web Token) is a compact, self-contained way to securely transmit information between parties as a digitally signed JSON object—commonly used for authentication and authorization in web apps.

It has 3 parts: Header.Payload.Signature

Once a user logs in, the server issues a JWT, and the client sends it with each request to prove identity—without needing to check a database every time.        
          
JWT structure is shown as follows...
        
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

---

## The demo (`jwt-demo/`)

```bash
cd jwt-demo
npm install
npm start          # http://localhost:3000
```

Two seeded accounts, both with password `password123`:
`testuser` (regular) and `admin` (sees an extra panel).

### What's implemented

| | |
|---|---|
| Passwords | bcrypt hashed, never stored in plaintext |
| Access token | 2 min, stateless, sent on every request |
| Refresh token | 7 days, rotated on every use, tracked server-side |
| Reuse detection | replaying a rotated token revokes the whole token family |
| Logout | revokes the refresh token; access token still dies on its own clock |
| Sessions | list your devices, revoke one or all |
| Authorization | `requireRole("admin")` + per-row ownership checks |
| Rate limiting | 5 failed logins → 5 minute lockout, keyed on IP + username |
| Persistence | `data.json`, so accounts survive a restart |

### Still not production

No HTTPS, tokens live in `localStorage` (readable by any XSS), secrets fall back
to hardcoded dev values, no email verification or password reset, and the data
store is a JSON file. Set `ACCESS_SECRET` and `REFRESH_SECRET` to override the
built-in secrets.
