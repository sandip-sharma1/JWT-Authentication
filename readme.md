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
