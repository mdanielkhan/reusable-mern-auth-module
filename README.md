# Reusable MERN Auth Module

Drop-in authentication for any MERN app: email/password, Google OAuth,
JWT access+refresh tokens (httpOnly cookies), role-based authorization,
email verification, password reset, and logout/revocation.

## How the pieces fit together

- **Access token** (15 min default): short-lived JWT, sent as an httpOnly
  cookie. Read by `authenticate` middleware on every request.
- **Refresh token** (7 day default): a second httpOnly JWT, scoped to the
  `/api/auth/refresh` path only. Its hash is stored in the `RefreshToken`
  collection so it can be revoked — a bare JWT can't be revoked, only a
  server-side record of it can.
- **Rotation**: every call to `/refresh` invalidates the old refresh token
  and issues a new one. If an old (already-rotated) token is replayed,
  every active session for that user is revoked — this is the standard way
  to detect refresh-token theft, at the cost of one extra DB write per
  refresh.
- **Roles**: flat enum (`user`, `manager`, `admin`) checked by
  `authorize(...roles)` middleware. No inheritance — `admin` does not
  automatically pass an `authorize('manager')` check. Change this in
  `middleware/authorize.js` if your spec wants a hierarchy.

## Backend integration

1. `cd backend && npm install`
2. Copy `.env.example` to `.env` and fill in real values.
   - **MongoDB in Pakistan**: if `mongodb+srv://` fails because your ISP
     blocks SRV DNS lookups, use the non-SRV connection string from Atlas
     (see the comment in `.env.example`) — same fix you already used on
     gitmatch.
   - Generate `JWT_ACCESS_SECRET` / `JWT_REFRESH_SECRET` with
     `node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"`,
     run twice for two different values.
3. `npm run dev` (or `npm start`).
4. Mount this into an existing app by copying `src/` in and requiring
   `authRoutes` from your main `app.js`:
   ```js
   app.use('/api/auth', require('./src/routes/authRoutes'));
   app.use(errorHandler); // must be the LAST app.use()
   ```
5. Protect any route in your own app:
   ```js
   const authenticate = require('./middleware/authenticate');
   const authorize = require('./middleware/authorize');

   router.get('/reports', authenticate, authorize('admin', 'manager'), handler);
   ```

## Frontend integration (React + Vite + react-router-dom)

1. `npm install axios react-router-dom`
2. Add the GIS script to `index.html`:
   ```html
   <script src="https://accounts.google.com/gsi/client" async defer></script>
   ```
3. Set `VITE_API_URL` and `VITE_GOOGLE_CLIENT_ID` in your frontend `.env`.
4. Wrap your app:
   ```jsx
   <AuthProvider>
     <BrowserRouter>
       <Routes>
         <Route path="/login" element={<LoginPage />} />
         <Route element={<ProtectedRoute />}>
           <Route path="/dashboard" element={<Dashboard />} />
         </Route>
         <Route element={<ProtectedRoute allowedRoles={['admin']} />}>
           <Route path="/admin" element={<AdminPanel />} />
         </Route>
       </Routes>
     </BrowserRouter>
   </AuthProvider>
   ```
   **If you're on Create React App instead of Vite**, `import.meta.env` in
   `axios.js` and `GoogleLoginButton.jsx` won't work — swap those two lines
   for `process.env.REACT_APP_API_URL` / `process.env.REACT_APP_GOOGLE_CLIENT_ID`.
   This module assumes Vite; say so if that's wrong and I'll redo those two files.

## Endpoint reference

| Method | Path | Auth required | Notes |
|---|---|---|---|
| POST | `/api/auth/register` | no | rate-limited |
| POST | `/api/auth/login` | no | rate-limited |
| POST | `/api/auth/google` | no | body: `{ idToken }` |
| POST | `/api/auth/refresh` | refresh cookie | rotates token |
| POST | `/api/auth/logout` | no (uses cookie) | revokes one session |
| POST | `/api/auth/logout-all` | yes | revokes all sessions |
| GET  | `/api/auth/me` | yes | current user |
| GET  | `/api/auth/verify-email?token=` | no | |
| POST | `/api/auth/resend-verification` | yes | |
| POST | `/api/auth/forgot-password` | no | rate-limited, always 200 |
| POST | `/api/auth/reset-password` | no | body: `{ token, password }`, revokes all sessions |

## What's cut for internship-timeline reasons — say something if this isn't acceptable

- **No CSRF token.** httpOnly cookies + `SameSite=Lax`/`None` + strict CORS
  origin cuts most CSRF risk, but a same-site GET-based attack on a
  state-changing endpoint isn't fully closed. Add `csurf` or a
  double-submit cookie if your reviewer will check for this specifically.
- **No account lockout after N failed logins** — only a blanket rate limit
  per IP. A distributed brute-force attempt (many IPs, one account) isn't
  stopped. `express-rate-limit` alone doesn't do this; you'd want a
  failed-attempt counter on the User document.
- **Email sending has no queue/retry.** If your SMTP provider is down for a
  minute, that verification/reset email is just gone. Fine for a class
  project; not fine at real scale — you'd want a job queue.
- **No refresh-token cap per user.** A user can accumulate unlimited
  refresh tokens (one per login/device) with nothing pruning old ones
  except the TTL index. Not a security hole, just unbounded row growth.
- **Google OAuth only links by email, doesn't ask for confirmation.** If
  someone's email is spoofable in some other system that Google trusts,
  auto-linking on email match is the standard approach but is a real
  (if unusual) attack surface if you ever add another OAuth provider —
  reassess if you do.

None of these are wrong choices for an internship deliverable — they're
tradeoffs. If the internship's grading rubric explicitly wants CSRF
protection or account lockout, tell me and I'll add them rather than you
finding out after submission.
