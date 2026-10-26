const { useEffect, useState } = React;

const TOKEN_KEY = "loginapp.jwt";

function authHeaders(token) {
  return { Authorization: "Bearer " + token };
}

function App() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [status, setStatus] = useState({ type: "", text: "" });
  const [loading, setLoading] = useState(false);
  const [session, setSession] = useState(null);
  const [checkingToken, setCheckingToken] = useState(true);

  useEffect(() => {
    const saved = sessionStorage.getItem(TOKEN_KEY);
    if (!saved) {
      setCheckingToken(false);
      return;
    }

    fetch("/api/me", { headers: authHeaders(saved) })
      .then(async (response) => {
        const data = await response.json();
        if (!response.ok || !data.ok) {
          sessionStorage.removeItem(TOKEN_KEY);
          return;
        }
        setSession({ token: saved, user: data.user });
      })
      .catch(() => sessionStorage.removeItem(TOKEN_KEY))
      .finally(() => setCheckingToken(false));
  }, []);

  async function handleSubmit(event) {
    event.preventDefault();
    setStatus({ type: "", text: "" });
    setLoading(true);

    try {
      const response = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      const data = await response.json();

      if (!response.ok || !data.ok) {
        setStatus({ type: "error", text: data.message || "Login failed" });
        return;
      }

      sessionStorage.setItem(TOKEN_KEY, data.token);
      setSession({ token: data.token, user: data.user, expiresIn: data.expiresIn });
      setPassword("");
      setStatus({ type: "success", text: data.message });
    } catch (error) {
      setStatus({ type: "error", text: "Cannot reach the Java backend on port 8080." });
    } finally {
      setLoading(false);
    }
  }

  async function handleLogout() {
    if (session?.token) {
      await fetch("/api/logout", {
        method: "POST",
        headers: authHeaders(session.token),
      });
    }
    sessionStorage.removeItem(TOKEN_KEY);
    setSession(null);
    setStatus({ type: "", text: "" });
  }

  if (checkingToken) {
    return (
      <div className="page">
        <main className="card">
          <p className="muted">Checking JWT session...</p>
        </main>
      </div>
    );
  }

  if (session?.user) {
    return (
      <div className="page">
        <main className="card welcome-card">
          <p className="eyebrow">JWT session</p>
          <h1>Welcome, {session.user.displayName}</h1>
          <p className="muted">
            The Java API verified your HS256 JWT as {session.user.username}. Protected
            routes require <code>Authorization: Bearer</code>.
          </p>
          <button className="primary" type="button" onClick={handleLogout}>
            Log out
          </button>
        </main>
      </div>
    );
  }

  return (
    <div className="page">
      <main className="card">
        <p className="eyebrow">Java + React mini app</p>
        <h1>Sign in</h1>
        <p className="muted">Login issues a signed JWT. The token expires after 15 minutes.</p>

        <form onSubmit={handleSubmit}>
          <label htmlFor="username">Username</label>
          <input
            id="username"
            name="username"
            autoComplete="username"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            placeholder="admin"
            required
          />

          <label htmlFor="password">Password</label>
          <div className="password-row">
            <input
              id="password"
              name="password"
              type={showPassword ? "text" : "password"}
              autoComplete="current-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="••••••••"
              required
            />
            <button
              className="ghost"
              type="button"
              onClick={() => setShowPassword((value) => !value)}
            >
              {showPassword ? "Hide" : "Show"}
            </button>
          </div>

          {status.text ? <p className={"banner " + status.type}>{status.text}</p> : null}

          <button className="primary" type="submit" disabled={loading}>
            {loading ? "Signing in..." : "Sign in"}
          </button>
        </form>

        <aside className="hint">
          <strong>Demo logins</strong>
          <span>admin / admin123</span>
          <span>keerthi / password</span>
        </aside>
      </main>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
