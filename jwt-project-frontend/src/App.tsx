import { useState, useEffect } from "react";
import axios from "axios";

axios.defaults.withCredentials = true;

export default function App() {
  const [token, setToken] = useState(() => localStorage.getItem("token") || "");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [profile, setProfile] = useState(null);

  const login = async () => {
    try {
      const res = await axios.post(
        "https://127.0.0.1:8000/login",
        new URLSearchParams({ username, password }),
        { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
      );
      setToken(res.data.access_token);
      localStorage.setItem("token", res.data.access_token);
      alert("Login successful!");
    } catch (err) {
      alert("Login failed");
    }
  };

  const refreshAccessToken = async () => {
    try {
      const res = await axios.post("https://127.0.0.1:8000/refresh");
      setToken(res.data.access_token);
      localStorage.setItem("token", res.data.access_token);
      return res.data.access_token;
    } catch (err) {
      console.error("Refresh token failed:", err);
      setToken("");
      localStorage.removeItem("token");
      alert("Session expired. Please login again.");
      return null;
    }
  };

  const getProfile = async () => {
    let accessToken = token;
    try {
      const res = await axios.get("https://127.0.0.1:8000/profile", {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      setProfile(res.data);
    } catch (err) {
      accessToken = await refreshAccessToken();
      if (!accessToken) {
        setProfile(null);
        return;
      } 
      const res = await axios.get("https://127.0.0.1:8000/profile", {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      setProfile(res.data);
    }
  };

  const logout = () => {
    setToken("");
    localStorage.removeItem("token");
    setProfile(null);
  };

  useEffect(() => {
    if (token) getProfile();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div style={{ padding: "20px" }}>
      <h1>JWT Demo with Refresh Token</h1>

      {!token ? (
        <div>
          <input
            placeholder="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <input
            placeholder="password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <button onClick={login}>Login</button>
        </div>
      ) : (
        <div>
          <p>Logged in (access token: {token.substring(0, 20)}...)</p>
          <button onClick={getProfile}>Get Profile</button>
          <button onClick={logout}>Logout</button>
        </div>
      )}

      {profile && (
        <div style={{ marginTop: "20px" }}>
          <h3>Profile:</h3>
          <pre>{JSON.stringify(profile, null, 2)}</pre>
        </div>
      )}
    </div>
  );
}
