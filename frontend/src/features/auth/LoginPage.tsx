import { KeyRound } from "lucide-react";
import { FormEvent, useState } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import { useAuth } from "./authContext";

const brandLogoPath = "/dashboard/brand/ares-logo.png";

export function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const { login, user } = useAuth();
  const navigate = useNavigate();

  if (user) {
    return <Navigate to="/" replace />;
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError("");
    try {
      await login(username, password);
      navigate("/");
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Login failed");
    }
  }

  return (
    <div className="grid min-h-screen place-items-center bg-slate-100 p-4">
      <form className="panel w-full max-w-sm p-5" onSubmit={(event) => void submit(event)}>
        <div className="mb-5 text-center">
          <img className="mx-auto mb-4 h-28 w-auto max-w-full object-contain" src={brandLogoPath} alt="ARES" />
          <h1 className="text-xl font-bold">ARES Dashboard</h1>
          <p className="text-sm text-slate-600">Authorized access</p>
        </div>
        <label className="mb-3 block text-sm font-semibold">
          Username
          <input className="field mt-1" value={username} onChange={(e) => setUsername(e.target.value)} />
        </label>
        <label className="mb-4 block text-sm font-semibold">
          Password
          <input
            className="field mt-1"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>
        {error && <div className="mb-3 rounded-md border border-red-200 bg-red-50 p-2 text-sm text-red-800">{error}</div>}
        <button className="btn btn-primary w-full" type="submit">
          <KeyRound size={16} /> Login
        </button>
      </form>
    </div>
  );
}
