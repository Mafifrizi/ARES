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
    <div className="min-h-screen flex flex-col items-center justify-center bg-zinc-950 px-4 text-zinc-100">
      <div className="w-full max-w-sm">
        {/* Brand Header */}
        <div className="mb-8 text-center">
          <img
            className="mx-auto mb-4 h-12 w-auto object-contain"
            src={brandLogoPath}
            alt="ARES"
          />
          <h1 className="text-xl font-semibold tracking-tight text-zinc-100">ARES Dashboard</h1>
          <p className="mt-1.5 text-sm text-zinc-400">
            Sign in with your operator credentials
          </p>
        </div>

        {/* Form Card */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-6 shadow-sm">
          <form onSubmit={(event) => void submit(event)} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1.5">
                Username
                <input
                  className="mt-1 block w-full rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-500 transition-colors focus:border-zinc-500 focus:outline-none focus:ring-1 focus:ring-zinc-500"
                  placeholder="operator"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  autoComplete="username"
                  required
                />
              </label>
            </div>

            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1.5">
                Password
                <input
                  className="mt-1 block w-full rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-500 transition-colors focus:border-zinc-500 focus:outline-none focus:ring-1 focus:ring-zinc-500"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="current-password"
                  required
                />
              </label>
            </div>

            {error && (
              <div className="rounded-md border border-red-900/50 bg-red-950/30 px-3 py-2 text-xs text-red-400">
                {error}
              </div>
            )}

            <button
              className="w-full mt-2 flex items-center justify-center gap-2 rounded-md bg-zinc-100 px-4 py-2 text-sm font-medium text-zinc-900 transition-colors hover:bg-white active:bg-zinc-200 focus:outline-none focus:ring-2 focus:ring-zinc-400 focus:ring-offset-2 focus:ring-offset-zinc-900"
              type="submit"
            >
              <KeyRound size={15} className="text-zinc-700" />
              Login
            </button>
          </form>
        </div>

        {/* Subtle Footer */}
        <div className="mt-6 text-center">
          <p className="text-xs text-zinc-500">
            ARES Automated Red Team Engagement System
          </p>
        </div>
      </div>
    </div>
  );
}
