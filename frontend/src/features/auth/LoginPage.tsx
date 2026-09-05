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
    <div className="relative min-h-screen flex items-center justify-center bg-[#090d16] p-4 text-slate-100 overflow-hidden selection:bg-orange-500 selection:text-white">
      {/* Subtle tactical ambient background glow */}
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_50%_25%,rgba(249,115,22,0.08),transparent_60%)]" />
      <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(to_right,rgba(255,255,255,0.015)_1px,transparent_1px),linear-gradient(to_bottom,rgba(255,255,255,0.015)_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_50%,#000_70%,transparent_100%)]" />

      <div className="relative w-full max-w-md">
        {/* Status Chip */}
        <div className="mb-4 flex items-center justify-center">
          <div className="inline-flex items-center gap-2 rounded-full border border-emerald-500/30 bg-emerald-950/40 px-3 py-1 font-mono text-xs tracking-wider text-emerald-400 backdrop-blur-md">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
            <span>NODE READY // TLS 1.3 ENCRYPTED</span>
          </div>
        </div>

        {/* Tactical Card */}
        <form
          className="panel rounded-2xl border border-slate-800/90 bg-slate-900/90 p-8 shadow-2xl shadow-black/80 backdrop-blur-xl"
          onSubmit={(event) => void submit(event)}
        >
          <div className="mb-6 text-center">
            <img
              className="mx-auto mb-3 h-20 w-auto max-w-full object-contain filter drop-shadow-[0_4px_12px_rgba(249,115,22,0.2)]"
              src={brandLogoPath}
              alt="ARES"
            />
            <h1 className="text-2xl font-bold tracking-tight text-white">ARES Dashboard</h1>
            <p className="mt-1 text-xs font-mono tracking-wide text-slate-400 uppercase">
              Adversary Emulation & Operator Console
            </p>
          </div>

          <div className="space-y-4">
            <label className="mb-3 block text-xs font-semibold uppercase tracking-wider text-slate-300">
              Username
              <input
                className="field mt-1.5 w-full rounded-lg border border-slate-700 bg-slate-950/80 px-3.5 py-2.5 text-sm text-slate-100 placeholder-slate-500 transition-all focus:border-orange-500 focus:outline-none focus:ring-2 focus:ring-orange-500/30"
                placeholder="Enter operator callsign"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
              />
            </label>

            <label className="mb-4 block text-xs font-semibold uppercase tracking-wider text-slate-300">
              Password
              <input
                className="field mt-1.5 w-full rounded-lg border border-slate-700 bg-slate-950/80 px-3.5 py-2.5 text-sm text-slate-100 placeholder-slate-500 transition-all focus:border-orange-500 focus:outline-none focus:ring-2 focus:ring-orange-500/30"
                type="password"
                placeholder="••••••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
              />
            </label>
          </div>

          {error && (
            <div className="mt-4 flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-950/50 p-3 text-sm text-red-300">
              <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-red-400" />
              <span>{error}</span>
            </div>
          )}

          <button
            className="btn btn-primary mt-6 flex w-full items-center justify-center gap-2 rounded-lg bg-orange-600 px-4 py-2.5 text-sm font-semibold text-white shadow-lg shadow-orange-950/50 transition-all hover:bg-orange-500 active:scale-[0.98] focus:outline-none focus:ring-2 focus:ring-orange-500/40"
            type="submit"
          >
            <KeyRound size={16} /> Login
          </button>

          <div className="mt-6 border-t border-slate-800/80 pt-4 text-center">
            <p className="font-mono text-[10px] tracking-widest text-slate-500 uppercase">
              RESTRICTED ACCESS • AUTHORIZED ENGAGEMENT ONLY
            </p>
          </div>
        </form>
      </div>
    </div>
  );
}
