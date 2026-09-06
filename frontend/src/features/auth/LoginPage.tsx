import { Activity, AlertCircle, Eye, EyeOff, GitGraph, Loader2, ShieldCheck } from "lucide-react";
import { FormEvent, useState } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import { SecurityMeshCanvas } from "./SecurityMeshCanvas";
import { useAuth } from "./authContext";

const brandMarkPath = "/dashboard/brand/ares-mark.png";

export function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState("");
  const { login, user } = useAuth();
  const navigate = useNavigate();

  if (user) {
    return <Navigate to="/" replace />;
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (isSubmitting) return;
    setError("");
    setIsSubmitting(true);
    try {
      await login(username, password);
      navigate("/", { replace: true });
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Authentication failed");
      setIsSubmitting(false);
    }
  }

  return (
    <div className="min-h-[100dvh] w-full bg-[#09090b] text-[#f4f4f5] grid lg:grid-cols-12 selection:bg-red-700 selection:text-white">

      {/* Left Column */}
      <div className="hidden lg:flex lg:col-span-7 flex-col justify-between p-12 xl:p-16 border-r border-[#1a1a1f] bg-[#0b0b0e] relative overflow-hidden">
        {/* The mesh IS the animation — purposeful: visualises the live attack graph */}
        <SecurityMeshCanvas />

        {/* Ambient atmospheric glow — soft ember warmth behind dragon scales */}
        <div className="pointer-events-none absolute left-1/3 top-1/2 -translate-x-1/2 -translate-y-1/2 h-[36rem] w-[36rem] rounded-full bg-red-950/[0.22] blur-[110px] animate-ares-breathe" />

        {/* Brand header */}
        <div className="relative z-10 flex items-center gap-3 animate-login-enter" style={{ animationDelay: "0ms" }}>
          <img
            className="h-9 w-9 object-contain rounded-md border border-zinc-800 bg-zinc-900/60 p-1"
            src={brandMarkPath}
            alt="ARES"
          />
          <div>
            <h1 className="text-base font-semibold text-white tracking-tight">ARES Dashboard</h1>
            <p className="text-[11px] text-zinc-500 font-mono">Adversary Emulation Suite</p>
          </div>
        </div>

        {/* Value proposition */}
        <div className="relative z-10 max-w-lg space-y-6 my-auto py-12">
          <div className="animate-login-enter" style={{ animationDelay: "80ms" }}>
            <h2 className="text-3xl font-semibold text-zinc-100 tracking-tight leading-tight">
              Autonomous adversary emulation for offensive security teams.
            </h2>
            <p className="text-sm text-zinc-400 leading-relaxed mt-3">
              Coordinate multi-vector attack chains, assess defensive barriers across enterprise enclaves, and validate resilience against adversary techniques with full audit fidelity.
            </p>
          </div>

          <div className="pt-2 grid gap-3 text-xs">
            {/* Pillar — hover translate communicates interactivity, red accent on hover ties to ARES brand */}
            <div
              className="flex items-start gap-3.5 p-3.5 rounded-lg border border-zinc-800/80 bg-zinc-900/30 backdrop-blur-sm hover:border-red-900/40 hover:bg-zinc-900/50 transition-all duration-200 group cursor-default hover:translate-x-1 animate-login-enter"
              style={{ animationDelay: "180ms" }}
            >
              <div className="p-1.5 rounded-md bg-zinc-900 border border-zinc-800 text-zinc-400 group-hover:border-red-900/50 group-hover:text-red-500 transition-colors mt-0.5 shrink-0">
                <GitGraph size={15} />
              </div>
              <div className="flex-1 min-w-0">
                <strong className="text-zinc-200 block text-xs font-medium">Multi-Vector Attack Graph</strong>
                <span className="text-zinc-400 text-[11px] leading-relaxed block mt-0.5">
                  Interactive DAG execution chains with deterministic objective replay.
                </span>
              </div>
            </div>

            <div
              className="flex items-start gap-3.5 p-3.5 rounded-lg border border-zinc-800/80 bg-zinc-900/30 backdrop-blur-sm hover:border-red-900/40 hover:bg-zinc-900/50 transition-all duration-200 group cursor-default hover:translate-x-1 animate-login-enter"
              style={{ animationDelay: "260ms" }}
            >
              <div className="p-1.5 rounded-md bg-zinc-900 border border-zinc-800 text-zinc-400 group-hover:border-red-900/50 group-hover:text-red-500 transition-colors mt-0.5 shrink-0">
                <Activity size={15} />
              </div>
              <div className="flex-1 min-w-0">
                <strong className="text-zinc-200 block text-xs font-medium">Adaptive OPSEC Controls</strong>
                <span className="text-zinc-400 text-[11px] leading-relaxed block mt-0.5">
                  Real-time telemetry, noise profiling, and automated containment governor.
                </span>
              </div>
            </div>

            <div
              className="flex items-start gap-3.5 p-3.5 rounded-lg border border-zinc-800/80 bg-zinc-900/30 backdrop-blur-sm hover:border-red-900/40 hover:bg-zinc-900/50 transition-all duration-200 group cursor-default hover:translate-x-1 animate-login-enter"
              style={{ animationDelay: "340ms" }}
            >
              <div className="p-1.5 rounded-md bg-zinc-900 border border-zinc-800 text-zinc-400 group-hover:border-red-900/50 group-hover:text-red-500 transition-colors mt-0.5 shrink-0">
                <ShieldCheck size={15} />
              </div>
              <div className="flex-1 min-w-0">
                <strong className="text-zinc-200 block text-xs font-medium">Zero-Trust Ticket Barrier</strong>
                <span className="text-zinc-400 text-[11px] leading-relaxed block mt-0.5">
                  Cryptographically verified WebSocket sessions and immutable audit logging.
                </span>
              </div>
            </div>
          </div>
        </div>

        <div />
      </div>

      {/* Right Column */}
      <div className="col-span-12 lg:col-span-5 flex flex-col justify-center items-center p-6 sm:p-10 relative overflow-hidden">
        {/* Background breathing glow — communicates the system is live, not dormant */}
        <div className="pointer-events-none absolute inset-0 flex items-center justify-center overflow-hidden">
          <div className="h-[28rem] w-[28rem] rounded-full bg-red-900/[0.04] blur-[90px] animate-ares-breathe" />
        </div>

        {/* Mobile brand */}
        <div className="lg:hidden text-center mb-8 relative z-10 animate-login-enter">
          <img
            className="h-10 w-10 object-contain rounded-md border border-zinc-800 bg-zinc-900/60 p-1 mx-auto mb-3"
            src={brandMarkPath}
            alt="ARES"
          />
          <div className="text-xl font-semibold text-white tracking-tight">ARES Enclave</div>
          <p className="text-xs text-zinc-400 mt-1">Adversary Emulation Suite</p>
        </div>

        {/* Auth card */}
        <div
          className="relative z-10 w-full max-w-sm rounded-xl border border-zinc-800/80 bg-[#111114]/95 backdrop-blur-md p-7 shadow-2xl animate-login-enter transition-all duration-200"
          style={{ animationDelay: "140ms" }}
        >
          <div className="mb-6">
            <h2 className="text-lg font-semibold text-white tracking-tight">Operator Authentication</h2>
            <p className="text-xs text-zinc-500 mt-1">Sign in with your authorized enclave credentials</p>
          </div>

          <form onSubmit={(event) => void submit(event)} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1.5" htmlFor="operator-username">
                Username / Operator ID
              </label>
              <input
                id="operator-username"
                className="block w-full rounded-md border border-zinc-800 bg-[#09090b] px-3 py-2 text-sm text-white placeholder-zinc-600 transition-all duration-150 focus:border-red-800/60 focus:outline-none focus:ring-1 focus:ring-red-800/40 disabled:opacity-50"
                placeholder="operator"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
                disabled={isSubmitting}
                required
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1.5" htmlFor="operator-password">
                Password
              </label>
              <div className="relative">
                <input
                  id="operator-password"
                  className="block w-full rounded-md border border-zinc-800 bg-[#09090b] pl-3 pr-10 py-2 text-sm text-white placeholder-zinc-600 transition-all duration-150 focus:border-red-800/60 focus:outline-none focus:ring-1 focus:ring-red-800/40 disabled:opacity-50"
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="current-password"
                  placeholder="••••••••••••"
                  disabled={isSubmitting}
                  required
                />
                <button
                  type="button"
                  className="absolute inset-y-0 right-0 flex items-center pr-3 text-zinc-500 hover:text-zinc-200 transition-colors disabled:pointer-events-none"
                  onClick={() => setShowPassword((v) => !v)}
                  disabled={isSubmitting}
                  aria-label={showPassword ? "Hide password" : "Show password"}
                >
                  {showPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>
            </div>

            {error && (
              <div className="rounded-md border border-red-700/30 bg-red-700/10 px-3 py-2 text-xs text-red-400 flex items-start gap-2 animate-login-enter">
                <AlertCircle size={14} className="mt-0.5 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            <button
              className="w-full mt-2 flex items-center justify-center gap-2 rounded-md bg-zinc-100 hover:bg-white active:scale-[0.98] px-4 py-2.5 text-sm font-semibold text-zinc-950 transition-all duration-150 shadow-sm hover:shadow-[0_0_20px_rgba(255,255,255,0.10)] focus:outline-none focus:ring-2 focus:ring-zinc-400 focus:ring-offset-2 focus:ring-offset-[#111114] disabled:opacity-50 disabled:cursor-not-allowed"
              type="submit"
              disabled={isSubmitting}
            >
              {isSubmitting ? (
                <>
                  <Loader2 size={15} className="animate-spin text-zinc-900" />
                  <span>Signing in...</span>
                </>
              ) : (
                <span>Sign in</span>
              )}
            </button>
          </form>

          <div className="mt-6 border-t border-zinc-800/60 pt-4 text-center">
            <p className="text-[11px] text-zinc-500 leading-relaxed">
              Restricted security gateway. All access attempts are cryptographically verified and audited.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
