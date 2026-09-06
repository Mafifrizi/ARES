import { AlertCircle, Eye, EyeOff } from "lucide-react";
import { FormEvent, useState } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import { AresIgniteButton } from "./AresIgniteButton";
import { BackgroundAnimationCanvas } from "./BackgroundAnimationCanvas";
import { useAuth } from "./authContext";

const brandMarkPath = "/dashboard/brand/ares-mark.png";
const brandMascotPath = "/dashboard/brand/ares-mascot.png";

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
    <div className="min-h-[100dvh] w-full bg-[#09090b] text-[#f4f4f5] grid lg:grid-cols-2 selection:bg-red-700 selection:text-white">

      {/* Left Column: Focused Clean Sign In */}
      <div className="flex flex-col justify-between p-8 sm:p-12 xl:p-16 relative">
        {/* Brand Header */}
        <div className="flex items-center gap-3">
          <img
            className="h-8 w-8 object-contain rounded-md border border-zinc-800 bg-zinc-900/80 p-1"
            src={brandMarkPath}
            alt="ARES"
          />
          <div>
            <h1 className="text-sm font-semibold text-white tracking-tight">ARES Dashboard</h1>
            <span className="text-xs text-zinc-500 font-mono">v6.0</span>
          </div>
        </div>

        {/* Center Form Container */}
        <div className="w-full max-w-sm mx-auto my-auto py-8">
          <div className="mb-6">
            <h2 className="text-2xl font-semibold text-white tracking-tight">Sign In</h2>
            <p className="text-xs text-zinc-400 mt-1.5 leading-relaxed">
              Enter your credentials to access your dashboard.
            </p>
          </div>

          <form onSubmit={(event) => void submit(event)} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1.5" htmlFor="operator-username">
                Username / Operator ID
              </label>
              <input
                id="operator-username"
                className="block w-full rounded-md border border-zinc-800 bg-zinc-950 px-3.5 py-2.5 text-sm text-white placeholder-zinc-600 transition-all duration-150 focus:border-red-600 focus:outline-none focus:ring-1 focus:ring-red-600 disabled:opacity-50"
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
                  className="block w-full rounded-md border border-zinc-800 bg-zinc-950 pl-3.5 pr-10 py-2.5 text-sm text-white placeholder-zinc-600 transition-all duration-150 focus:border-red-600 focus:outline-none focus:ring-1 focus:ring-red-600 disabled:opacity-50"
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
                  className="absolute inset-y-0 right-0 flex items-center pr-3 text-zinc-500 hover:text-zinc-300 transition-colors disabled:pointer-events-none"
                  onClick={() => setShowPassword((v) => !v)}
                  disabled={isSubmitting}
                  aria-label={showPassword ? "Hide password" : "Show password"}
                >
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            {error && (
              <div className="rounded-md border border-red-900/50 bg-red-950/30 px-3 py-2 text-xs text-red-400 flex items-start gap-2 animate-login-enter">
                <AlertCircle size={14} className="mt-0.5 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            <AresIgniteButton isLoading={isSubmitting} disabled={isSubmitting}>
              Sign in
            </AresIgniteButton>
          </form>
        </div>

        {/* Minimalist Subtext Footer */}
        <div className="text-xs text-zinc-500 font-mono">
          ARES Automated Red Team Engagement System
        </div>
      </div>

      {/* Right Column: High-Precision Modern Presentation with Living Canvas Motion */}
      <div className="hidden lg:flex flex-col items-center justify-center p-12 xl:p-16 border-l border-zinc-800/80 bg-[#070709] relative overflow-hidden select-none">
        {/* Dynamic Architectural Grid & Traveling Light Pulses Canvas */}
        <BackgroundAnimationCanvas className="opacity-90" />

        {/* Ambient Warmth Glow behind content */}
        <div className="pointer-events-none absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 h-[32rem] w-[32rem] rounded-full bg-red-950/15 blur-[140px]" />

        {/* ARES Cyber Dragon Mascot with Tastefully Lowered Opacity */}
        <div className="pointer-events-none absolute -right-6 -bottom-8 w-[520px] xl:w-[600px] select-none opacity-35 transition-opacity duration-700">
          <img
            src={brandMascotPath}
            alt="ARES Dragon Mascot"
            className="w-full h-auto object-contain drop-shadow-[0_0_60px_rgba(220,38,38,0.3)]"
          />
        </div>

        {/* Centerpiece Content */}
        <div className="relative z-10 w-full max-w-md space-y-8">
          {/* Typography */}
          <div>
            <h2 className="text-3xl xl:text-4xl font-semibold text-white tracking-tight leading-tight">
              Offensive security,
              <br />
              <span className="text-zinc-500 font-normal">engineered for precision.</span>
            </h2>
            <p className="text-sm text-zinc-400 leading-relaxed mt-3 max-w-sm">
              Automate multi-stage attack chains with deterministic execution and full audit fidelity.
            </p>
          </div>

          {/* Clean Enterprise Specification Card */}
          <div className="w-full max-w-sm rounded-lg border border-zinc-800/80 bg-zinc-950/80 backdrop-blur-md p-5 shadow-2xl">
            <div className="text-xs font-mono font-medium text-zinc-300 tracking-wider pb-3 border-b border-zinc-800/80 uppercase">
              System Environment
            </div>

            <div className="divide-y divide-zinc-800/60 text-xs font-mono">
              <div className="flex items-center justify-between py-2.5">
                <span className="text-zinc-500">Architecture</span>
                <span className="text-zinc-200">Distributed Core</span>
              </div>
              <div className="flex items-center justify-between py-2.5">
                <span className="text-zinc-500">Policy Engine</span>
                <span className="text-zinc-200">Deterministic Fail-Closed</span>
              </div>
              <div className="flex items-center justify-between py-2.5">
                <span className="text-zinc-500">Isolation Layer</span>
                <span className="text-zinc-200">Hermetic Enclave</span>
              </div>
              <div className="flex items-center justify-between py-2.5">
                <span className="text-zinc-500">Audit Protocol</span>
                <span className="text-zinc-200">Cryptographic Verification</span>
              </div>
            </div>

            <div className="mt-3 pt-3 border-t border-zinc-800/60 flex items-center justify-between text-[11px] font-mono text-zinc-500">
              <span>Host: 127.0.0.1</span>
              <span>API Gateway: 8080</span>
            </div>
          </div>
        </div>
      </div>

    </div>
  );
}
