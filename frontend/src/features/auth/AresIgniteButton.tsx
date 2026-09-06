import { Loader2 } from "lucide-react";
import { ButtonHTMLAttributes, ReactNode, useEffect, useRef, useState } from "react";

interface FireParticle {
  x: number;
  y: number;
  vx: number;
  vy: number;
  life: number;       // 1..0
  maxLife: number;
  size: number;
  hue: number;        // 0=red .. 28=orange-red
  edge: 0 | 1 | 2 | 3; // 0=top 1=bottom 2=left 3=right
}

interface AresIgniteButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  isLoading?: boolean;
  children: ReactNode;
}

// Padding around button where fire lives (keep tight so it hugs the button)
const PAD = 32;

function spawnEdgeParticles(
  particles: FireParticle[],
  bw: number,
  bh: number,
  count: number
) {
  for (let i = 0; i < count; i++) {
    const edge = Math.floor(Math.random() * 4) as 0 | 1 | 2 | 3;
    let px = 0, py = 0, vx = 0, vy = 0;

    if (edge === 0) {
      // Top edge — fire curls up and slightly inward
      px = PAD + Math.random() * bw;
      py = PAD + (Math.random() * 4 - 2);   // tight to top border
      vy = -(Math.random() * 0.8 + 0.3);    // gently upward
      vx = (Math.random() - 0.5) * 0.6;
    } else if (edge === 1) {
      // Bottom edge — fire rises upward more strongly
      px = PAD + Math.random() * bw;
      py = PAD + bh + (Math.random() * 3);  // just below bottom border
      vy = -(Math.random() * 1.2 + 0.6);    // rise up toward button
      vx = (Math.random() - 0.5) * 0.8;
    } else if (edge === 2) {
      // Left edge
      px = PAD + (Math.random() * 3 - 1);
      py = PAD + Math.random() * bh;
      vy = -(Math.random() * 0.9 + 0.2);
      vx = -(Math.random() * 0.4);
    } else {
      // Right edge
      px = PAD + bw + (Math.random() * 3 - 1);
      py = PAD + Math.random() * bh;
      vy = -(Math.random() * 0.9 + 0.2);
      vx = Math.random() * 0.4;
    }

    particles.push({
      x: px,
      y: py,
      vx,
      vy,
      life: 1,
      maxLife: 18 + Math.random() * 18, // short life = stays close to button
      size: 3 + Math.random() * 5,
      hue: Math.random() * 28,
      edge,
    });
  }
}

export function AresIgniteButton({
  isLoading = false,
  children,
  disabled,
  className = "",
  ...props
}: AresIgniteButtonProps) {
  const wrapRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const particlesRef = useRef<FireParticle[]>([]);
  const rafRef = useRef<number>(0);
  const isHoveringRef = useRef(false);
  const [isHovering, setIsHovering] = useState(false);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    let ctx: CanvasRenderingContext2D | null = null;
    try {
      ctx = canvas.getContext("2d");
    } catch {
      return;
    }
    if (!ctx) return;

    function tick() {
      const particles = particlesRef.current;
      if (!ctx || !canvas) return;

      // Keep canvas fitted to wrapper
      const wrap = wrapRef.current;
      if (wrap) {
        const w = wrap.offsetWidth + PAD * 2;
        const h = wrap.offsetHeight + PAD * 2;
        if (canvas.width !== w || canvas.height !== h) {
          canvas.width = w;
          canvas.height = h;
          canvas.style.left = `-${PAD}px`;
          canvas.style.top = `-${PAD}px`;
        }

        // Continuously spawn while hovered
        if (isHoveringRef.current) {
          spawnEdgeParticles(particles, wrap.offsetWidth, wrap.offsetHeight, 5);
        }
      }

      ctx.clearRect(0, 0, canvas.width, canvas.height);

      for (let i = particles.length - 1; i >= 0; i--) {
        const p = particles[i];

        p.x += p.vx;
        p.y += p.vy;
        // Gentle buoyancy — fire hugs button
        p.vy -= 0.06;
        p.vx += (Math.random() - 0.5) * 0.18;
        p.vx *= 0.97;
        p.size *= 0.965;
        p.life -= 1 / p.maxLife;

        if (p.life <= 0 || p.size < 0.4) {
          particles.splice(i, 1);
          continue;
        }

        const alpha = Math.pow(p.life, 0.7);
        const r = Math.max(0.1, p.size);

        // Outer flame glow
        const glow = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, r * 2.8);
        glow.addColorStop(0, `hsla(${p.hue}, 100%, 65%, ${alpha * 0.45})`);
        glow.addColorStop(0.5, `hsla(${p.hue}, 100%, 45%, ${alpha * 0.2})`);
        glow.addColorStop(1, `hsla(${p.hue}, 100%, 30%, 0)`);
        ctx.beginPath();
        ctx.arc(p.x, p.y, r * 2.8, 0, Math.PI * 2);
        ctx.fillStyle = glow;
        ctx.fill();

        // Inner bright flame core
        const core = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, r);
        core.addColorStop(0, `hsla(${p.hue + 25}, 100%, 92%, ${alpha})`);
        core.addColorStop(0.35, `hsla(${p.hue + 10}, 100%, 65%, ${alpha * 0.85})`);
        core.addColorStop(0.8, `hsla(${p.hue}, 100%, 45%, ${alpha * 0.6})`);
        core.addColorStop(1, `hsla(${p.hue - 5}, 100%, 30%, 0)`);
        ctx.beginPath();
        ctx.arc(p.x, p.y, r, 0, Math.PI * 2);
        ctx.fillStyle = core;
        ctx.fill();
      }

      rafRef.current = requestAnimationFrame(tick);
    }

    rafRef.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(rafRef.current);
  }, []);

  // Burst fire on Enter key
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Enter" && !disabled && !isLoading) {
        const wrap = wrapRef.current;
        if (!wrap) return;
        spawnEdgeParticles(particlesRef.current, wrap.offsetWidth, wrap.offsetHeight, 60);
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [disabled, isLoading]);

  function handleMouseEnter() {
    if (disabled || isLoading) return;
    isHoveringRef.current = true;
    setIsHovering(true);
  }

  function handleMouseLeave() {
    isHoveringRef.current = false;
    setIsHovering(false);
  }

  // Burst fire on click
  function handleMouseDown() {
    if (disabled || isLoading) return;
    const wrap = wrapRef.current;
    if (!wrap) return;
    spawnEdgeParticles(particlesRef.current, wrap.offsetWidth, wrap.offsetHeight, 55);
  }

  return (
    <div ref={wrapRef} className="relative mt-2 w-full">
      {/* Fire canvas — absolute overlay, pointer-events none */}
      <canvas
        ref={canvasRef}
        className="absolute pointer-events-none z-20"
        style={{ mixBlendMode: "screen" }}
      />

      <button
        {...props}
        type="submit"
        disabled={disabled || isLoading}
        onMouseEnter={handleMouseEnter}
        onMouseLeave={handleMouseLeave}
        onMouseDown={handleMouseDown}
        className={[
          "relative z-10 w-full flex items-center justify-center gap-2 rounded-md px-4 py-2.5 text-sm font-medium text-white select-none",
          "transition-all duration-200 ease-out",
          "focus:outline-none focus-visible:ring-2 focus-visible:ring-red-500/60 focus-visible:ring-offset-2 focus-visible:ring-offset-zinc-950",
          "disabled:opacity-50 disabled:cursor-not-allowed",
          isLoading
            ? "bg-zinc-900 border border-zinc-800 text-zinc-400"
            : [
                "bg-[#A32D2D] border border-[#C43D3D] shadow-sm",
                "active:bg-[#8E2525] active:scale-[0.98]",
                isHovering
                  ? "bg-[#B83535] border-[#D94545] shadow-[0_0_20px_3px_rgba(196,61,61,0.45)]"
                  : "hover:bg-[#B83535]",
              ].join(" "),
          className,
        ].filter(Boolean).join(" ")}
      >
        {isLoading ? (
          <>
            <Loader2 size={15} className="animate-spin text-red-400 shrink-0" />
            <span>Authenticating...</span>
          </>
        ) : (
          children
        )}
      </button>
    </div>
  );
}
