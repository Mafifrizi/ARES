import { useEffect, useRef } from "react";

interface SecurityMeshCanvasProps {
  className?: string;
}

/**
 * SecurityMeshCanvas — ARES Dragon Scale Grid
 *
 * Renders a tiled hexagonal grid (dragon scales). At rest the scales are barely
 * visible — a ghostly crimson lattice. A slow diagonal breathing wave drifts
 * across the grid, keeping it alive. When the operator moves the cursor over
 * the panel the scales beneath react, glowing bright crimson, as if the dragon
 * is aware of the operator's presence.
 *
 * Motivation for every animation:
 *   • Hex grid         — dragon scales, the ARES identity made literal
 *   • Breathing wave   — the system is live, not dormant
 *   • Mouse proximity  — the dragon reacts to the operator approaching
 */
export function SecurityMeshCanvas({ className = "" }: SecurityMeshCanvasProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    if (typeof navigator !== "undefined" && navigator.userAgent.includes("jsdom")) return;

    let ctx: CanvasRenderingContext2D | null = null;
    try { ctx = canvas.getContext("2d"); } catch { return; }
    if (!ctx) return;

    let animId: number;
    let W = 0;
    let H = 0;
    const dpr = window.devicePixelRatio || 1;
    const mouse = { x: -9999, y: -9999 };

    // ── Hex geometry (flat-top orientation) ──────────────────────────────────
    const R = 25;
    const HH = Math.sqrt(3) * R;
    const COL = R * 1.5;
    const ROW = HH;

    // Six corner offsets for a flat-top hex (angles 0°, 60°, …, 300°)
    const OFFSETS = Array.from({ length: 6 }, (_, i) => {
      const a = (Math.PI / 3) * i;
      return [Math.cos(a), Math.sin(a)] as [number, number];
    });

    interface Hex { cx: number; cy: number }
    let hexes: Hex[] = [];

    const buildHexes = () => {
      hexes = [];
      const cols = Math.ceil(W / COL) + 3;
      const rows = Math.ceil(H / ROW) + 3;
      for (let c = -1; c < cols; c++) {
        const cx = c * COL;
        const yOff = c % 2 === 0 ? 0 : HH / 2;
        for (let r = -1; r < rows; r++) {
          hexes.push({ cx, cy: r * ROW + yOff });
        }
      }
    };

    const updateSize = () => {
      const rect = canvas.getBoundingClientRect();
      W = rect.width;
      H = rect.height;
      canvas.width  = Math.max(1, Math.floor(W * dpr));
      canvas.height = Math.max(1, Math.floor(H * dpr));
      ctx!.setTransform(1, 0, 0, 1, 0, 0);
      ctx!.scale(dpr, dpr);
      buildHexes();
    };

    updateSize();

    // ── Interaction handlers ──────────────────────────────────────────────────
    const onMouseMove = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      mouse.x = e.clientX - rect.left;
      mouse.y = e.clientY - rect.top;
    };
    const onMouseLeave = () => { mouse.x = -9999; mouse.y = -9999; };

    window.addEventListener("resize", updateSize);
    const parent = canvas.parentElement;
    parent?.addEventListener("mousemove", onMouseMove);
    parent?.addEventListener("mouseleave", onMouseLeave);

    // ── Render constants ──────────────────────────────────────────────────────
    const MOUSE_R  = 160;   // radius of mouse-proximity glow
    const DRAW_R   = R - 1.2; // clean spacing between scales

    let t = 0;

    const render = () => {
      if (document.hidden) { animId = requestAnimationFrame(render); return; }
      t += 0.009; // calm, authoritative breathing speed

      ctx!.clearRect(0, 0, W, H);

      for (const { cx, cy } of hexes) {
        // Skip hexes well outside the canvas
        if (cx < -R * 2 || cx > W + R * 2 || cy < -R * 2 || cy > H + R * 2) continue;

        // ── Mouse proximity (reactive layer) ──────────────────────────────
        const dx = cx - mouse.x;
        const dy = cy - mouse.y;
        const distM = Math.hypot(dx, dy);
        const mouse_t = distM < MOUSE_R ? (1 - distM / MOUSE_R) ** 1.5 : 0;

        // ── Autonomous harmonic waves (automatic breathing motion) ────────
        // Primary diagonal drift across dragon scales
        const wave1 = Math.sin(t + cx * 0.009 + cy * 0.007) * 0.5 + 0.5;
        // Secondary cross-drift for organic fluidity
        const wave2 = Math.cos(t * 0.7 - cx * 0.006 + cy * 0.008) * 0.5 + 0.5;
        const autoWave = wave1 * 0.7 + wave2 * 0.3;

        // Ambient energy is always visible and softly pulses
        const ambientGlow = 0.16 + autoWave * 0.40;

        // Total scale excitation: ambient wave plus operator cursor focus
        const glow = Math.min(1.0, ambientGlow + mouse_t * 0.65);

        // ── Draw hex path ─────────────────────────────────────────────────
        ctx!.beginPath();
        for (let i = 0; i < 6; i++) {
          const px = cx + DRAW_R * OFFSETS[i][0];
          const py = cy + DRAW_R * OFFSETS[i][1];
          i === 0 ? ctx!.moveTo(px, py) : ctx!.lineTo(px, py);
        }
        ctx!.closePath();

        // Fill — subtle warm ember glow on wave crests, concentrated under cursor
        const fillAlpha = glow * 0.13;
        ctx!.fillStyle = `rgba(185, 28, 28, ${fillAlpha})`;
        ctx!.fill();

        // Border — distinct, crisp crimson lattice lines
        const borderAlpha = 0.20 + glow * 0.38;
        ctx!.strokeStyle = `rgba(239, 68, 68, ${borderAlpha})`;
        ctx!.lineWidth = 0.85;
        ctx!.stroke();

        // Subtle node dot on energetic scale centers (looks like a live cyber lattice)
        if (glow > 0.48) {
          const dotAlpha = (glow - 0.48) * 0.7;
          ctx!.beginPath();
          ctx!.arc(cx, cy, 1.2, 0, Math.PI * 2);
          ctx!.fillStyle = `rgba(252, 165, 165, ${dotAlpha})`;
          ctx!.fill();
        }
      }

      animId = requestAnimationFrame(render);
    };

    animId = requestAnimationFrame(render);

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener("resize", updateSize);
      parent?.removeEventListener("mousemove", onMouseMove);
      parent?.removeEventListener("mouseleave", onMouseLeave);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className={`pointer-events-none absolute inset-0 h-full w-full ${className}`}
      aria-hidden="true"
    />
  );
}
