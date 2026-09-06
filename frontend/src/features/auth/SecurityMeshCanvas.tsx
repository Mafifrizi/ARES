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
    // R   = circumradius (center → corner)
    // HH  = hex height flat-to-flat = √3 × R
    // COL = horizontal distance between centers = R × 1.5 (columns overlap by R/2)
    // ROW = vertical distance between centers in same column = HH
    // Odd columns are offset down by HH/2
    const R = 24;
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
    const MOUSE_R  = 140;   // radius of mouse-proximity glow
    const DRAW_R   = R - 1; // slightly smaller so gaps show between scales

    let t = 0;

    const render = () => {
      if (document.hidden) { animId = requestAnimationFrame(render); return; }
      t += 0.006; // breathing speed — slow, subliminal

      ctx!.clearRect(0, 0, W, H);

      for (const { cx, cy } of hexes) {
        // Skip hexes well outside the canvas
        if (cx < -R * 2 || cx > W + R * 2 || cy < -R * 2 || cy > H + R * 2) continue;

        // ── Mouse proximity glow (dragon reacts to operator) ──────────────
        const dx = cx - mouse.x;
        const dy = cy - mouse.y;
        const distM = Math.hypot(dx, dy);
        const mouse_t = distM < MOUSE_R ? 1 - distM / MOUSE_R : 0;

        // ── Breathing wave (diagonal drift = direction of dragon's attention) ─
        // Wave travels diagonally top-left → bottom-right
        const wave_t = Math.sin(t + cx * 0.012 + cy * 0.009) * 0.5 + 0.5;

        // Combined intensity
        const glow = Math.max(mouse_t * 0.9, wave_t * 0.13);

        // ── Draw hex path ─────────────────────────────────────────────────
        ctx!.beginPath();
        for (let i = 0; i < 6; i++) {
          const px = cx + DRAW_R * OFFSETS[i][0];
          const py = cy + DRAW_R * OFFSETS[i][1];
          i === 0 ? ctx!.moveTo(px, py) : ctx!.lineTo(px, py);
        }
        ctx!.closePath();

        // Fill — barely there at rest, deep crimson near cursor
        ctx!.fillStyle = `rgba(180, 15, 15, ${glow * 0.11})`;
        ctx!.fill();

        // Border — the scale edge, always visible but dim at rest
        const border = 0.14 + glow * 0.5;
        ctx!.strokeStyle = `rgba(220, 38, 38, ${border})`;
        ctx!.lineWidth = 0.75;
        ctx!.stroke();
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
