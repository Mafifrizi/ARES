import { useEffect, useRef } from "react";

interface BackgroundAnimationCanvasProps {
  className?: string;
}

interface Pulse {
  x: number;
  y: number;
  vx: number;
  vy: number;
  life: number;
  maxLife: number;
  size: number;
}

export function BackgroundAnimationCanvas({ className = "" }: BackgroundAnimationCanvasProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    if (typeof navigator !== "undefined" && navigator.userAgent.includes("jsdom")) return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

    let ctx: CanvasRenderingContext2D | null = null;
    try {
      ctx = canvas.getContext("2d");
    } catch {
      return;
    }
    if (!ctx) return;

    let animId: number;
    let width = 0;
    let height = 0;
    const dpr = window.devicePixelRatio || 1;
    const mouse = { x: -9999, y: -9999 };

    const GRID_SIZE = 40;
    const pulses: Pulse[] = [];
    const MAX_PULSES = 18;

    const spawnPulse = () => {
      if (width <= 0 || height <= 0) return;
      const isHorizontal = Math.random() > 0.5;
      const col = Math.floor(Math.random() * (width / GRID_SIZE));
      const row = Math.floor(Math.random() * (height / GRID_SIZE));
      const x = col * GRID_SIZE;
      const y = row * GRID_SIZE;

      const speed = 1.2 + Math.random() * 1.5;
      pulses.push({
        x,
        y,
        vx: isHorizontal ? (Math.random() > 0.5 ? speed : -speed) : 0,
        vy: !isHorizontal ? (Math.random() > 0.5 ? speed : -speed) : 0,
        life: 0,
        maxLife: 60 + Math.floor(Math.random() * 80),
        size: 2 + Math.random() * 1.5
      });
    };

    const updateSize = () => {
      const rect = canvas.getBoundingClientRect();
      width = rect.width;
      height = rect.height;
      canvas.width = Math.max(1, Math.floor(width * dpr));
      canvas.height = Math.max(1, Math.floor(height * dpr));
      ctx!.setTransform(1, 0, 0, 1, 0, 0);
      ctx!.scale(dpr, dpr);
    };

    updateSize();

    const onMouseMove = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      mouse.x = e.clientX - rect.left;
      mouse.y = e.clientY - rect.top;
    };

    const onMouseLeave = () => {
      mouse.x = -9999;
      mouse.y = -9999;
    };

    window.addEventListener("resize", updateSize);
    const parent = canvas.parentElement;
    parent?.addEventListener("mousemove", onMouseMove);
    parent?.addEventListener("mouseleave", onMouseLeave);

    // Populate initial pulses
    for (let i = 0; i < 10; i++) {
      spawnPulse();
    }

    let frame = 0;

    const render = () => {
      frame++;
      ctx!.clearRect(0, 0, width, height);

      // 1. Draw Architectural Grid
      ctx!.lineWidth = 1;
      ctx!.strokeStyle = "rgba(113, 113, 122, 0.08)";

      ctx!.beginPath();
      for (let x = 0; x <= width; x += GRID_SIZE) {
        ctx!.moveTo(x, 0);
        ctx!.lineTo(x, height);
      }
      for (let y = 0; y <= height; y += GRID_SIZE) {
        ctx!.moveTo(0, y);
        ctx!.lineTo(width, y);
      }
      ctx!.stroke();

      // 2. Mouse Glow on Grid Intersections
      if (mouse.x > 0 && mouse.y > 0) {
        const glowRadius = 140;
        const radialGrad = ctx!.createRadialGradient(
          mouse.x,
          mouse.y,
          0,
          mouse.x,
          mouse.y,
          glowRadius
        );
        radialGrad.addColorStop(0, "rgba(220, 38, 38, 0.12)");
        radialGrad.addColorStop(0.5, "rgba(113, 113, 122, 0.06)");
        radialGrad.addColorStop(1, "rgba(0, 0, 0, 0)");

        ctx!.fillStyle = radialGrad;
        ctx!.fillRect(mouse.x - glowRadius, mouse.y - glowRadius, glowRadius * 2, glowRadius * 2);
      }

      // 3. Update & Draw Moving Grid Pulses
      if (frame % 15 === 0 && pulses.length < MAX_PULSES) {
        spawnPulse();
      }

      for (let i = pulses.length - 1; i >= 0; i--) {
        const p = pulses[i];
        p.x += p.vx;
        p.y += p.vy;
        p.life++;

        // Calculate fade in and fade out
        const progress = p.life / p.maxLife;
        const opacity = progress < 0.2
          ? progress / 0.2
          : 1 - (progress - 0.2) / 0.8;

        if (p.life >= p.maxLife || p.x < 0 || p.x > width || p.y < 0 || p.y > height) {
          pulses.splice(i, 1);
          continue;
        }

        // Draw pulse particle
        ctx!.beginPath();
        ctx!.arc(p.x, p.y, p.size, 0, Math.PI * 2);
        ctx!.fillStyle = `rgba(220, 38, 38, ${Math.max(0, opacity * 0.45)})`;
        ctx!.fill();

        // Subtle streak / tail
        ctx!.beginPath();
        ctx!.moveTo(p.x, p.y);
        ctx!.lineTo(p.x - p.vx * 3.5, p.y - p.vy * 3.5);
        ctx!.strokeStyle = `rgba(220, 38, 38, ${Math.max(0, opacity * 0.25)})`;
        ctx!.lineWidth = p.size * 0.8;
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
      aria-hidden="true"
      className={`pointer-events-none absolute inset-0 h-full w-full ${className}`}
    />
  );
}
