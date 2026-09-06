import { Loader2 } from "lucide-react";
import { ButtonHTMLAttributes, ReactNode, useRef } from "react";

interface AresIgniteButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  isLoading?: boolean;
  children: ReactNode;
}

/**
 * ARES Signature Interaction: Crimson Plasma Shockwave on click.
 * On mousedown: spawns an expanding radial shockwave ring (crimson) that erupts
 * outward from the exact click origin and dissolves in 500ms.
 * On hover: laser-border sweep via CSS class.
 * On loading: perimeter crimson pulse + dark inversion.
 * Pure imperative DOM + CSS - no animation library dependency.
 */
export function AresIgniteButton({
  isLoading,
  children,
  onClick,
  disabled,
  className: _className,
  ...props
}: AresIgniteButtonProps) {
  const buttonRef = useRef<HTMLButtonElement>(null);

  function spawnShockwave(e: React.MouseEvent<HTMLButtonElement>) {
    const btn = buttonRef.current;
    if (!btn || disabled || isLoading) return;

    const rect = btn.getBoundingClientRect();

    // Calculate click origin relative to button
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;

    // Diameter must cover entire button diagonally
    const diameter = Math.max(rect.width, rect.height) * 2.6;
    const radius = diameter / 2;

    // Spawn the shockwave ring element
    const ring = document.createElement("span");
    ring.style.cssText = `
      position: absolute;
      left: ${x - radius}px;
      top: ${y - radius}px;
      width: ${diameter}px;
      height: ${diameter}px;
      border-radius: 50%;
      pointer-events: none;
      animation: aresShockwave 520ms cubic-bezier(0.22, 1, 0.36, 1) forwards;
    `;

    btn.style.position = "relative";
    btn.style.overflow = "hidden";
    btn.appendChild(ring);

    ring.addEventListener("animationend", () => {
      ring.remove();
    });

    if (onClick) onClick(e);
  }

  return (
    <button
      ref={buttonRef}
      {...props}
      disabled={disabled || isLoading}
      onMouseDown={spawnShockwave}
      className={[
        "w-full mt-2 flex items-center justify-center gap-2 rounded-md px-4 py-2.5 text-sm font-semibold",
        "transition-all duration-200",
        "focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-zinc-950",
        "disabled:cursor-not-allowed",
        isLoading
          ? "bg-zinc-950 text-red-400 border border-red-800/60 ares-ignite-loading disabled:opacity-100 focus:ring-red-800/60"
          : "bg-zinc-100 hover:bg-white text-zinc-950 shadow-sm active:scale-[0.98] ares-ignite-idle focus:ring-zinc-400 disabled:opacity-50",
      ].join(" ")}
    >
      {isLoading ? (
        <>
          <Loader2 size={15} className="animate-spin text-red-500 shrink-0" />
          <span>Authenticating...</span>
        </>
      ) : (
        children
      )}
    </button>
  );
}
