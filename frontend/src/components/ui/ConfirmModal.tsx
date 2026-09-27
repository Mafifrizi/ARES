import { AlertTriangle, X } from "lucide-react";
import { useEffect, useRef } from "react";

export interface ConfirmModalProps {
  open: boolean;
  title: string;
  description: string;
  confirmLabel?: string;    // default: "Delete"
  cancelLabel?: string;     // default: "Cancel"
  variant?: "danger" | "warning";  // default: "danger"
  onConfirm: () => void;
  onCancel: () => void;
}

export function ConfirmModal({
  open,
  title,
  description,
  confirmLabel = "Delete",
  cancelLabel = "Cancel",
  variant = "danger",
  onConfirm,
  onCancel
}: ConfirmModalProps) {
  const confirmButtonRef = useRef<HTMLButtonElement | null>(null);

  useEffect(() => {
    if (!open) return;

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        event.preventDefault();
        onCancel();
      }
    }

    window.addEventListener("keydown", handleKeyDown);
    // Focus the action button for keyboard accessibility
    const timer = window.setTimeout(() => {
      confirmButtonRef.current?.focus();
    }, 50);

    return () => {
      window.removeEventListener("keydown", handleKeyDown);
      window.clearTimeout(timer);
    };
  }, [open, onCancel]);

  if (!open) return null;

  const isWarning = variant === "warning";

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/70 backdrop-blur-xs p-4"
      onClick={(e) => {
        if (e.target === e.currentTarget) {
          onCancel();
        }
      }}
      role="presentation"
    >
      <section
        aria-describedby="confirm-modal-description"
        aria-labelledby="confirm-modal-title"
        aria-modal="true"
        className="panel w-full max-w-md p-5 shadow-2xl border border-zinc-800 bg-[#111114] rounded-lg"
        role="dialog"
      >
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-3">
            <div
              className={`p-2 rounded-md shrink-0 ${
                isWarning
                  ? "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                  : "bg-rose-500/10 text-rose-400 border border-rose-500/20"
              }`}
            >
              <AlertTriangle size={18} />
            </div>
            <div>
              <h2 className="text-base font-semibold text-zinc-100" id="confirm-modal-title">
                {title}
              </h2>
              <p className="mt-1.5 text-sm text-zinc-400 leading-normal" id="confirm-modal-description">
                {description}
              </p>
            </div>
          </div>
          <button
            aria-label="Close dialog"
            className="icon-button icon-button-small text-zinc-400 hover:text-zinc-100"
            onClick={onCancel}
            type="button"
          >
            <X size={14} />
          </button>
        </div>

        <div className="mt-6 flex items-center justify-end gap-2.5">
          <button
            className="btn"
            onClick={onCancel}
            type="button"
          >
            {cancelLabel}
          </button>
          <button
            className={`btn ${
              isWarning
                ? "border-amber-500/40 bg-amber-500/10 text-amber-300 hover:bg-amber-500/20"
                : "btn-danger"
            }`}
            onClick={onConfirm}
            ref={confirmButtonRef}
            type="button"
          >
            {confirmLabel}
          </button>
        </div>
      </section>
    </div>
  );
}
