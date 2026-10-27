import { type ReactNode, useEffect, useRef } from "react";
import { createPortal } from "react-dom";
import { X } from "lucide-react";

export default function Modal({
  title,
  onClose,
  children,
  busy = false,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  busy?: boolean;
}) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    ref.current?.focus();
    return () => previous?.focus();
  }, []);
  return createPortal(
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget && !busy) onClose();
      }}
    >
      <div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        tabIndex={-1}
        onKeyDown={(e) => {
          if (e.key === "Escape" && !busy) {
            e.stopPropagation();
            onClose();
          }
          if (e.key === "Tab") {
            const nodes = [
              ...(ref.current?.querySelectorAll<HTMLElement>(
                'button:not(:disabled),input:not(:disabled),textarea:not(:disabled),a[href],[tabindex="0"]',
              ) || []),
            ];
            const first = nodes[0],
              last = nodes[nodes.length - 1];
            if (
              e.shiftKey &&
              (document.activeElement === first ||
                document.activeElement === ref.current)
            ) {
              e.preventDefault();
              last?.focus();
            } else if (
              !e.shiftKey &&
              (document.activeElement === last ||
                document.activeElement === ref.current)
            ) {
              e.preventDefault();
              first?.focus();
            }
          }
        }}
        className="flex max-h-[90vh] w-full max-w-3xl flex-col rounded-2xl border border-slate-700 bg-slate-950 text-slate-200 shadow-2xl outline-none"
      >
        <div className="flex items-center justify-between border-b border-slate-800 px-6 py-4">
          <h2 className="text-xl font-semibold">{title}</h2>
          <button
            aria-label="Close dialog"
            disabled={busy}
            onClick={onClose}
            className="rounded p-2 hover:bg-slate-800"
          >
            <X size={20} />
          </button>
        </div>
        {children}
      </div>
    </div>,
    document.body,
  );
}
