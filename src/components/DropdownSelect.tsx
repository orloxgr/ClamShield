import { ChevronDown } from "lucide-react";
import { type ReactNode, useEffect, useRef, useState } from "react";

export type DropdownOption = { value: string, label: ReactNode };

export default function DropdownSelect({
  ariaLabel,
  value,
  options,
  onChange,
  compact = false,
  align = "left",
  active = false
}: {
  ariaLabel: string,
  value: string,
  options: DropdownOption[],
  onChange: (value: string) => void,
  compact?: boolean,
  align?: "left" | "right",
  active?: boolean
}) {
  const [open, setOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement | null>(null);
  const selected = options.find(option => option.value === value) || options[0];

  useEffect(() => {
    if (!open) return;
    const handlePointerDown = (event: MouseEvent) => {
      if (!menuRef.current?.contains(event.target as Node)) setOpen(false);
    };
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", handlePointerDown);
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("mousedown", handlePointerDown);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [open]);

  return (
    <div ref={menuRef} className="relative inline-flex">
      <button
        type="button"
        aria-label={ariaLabel}
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={() => setOpen(current => !current)}
        className={`inline-flex items-center justify-between gap-1.5 rounded-md border transition-colors ${
          compact
            ? "border-slate-700/70 bg-slate-900/70 px-2 py-1 text-xs text-slate-300 hover:bg-slate-800 hover:text-slate-100"
            : "border-slate-800 bg-slate-950 px-3 py-2 text-sm text-slate-300 hover:border-slate-700 hover:bg-slate-900"
        } ${active ? "border-indigo-500/60 text-indigo-200" : ""}`}
      >
        <span className="truncate">{selected?.label}</span>
        <ChevronDown className={`shrink-0 transition-transform ${compact ? "w-3.5 h-3.5" : "w-4 h-4"} ${open ? "rotate-180" : ""}`} />
      </button>
      {open && (
        <div
          role="listbox"
          aria-label={ariaLabel}
          className={`absolute top-full z-30 mt-1 min-w-40 overflow-hidden rounded-md border border-slate-700 bg-slate-950 py-1 shadow-xl shadow-black/30 ${
            align === "right" ? "right-0" : "left-0"
          }`}
        >
          {options.map(option => {
            const selectedOption = option.value === value;
            return (
              <button
                key={option.value}
                type="button"
                role="option"
                aria-selected={selectedOption}
                onClick={() => {
                  onChange(option.value);
                  setOpen(false);
                }}
                className={`flex w-full items-center justify-between gap-3 px-3 py-2 text-left text-sm transition-colors ${
                  selectedOption ? "bg-indigo-500/15 text-indigo-200" : "text-slate-300 hover:bg-slate-800 hover:text-slate-100"
                }`}
              >
                <span className="truncate">{option.label}</span>
                {selectedOption && <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-indigo-300" />}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
