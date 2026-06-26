import type { ReactNode } from "react";

type PageHeaderProps = {
  title: string;
  description: string;
  actions?: ReactNode;
};

export default function PageHeader({ title, description, actions }: PageHeaderProps) {
  return (
    <div className="sticky top-0 z-30 -mx-8 px-8 py-5 bg-slate-950/95 backdrop-blur border-b border-slate-800/80">
      <header className="flex items-start justify-between gap-6">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">{title}</h1>
          <p className="text-slate-400">{description}</p>
        </div>
        {actions ? <div className="shrink-0">{actions}</div> : null}
      </header>
    </div>
  );
}
