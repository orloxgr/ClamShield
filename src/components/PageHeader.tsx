import type { ReactNode } from "react";

type PageHeaderProps = {
  title: string;
  description: string;
  actions?: ReactNode;
};

export default function PageHeader({ title, description, actions }: PageHeaderProps) {
  return (
    <div className="sticky top-0 z-30 -mx-8 px-8 py-5 bg-slate-950/95 backdrop-blur border-b border-slate-800/80">
      <header className="flex flex-wrap items-start justify-between gap-4 sm:gap-6">
        <div className="min-w-0">
          <h1 className="text-3xl font-bold text-white mb-2">{title}</h1>
          <p className="text-slate-400">{description}</p>
        </div>
        {actions ? <div className="min-w-0 max-w-full">{actions}</div> : null}
      </header>
    </div>
  );
}
