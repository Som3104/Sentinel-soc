import { Hammer } from "lucide-react";

// Placeholder for pages built in later phases. Shows what each page WILL do,
// so the dashboard already reads as a complete product roadmap.
// Every planned page is built (Phase 7 finished the last one). Kept for future additions.
export const UPCOMING = {};

export default function ComingSoon({ path }) {
  const p = UPCOMING[path];
  return (
    <div className="mx-auto mt-10 max-w-xl rounded-xl border border-dashed border-line bg-panel/70 p-8">
      <div className="flex items-center gap-3">
        <div className="grid h-10 w-10 place-items-center rounded-lg bg-panel-2 text-accent"><Hammer size={18} /></div>
        <div>
          <div className="font-mono text-xs text-accent">PHASE {p.phase}</div>
          <h2 className="text-lg font-semibold">{p.title}</h2>
        </div>
      </div>
      <p className="mt-4 text-sm text-muted">{p.blurb}</p>
      <ul className="mt-5 space-y-2">
        {p.features.map((f) => (
          <li key={f} className="flex gap-2.5 text-sm text-ink/90">
            <span className="mt-2 h-1 w-1 shrink-0 rounded-full bg-accent" />
            {f}
          </li>
        ))}
      </ul>
    </div>
  );
}
