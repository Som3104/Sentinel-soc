import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Hand, ShieldCheck, Siren, X } from "lucide-react";
import { onMessage } from "../lib/realtime";
import { SEVERITY } from "../lib/format";

// Pop-up notifications for the things an analyst must not miss, on whatever page they're on.
// Alerts are too many to toast one by one (a full demo makes ~30), so only incidents,
// automatic containments and approval requests pop up.
const KIND = {
  incident: { icon: Siren, label: "New incident" },
  response: { icon: ShieldCheck, label: "Auto-response", color: "var(--color-ok)" },
  approval: { icon: Hand, label: "Approval needed", color: "var(--color-medium)" },
};
const MAX = 4;
const TTL_MS = 8000;

export default function Toasts() {
  const [toasts, setToasts] = useState([]);
  const navigate = useNavigate();
  const nextId = useRef(0);

  useEffect(() => onMessage((msg) => {
    const items = (msg.feed ?? []).filter((f) => KIND[f.kind]);
    if (!items.length) return;
    const now = Date.now();
    setToasts((ts) => [
      ...items.map((f) => ({ ...f, key: nextId.current++, until: now + TTL_MS })).reverse(),
      ...ts,
    ].slice(0, MAX));
  }), []);

  useEffect(() => {
    if (!toasts.length) return undefined;
    const id = setInterval(() => setToasts((ts) => ts.filter((t) => t.until > Date.now())), 1000);
    return () => clearInterval(id);
  }, [toasts.length]);

  const dismiss = (key) => setToasts((ts) => ts.filter((t) => t.key !== key));

  return (
    <div className="pointer-events-none fixed right-5 bottom-5 z-50 flex w-[360px] max-w-[calc(100vw-2.5rem)] flex-col gap-2">
      {toasts.map((t) => {
        const k = KIND[t.kind];
        const color = k.color ?? SEVERITY[t.severity]?.color ?? "var(--color-accent)";
        const Icon = k.icon;
        return (
          <div key={t.key}
            className="toast-in pointer-events-auto flex gap-3 rounded-xl border bg-panel/95 p-3 shadow-2xl shadow-black/40 backdrop-blur"
            style={{ borderColor: `color-mix(in srgb, ${color} 45%, var(--color-line))` }}>
            <div className="grid h-8 w-8 shrink-0 place-items-center rounded-lg"
              style={{ background: `color-mix(in srgb, ${color} 15%, transparent)`, color }}>
              <Icon size={16} />
            </div>
            <button className="min-w-0 flex-1 text-left" onClick={() => { navigate(t.link); dismiss(t.key); }}>
              <div className="text-[11px] font-semibold uppercase tracking-wider" style={{ color }}>
                {k.label}{t.kind === "incident" && t.severity ? ` · ${t.severity}` : ""}
              </div>
              <div className="mt-0.5 line-clamp-2 text-sm text-ink">{t.text}</div>
            </button>
            <button onClick={() => dismiss(t.key)} className="self-start text-faint hover:text-ink" aria-label="Dismiss">
              <X size={14} />
            </button>
          </div>
        );
      })}
    </div>
  );
}
