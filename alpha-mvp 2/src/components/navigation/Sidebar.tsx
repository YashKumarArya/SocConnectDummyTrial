import { NavLink } from "react-router-dom";
import { useState } from "react";
import {
  GripVertical,
  LayoutDashboard,
  AlertTriangle,
  X,
  Diameter,
} from "lucide-react";

type Item = {
  to: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  end?: boolean;
};

const NAV_ITEMS: Item[] = [
  { to: "/app/dashboard", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/app/alerts", label: "Alerts", icon: AlertTriangle },
];

const railBase =
  "fixed left-0 top-0 h-screen w-16 flex flex-col items-center border-r";
const railColors =
  "bg-[#05090d] border-white/10"; // very dark blue, near-black

const iconButton =
  "inline-flex items-center justify-center rounded-md hover:bg-[#032e30] transition focus:outline-none focus:ring-2 focus:ring-white/20";

const iconLinkBase =
  "w-10 h-10 flex items-center justify-center rounded-md transition ";
const iconLinkActive =
  "bg-[#032e30] text-white";
const iconLinkInactive =
  "text-gray-200 hover:bg-white/10 hover:text-[#032e30]";

const expandedPanelBase =
  "fixed left-0 top-0 h-screen w-72 max-w-[80vw] shadow-xl border-r";
const expandedPanelColors =
  "bg-[#0b1116] border-white/10";

export default function Sidebar() {
  const [open, setOpen] = useState(false);

  return (
    <>
      {/* Thin icon rail */}
      <aside className={`${railBase} ${railColors} z-40`}>
        {/* Toggle button (3 vertical lines) */}
        <button
          aria-label="Open sidebar"
          aria-expanded={open}
          onClick={() => setOpen(true)}
          className={`${iconButton} mt-4 w-10 h-10 text-gray-300`}
        >
          <GripVertical className="w-5 h-5" />
        </button>

        {/* Divider */}
        <div className="my-4 h-px w-8 bg-white/10" />

        {/* Icon-only nav */}
        <nav className="flex-1 flex flex-col gap-2">
          {NAV_ITEMS.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              title={label}
              className={({ isActive }) =>
                `${iconLinkBase} ${isActive ? iconLinkActive : iconLinkInactive}`
              }
            >
              <Icon className="w-5 h-5" />
            </NavLink>
          ))}
        </nav>
      </aside>

      {/* Expanded overlay panel + backdrop (only when open) */}
      {open && (
        <>
          {/* Backdrop with blur */}
          <button
            aria-label="Close sidebar backdrop"
            onClick={() => setOpen(false)}
            className="fixed inset-0 z-40 bg-black/40 backdrop-blur-sm"
          />

          {/* Slide-in panel */}
          <div
            className={`${expandedPanelBase} ${expandedPanelColors} z-50 transform transition-transform duration-200 translate-x-0`}
            role="dialog"
            aria-modal="true"
          >
            {/* Header row */}
            <div className="flex items-center justify-between p-4 border-b border-white/10">
              <div className="flex items-center gap-2">
                <Diameter className="w-7 h-7 text-gray-300" />
                <span className="text-2xl font-bold text-gray-200">Alpha</span>
              </div>
              <button
                aria-label="Close sidebar"
                onClick={() => setOpen(false)}
                className={`${iconButton} w-9 h-9 text-gray-300`}
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Full nav (icon + label) */}
            <nav className="p-3 space-y-1">
              {NAV_ITEMS.map(({ to, label, icon: Icon, end }) => (
                <NavLink
                  key={to}
                  to={to}
                  end={end}
                  className={({ isActive }) =>
                    [
                      "flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition",
                      "hover:bg-white/10",
                      isActive ? "bg-[#032e30] text-white" : "text-gray-300",
                    ].join(" ")
                  }
                  onClick={() => setOpen(false)}
                >
                  <Icon className="w-5 h-5" />
                  <span>{label}</span>
                </NavLink>
              ))}
            </nav>
          </div>
        </>
      )}
    </>
  );
}
