// import { useMemo, useState } from "react";
// import { Search, Eye, Trash2 } from "lucide-react";
// import StatusPill from "@/components/common/StatusPill";
// import { CustomButton } from "@/components/common/CustomButton";
// import type { AlertRow } from "@/mock/alerts";
// import { mockAlerts } from "@/mock/alerts";


// const SEVERITY_TONE = {
//   Critical: "red",
//   High: "amber",   
//   Medium: "yellow",
//   Low: "green",
// } as const;

// const STATUS_TONE = {
//   Active: "red",
//   Investigating: "orange",
//   Resolved: "green",
//   "Pending Patch": "amber",
//   Dismissed: "gray",
// } as const;

// export default function AlertsPage() {
//   const [q, setQ] = useState("");

//   // Search
//   const filtered: AlertRow[] = useMemo(() => {
//     const needle = q.trim().toLowerCase();
//     if (!needle) return mockAlerts;
//     return mockAlerts.filter((a) =>
//       [a.id, a.source, a.title, a.severity, a.status, a.analyst, a.recommendation]
//         .filter(Boolean)
//         .some((v) => String(v).toLowerCase().includes(needle))
//     );
//   }, [q]);

//   const handleView = (id: string) => {
//     // open drawer/modal or navigate
//     console.log("view", id);
//   };

//   const handleDelete = (id: string) => {
//     // confirm + perform delete
//     console.log("delete", id);
//   };

//   return (
//     <div className="space-y-4">
//       {/* Sticky toolbar (no box). Sits under the app header (h-14). */}
//       <div className="sticky z-10 bg-transparent pt-1 pb-2">
//         <div className="w-full py-2 flex items-center gap-14 backdrop-blur-md">
//           {/* Heading */}
//           <h3 className="text-3xl font-roboto font-semibold text-white whitespace-nowrap">
//             Smart Alert Management
//           </h3>

//           {/* Search next to heading */}
//           <div className="flex items-center gap-2 flex-1 max-w-xl ml-2">
//             <div className="relative w-full">
//               <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400">
//                 <Search className="w-4 h-4" />
//               </span>
//               <input
//                 value={q}
//                 onChange={(e) => setQ(e.target.value)}
//                 placeholder="Search alerts…"
//                 className="w-full pl-9 pr-3 h-9 text-sm rounded-md bg-white/5 text-gray-200 placeholder:text-gray-400 border border-white/10 focus:outline-none focus:ring-2 focus:ring-white/20"
//               />
//             </div>
//           </div>

//           {/* Right corner: AI Filter button */}
//           <CustomButton
//                              title="AI Filter"
//                              onClick={() =>{}}
//                              className="px-3 py-1 rounded-xl text-white border font-roboto text-sm border-[#032e30] bg-transparent hover:bg-[#032e30] transition-colors"
//                            />
//         </div>
//       </div>

//       {/* Table card (rounded), self-contained vertical + horizontal scroll */}
//       <div
//         className={[
//           "relative rounded-xl border border-white/10 ",
//           "min-h-screen overflow-auto no-scrollbar", // vertical scroll (hidden)
//         ].join(" ")}
//       >
//         {/* Horizontal scroller (hidden scrollbar) */}
//         <div className="overflow-x-auto no-scrollbar">
//           {/* Keep some right padding at end of horizontal scroll */}
//           <div className="inline-block min-w-[1300px] w-full">
//             <table className="w-full text-sm">
//               <thead>
//                 <tr className="text-gray-300">
//                   <th className="px-4 py-3 text-left font-bebas font-medium">Alert ID</th>
//                   <th className="px-4 py-3 text-left font-bebas font-medium">Source</th>
//                   <th className="px-4 py-3 text-left font-bebas font-medium">Title</th>
//                   <th className="px-4 py-3 text-left font-bebas font-medium">Severity</th>
//                   <th className="px-4 py-3 text-left font-bebas font-medium">Status</th>
//                   <th className="px-4 py-3 text-left font-bebas font-medium">Assigned Analyst</th>
//                   <th className="px-4 py-3 text-left font-bebas font-medium">AI Recommendation</th>
//                   <th className="px-4 py-3 text-center font-bebas font-medium">Actions</th>
//                 </tr>
//               </thead>

//               <tbody className="divide-y divide-white/10">
//                 {filtered.length === 0 ? (
//                   <tr>
//                     <td colSpan={8} className="px-4 py-10 text-center text-gray-400">
//                       No alerts yet. Connect your data source or load mock data for preview.
//                     </td>
//                   </tr>
//                 ) : (
//                   filtered.map((a) => (
//                     <tr key={a.id} className="text-gray-200">
//                       <td className="px-2 py-1 font-mono text-[15px] text-[hsl(220,30%,70%)]">
//                         {a.id}
//                       </td>
//                       <td className="px-4 py-1 font-roboto">{a.source}</td>
//                       <td className="px-4 py-1 font-roboto">{a.title}</td>
//                       <td className="px-4 py-1 font-roboto">
//                         <StatusPill label={a.severity} tone={SEVERITY_TONE[a.severity]} />
//                       </td>
//                       <td className="px-4 py-1 font-roboto">
//                         <StatusPill label={a.status} tone={STATUS_TONE[a.status]} />
//                       </td>
//                       <td className="px-4 py-1 font-roboto">{a.analyst}</td>
//                       <td className="px-4 py-1 text-gray-300 font-roboto">{a.recommendation}</td>
//                       <td className="px-4 py-1 font-roboto">
//                         <div className="flex items-center justify-end gap-2">
//                           <button
//                             aria-label={`View ${a.id}`}
//                             onClick={() => handleView(a.id)}
//                             className="w-9 h-9 inline-flex items-center justify-center rounded-md text-gray-300 hover:bg-white/10"
//                           >
//                             <Eye className="w-4 h-4" />
//                           </button>
//                           <button
//                             aria-label={`Delete ${a.id}`}
//                             onClick={() => handleDelete(a.id)}
//                             className="w-9 h-9 inline-flex items-center justify-center rounded-md text-gray-300 hover:bg-red-500/10 hover:text-red-300"
//                           >
//                             <Trash2 className="w-4 h-4" />
//                           </button>
//                         </div>
//                       </td>
//                     </tr>
//                   ))
//                 )}
//               </tbody>
//             </table>
//           </div>
//         </div>

//         {/* Small bottom spacer so last row isn't flush */}
//         <div className="h-2" />
//       </div>
//     </div>
//   );
// }

import { useEffect, useMemo, useState, useCallback } from "react";
import { Search, Eye, Trash2, Loader2 } from "lucide-react";
import StatusPill from "@/components/common/StatusPill";
import { CustomButton } from "@/components/common/CustomButton";
// Reuse your existing type. (You can move this type to a shared `types/alerts.ts` later.)
import type { AlertRow } from "@/mock/alerts";

const ENDPOINT = "http://localhost:3002/api/edr/alertslist";

const SEVERITY_TONE = {
  Critical: "red",
  High: "amber",
  Medium: "yellow",
  Low: "green",
} as const;

const STATUS_TONE = {
  Active: "red",
  Investigating: "orange",
  Resolved: "green",
  "Pending Patch": "amber",
  Dismissed: "gray",
} as const;

type ApiResponse<T> = {
  ok: boolean;
  // The API can return: an array, { items: [...] }, or an object keyed by id.
  data: unknown;
};

function normalizeApiData(raw: unknown): AlertRow[] {
  if (Array.isArray(raw)) return raw as AlertRow[];
  if (raw && typeof raw === "object") {
    const obj = raw as Record<string, unknown>;
    if (Array.isArray((obj as any).items)) return (obj as any).items as AlertRow[];
    return Object.values(obj) as AlertRow[];
  }
  return [];
}

function isAlertRowLike(x: any): x is AlertRow {
  return (
    x &&
    typeof x === "object" &&
    typeof x.id === "string" &&
    typeof x.source === "string" &&
    typeof x.title === "string" &&
    typeof x.severity === "string" &&
    typeof x.status === "string" &&
    typeof x.analyst === "string" &&
    typeof x.recommendation === "string"
  );
}

export default function AlertsPage() {
  const [q, setQ] = useState("");
  const [alerts, setAlerts] = useState<AlertRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadToken, setReloadToken] = useState(0); // for manual refresh

  const fetchAlerts = useCallback(async (signal?: AbortSignal) => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(ENDPOINT, {
        method: "GET",
        headers: { Accept: "application/json" },
        signal,
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      const json = (await res.json()) as ApiResponse<AlertRow[]>;
      if (!json?.ok) throw new Error("API returned ok=false");

      const rows = normalizeApiData(json.data).filter(isAlertRowLike);
      setAlerts(rows);
    } catch (e: any) {
      if (e?.name === "AbortError") return; // ignore aborted fetch
      setError(e?.message || "Failed to load alerts");
      setAlerts([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    fetchAlerts(controller.signal);
    return () => controller.abort();
  }, [fetchAlerts, reloadToken]);

  const filtered: AlertRow[] = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return alerts;
    return alerts.filter((a) =>
      [a.id, a.source, a.title, a.severity, a.status, a.analyst, a.recommendation]
        .filter(Boolean)
        .some((v) => String(v).toLowerCase().includes(needle))
    );
  }, [q, alerts]);

  const handleView = (id: string) => {
    // open drawer/modal or navigate
    console.log("view", id);
  };

  const handleDelete = (id: string) => {
    // confirm + perform delete
    console.log("delete", id);
  };

  return (
    <div className="space-y-4">
      {/* Sticky toolbar */}
      <div className="sticky z-10 bg-transparent pt-1 pb-2">
        <div className="w-full py-2 flex items-center gap-14 backdrop-blur-md">
          <h3 className="text-3xl font-roboto font-semibold text-white whitespace-nowrap">
            Smart Alert Management
          </h3>

          {/* Search next to heading */}
          <div className="flex items-center gap-2 flex-1 max-w-xl ml-2">
            <div className="relative w-full">
              <span className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400">
                <Search className="w-4 h-4" />
              </span>
              <input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="Search alerts…"
                className="w-full pl-9 pr-3 h-9 text-sm rounded-md bg-white/5 text-gray-200 placeholder:text-gray-400 border border-white/10 focus:outline-none focus:ring-2 focus:ring-white/20"
              />
            </div>
          </div>

          {/* Right corner: AI Filter + Refresh */}
          <div className="flex items-center gap-2">
            <CustomButton
              title="AI Filter"
              onClick={() => {}}
              className="px-3 py-1 rounded-xl text-white border font-roboto text-sm border-[#032e30] bg-transparent hover:bg-[#032e30] transition-colors"
            />
            <CustomButton
              title="Refresh"
              onClick={() => setReloadToken((v) => v + 1)}
              className="px-3 py-1 rounded-xl text-white border font-roboto text-sm border-white/10 bg-white/5 hover:bg-white/10 transition-colors"
            />
          </div>
        </div>
      </div>

      {/* Table card */}
      <div
        className={[
          "relative rounded-xl border border-white/10 ",
          "min-h-screen overflow-auto no-scrollbar",
        ].join(" ")}
      >
        <div className="overflow-x-auto no-scrollbar">
          <div className="inline-block min-w-[1300px] w-full">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-gray-300">
                  <th className="px-4 py-3 text-left font-bebas font-medium">Alert ID</th>
                  <th className="px-4 py-3 text-left font-bebas font-medium">Source</th>
                  <th className="px-4 py-3 text-left font-bebas font-medium">Title</th>
                  <th className="px-4 py-3 text-left font-bebas font-medium">Severity</th>
                  <th className="px-4 py-3 text-left font-bebas font-medium">Status</th>
                  <th className="px-4 py-3 text-left font-bebas font-medium">Assigned Analyst</th>
                  <th className="px-4 py-3 text-left font-bebas font-medium">AI Recommendation</th>
                  <th className="px-4 py-3 text-center font-bebas font-medium">Actions</th>
                </tr>
              </thead>

              <tbody className="divide-y divide-white/10">
                {loading ? (
                  <tr>
                    <td colSpan={8} className="px-4 py-10 text-center text-gray-400">
                      <div className="inline-flex items-center gap-2">
                        <Loader2 className="w-4 h-4 animate-spin" /> Loading alerts…
                      </div>
                    </td>
                  </tr>
                ) : error ? (
                  <tr>
                    <td colSpan={8} className="px-4 py-10 text-center text-red-300">
                      {error}{" "}
                      <button
                        onClick={() => setReloadToken((v) => v + 1)}
                        className="ml-2 underline hover:opacity-80"
                      >
                        Retry
                      </button>
                    </td>
                  </tr>
                ) : filtered.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="px-4 py-10 text-center text-gray-400">
                      No alerts yet.
                    </td>
                  </tr>
                ) : (
                  filtered.map((a) => (
                    <tr key={a.id} className="text-gray-200">
                      <td className="px-2 py-1 font-mono text-[15px] text-[hsl(220,30%,70%)]">
                        {a.id}
                      </td>
                      <td className="px-4 py-1 font-roboto">{a.source}</td>
                      <td className="px-4 py-1 font-roboto">{a.title}</td>
                      <td className="px-4 py-1 font-roboto">
                        <StatusPill label={a.severity} tone={SEVERITY_TONE[a.severity]} />
                      </td>
                      <td className="px-4 py-1 font-roboto">
                        <StatusPill label={a.status} tone={STATUS_TONE[a.status]} />
                      </td>
                      <td className="px-4 py-1 font-roboto">{a.analyst}</td>
                      <td className="px-4 py-1 text-gray-300 font-roboto">{a.recommendation}</td>
                      <td className="px-4 py-1 font-roboto">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            aria-label={`View ${a.id}`}
                            onClick={() => handleView(a.id)}
                            className="w-9 h-9 inline-flex items-center justify-center rounded-md text-gray-300 hover:bg-white/10"
                          >
                            <Eye className="w-4 h-4" />
                          </button>
                          <button
                            aria-label={`Delete ${a.id}`}
                            onClick={() => handleDelete(a.id)}
                            className="w-9 h-9 inline-flex items-center justify-center rounded-md text-gray-300 hover:bg-red-500/10 hover:text-red-300"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="h-2" />
      </div>
    </div>
  );
}

