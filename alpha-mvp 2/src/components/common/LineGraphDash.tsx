// src/components/charts/MiniSparkline.tsx
import  { useMemo } from "react";
import { Line } from "react-chartjs-2";
import {
  Chart as ChartJS,
  LineElement,
  PointElement,
  LinearScale,
  CategoryScale,
  Tooltip,
  Legend,
  Filler,
} from "chart.js";

ChartJS.register(LineElement, PointElement, LinearScale, CategoryScale, Tooltip, Legend, Filler);

export interface MiniSparklineProps {
  labels: (number | string)[];   // e.g. [0,5,10,...,60] (13 labels)
  datasets: { data: number[]; borderColor?: string }[]; // align to labels
  className?: string;            // to control sizing (use aspect-square for a square)
}

export default function MiniSparkline({ labels, datasets, className = "" }: MiniSparklineProps) {
  const chartData = useMemo(
    () => ({
      labels,
      datasets: datasets.map(d => ({
        data: d.data,
        borderColor: d.borderColor,
        pointRadius: 0,
        borderWidth: 2,
        fill: false,
        tension: 0.35,
      })),
    }),
    [labels, datasets]
  );

  const options = useMemo(
    () => ({
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      scales: {
        x: { display: false }, // hide axis completely
        y: { display: false, min: 0, max: 1000 }, // fixed domain, hidden
      },
      plugins: {
        legend: { display: false },
        tooltip: { enabled: false }, // only the line
      },
      elements: { line: { capBezierPoints: true } },
    }),
    []
  );

  return (
    <div className={`rounded-md bg-black/20 ${className}`}>
      <Line data={chartData} options={options as any} />
    </div>
  );
}

// // src/components/metrics/VendorSparklines.tsx
// import React, { useEffect, useState, useMemo } from "react";
// import MiniSparkline from "@/components/charts/MiniSparkline";

// type Series = {
//   id: string;
//   display_name: string;
//   counts_at_ticks: number[]; // length 13 for 0..60
//   color?: string;
// };
// type Payload = {
//   window_minutes: number;     // 60
//   bucket_minutes: number;     // 5
//   series: Series[];
// };

// const FIXED_LABELS = Array.from({ length: 13 }, (_, i) => i * 5); // [0,5,...,60]

// export default function VendorSparklines({ apiUrl, initialData }: { apiUrl?: string; initialData?: Payload }) {
//   const [data, setData] = useState<Payload | null>(initialData ?? null);
//   const [err, setErr] = useState<string | null>(null);

//   useEffect(() => {
//     if (!apiUrl) return;
//     let stop = false;
//     (async () => {
//       try {
//         const r = await fetch(apiUrl, { headers: { Accept: "application/json" } });
//         if (!r.ok) throw new Error(`HTTP ${r.status}`);
//         const j = (await r.json()) as Payload;
//         if (!stop) setData(j);
//       } catch (e: any) {
//         if (!stop) setErr(e?.message ?? "Failed to load");
//       }
//     })();
//     return () => { stop = true; };
//   }, [apiUrl]);

//   const items = useMemo(() => data?.series ?? [], [data]);

//   if (err) return <div className="text-red-400">Error: {err}</div>;
//   if (!data) return <div className="opacity-70">Loading…</div>;

//   return (
//     <div className="space-y-3">
//       {items.map((s) => (
//         <div
//           key={s.id}
//           className="flex items-center justify-between rounded-xl border border-slate-800 bg-gradient-to-br from-slate-950 to-slate-900 p-3"
//         >
//           {/* Left: vendor name (from API) */}
//           <div className="text-sm md:text-base font-medium text-slate-100 pr-4">{s.display_name}</div>

//           {/* Right: square sparkline only (no axes). Adjust size via w-XX or h-XX */}
//           <div className="w-36 md:w-44 aspect-square">
//             <MiniSparkline
//               labels={FIXED_LABELS}
//               datasets={[{ data: s.counts_at_ticks, borderColor: s.color }]}
//               className="w-full h-full bg-slate-950/40"
//             />
//           </div>
//         </div>
//       ))}
//     </div>
//   );
// }
