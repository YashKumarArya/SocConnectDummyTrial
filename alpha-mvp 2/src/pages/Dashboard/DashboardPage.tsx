
"use client";

import { useEffect, useRef, useState } from "react";
import ThreatVisualizationbeta, {
  type IncomingEvent,
  type ResultEvent,
} from "@/components/common/DynamicDashboard"
import { TimeMetricBox } from "@/components/common/TimeMetricBox";
import { CustomTitleBox } from "@/components/common/CustomTitleBox";
import { ConfusionMatrix } from "@/components/common/ConfusionMatrix";
import AiHandledPie from "@/components/common/AiHandledPie";

// API endpoints (GET)
const VENDOR_API = "http://localhost:3002/api/edr/alerts/sources";
const RESULT_API = "http://localhost:3002/api/edr/alerts/results";

// API response shapes
type ApiResp<T> = { ok: boolean; data: T[] };
type ApiVendor = { alert_id: string; source: IncomingEvent["source"] };
type ApiResult = { alert_id: string; result: ResultEvent["result"] };

//API RESPONSE SHAPE FOR NOISE REDUCTION

type ApiNoise = { model_handled: number; escalate: number };
type ApiRespNoise = { ok: boolean; data: ApiNoise };

//TOP 3 MITRE TECHNIQUES

type ApiMitre = { mitre_name: string; mitre_id: string; count: number };
type ApiRespMitre = { ok: boolean; data: ApiMitre[] };

//Confusion Matrix 

type ApiConfusion = {
  true_positive: number;
  false_positive: number;
  true_negative: number;
  false_negative: number;
};

type ApiRespConfusion = { ok: boolean; data: ApiConfusion };

// TIME METRICS
type ApiTimeMetrics = {
  invest_mean_time: number;    // seconds
  response_mean_time: number;  // seconds
  time_saved: number;          // seconds
};
type ApiRespTimeMetrics = { ok: boolean; data: ApiTimeMetrics };


//Total Alerts INgested
type ApiTotalAlerts = { alerts_count: number };
type ApiRespTotalAlerts = { ok: boolean; data: ApiTotalAlerts };

export default function DashboardPage() {
  // Display counts (increment ONLY after pulses arrive)
  const [counts, setCounts] = useState({ tp: 0, fp: 0, esc: 0 });

  // Streams for the viz component
  const [vendorEvents, setVendorEvents] = useState<IncomingEvent[]>([]);
  const [resultEvents, setResultEvents] = useState<ResultEvent[]>([]);

  //For NOISE REDUCTION (AI HANDLED VS ESCALATED)
  const [noiseReduction, setNoiseReduction] = useState<[number, number]>([0, 0]);
  const [loadingNoise, setLoadingNoise] = useState(true);

  //FOR TOP 3 MITRE TECHNIQUES
  const [mitreTechniques, setMitreTechniques] = useState<ApiMitre[]>([]);
  const [loadingMitre, setLoadingMitre] = useState(true);

  //Confusion Matrix
  const [confusion, setConfusion] = useState<ApiConfusion | null>(null);
  const [loadingConfusion, setLoadingConfusion] = useState(true);

  // Time metrics (investigation mean time, response mean time, time saved)
  const [timeMetrics, setTimeMetrics] = useState<ApiTimeMetrics | null>(null);
  const [loadingTimeMetrics, setLoadingTimeMetrics] = useState(true);

    // For TOTAL ALERTS
  const [totalAlerts, setTotalAlerts] = useState<number | null>(null);
  const [loadingTotalAlerts, setLoadingTotalAlerts] = useState(true);


  // Pretty-print seconds as min/hrs like "1.5m", "2min", "3hrs"
const fmtSeconds = (s: number) => {
  if (s < 60) return `${s}s`;
  if (s < 3600) {
    // minutes
    const m = s / 60;
    return Number.isInteger(m) ? `${m}min` : `${m.toFixed(1)}min`;
  }
  // hours
  const h = s / 3600;
  return Number.isInteger(h) ? `${h}hrs` : `${h.toFixed(1)}hrs`;
};


  // Dedup across polls
  const seenVendor = useRef<Set<string>>(new Set());
  const seenResult = useRef<Set<string>>(new Set());
  // Guard against double increment
  const delivered = useRef<Set<string>>(new Set());

  // Poll vendors for INCOMING ALERTS (GET)
  useEffect(() => {
    let isMounted = true;
    let inFlight = false;
    const POLL_MS = 1000;

    const tick = async () => {
      if (inFlight) return;
      inFlight = true;
      try {
        const res = await fetch(VENDOR_API, { method: "GET", cache: "no-store" });
        const json = (await res.json()) as ApiResp<ApiVendor>;
        if (!isMounted || !json?.ok || !Array.isArray(json.data)) return;

        const newEvents: IncomingEvent[] = [];
        for (const item of json.data) {
          const id = item.alert_id;
          const src = item.source; // already canonical
          if (!id || !src) continue;
          if (seenVendor.current.has(id)) continue;
          seenVendor.current.add(id);
          newEvents.push({ alert_id: id, source: src });
        }
        if (newEvents.length) setVendorEvents((prev) => [...prev, ...newEvents]);
      } catch {
        // ignore network/parse blips
      } finally {
        inFlight = false;
      }
    };

    const interval = setInterval(tick, POLL_MS);
    tick(); // prime

    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  // Poll results for ALERTS GOING IN WHICH SECTION TP/FP/ESC (GET)
  useEffect(() => {
    let isMounted = true;
    let inFlight = false;
    const POLL_MS = 1000;

    const tick = async () => {
      if (inFlight) return;
      inFlight = true;
      try {
        const res = await fetch(RESULT_API, { method: "GET", cache: "no-store" });
        const json = (await res.json()) as ApiResp<ApiResult>;
        if (!isMounted || !json?.ok || !Array.isArray(json.data)) return;

        const newEvents: ResultEvent[] = [];
        for (const item of json.data) {
          const id = item.alert_id;
          const r = item.result; // "tp" | "fp" | "esc"
          if (!id || !r) continue;
          if (seenResult.current.has(id)) continue;
          seenResult.current.add(id);
          newEvents.push({ alert_id: id, result: r });
        }
        if (newEvents.length) setResultEvents((prev) => [...prev, ...newEvents]);
      } catch {
        // ignore network/parse blips
      } finally {
        inFlight = false;
      }
    };

    const interval = setInterval(tick, POLL_MS);
    tick(); // prime

    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  // For NOISE REDUCTION (AI HANDLED VS ESCALATED)
  //useEffect for polling/fetching your Noise Reduction numbers

useEffect(() => {
  let isMounted = true;
  const POLL_MS = 5000; // refresh every 5s

  const tick = async () => {
    try {
      const res = await fetch("http://localhost:3002/api/edr/alerts/noise", {
        method: "GET",
        cache: "no-store",
      });
      const json = (await res.json()) as ApiRespNoise;

      if (isMounted && json?.ok && json.data) {
        setNoiseReduction([json.data.model_handled, json.data.escalate]);
      }
    } catch (err) {
      console.error("Failed to fetch noise reduction:", err);
    } finally {
      if (isMounted) setLoadingNoise(false);
    }
  };

  tick(); // initial
  const interval = setInterval(tick, POLL_MS);

  return () => {
    isMounted = false;
    clearInterval(interval);
  };
}, []);

  // End For NOISE REDUCTION (AI HANDLED VS ESCALATED)

  // For TOP 3 MITRE TECHNIQUES
  useEffect(() => {
  let isMounted = true;
  const POLL_MS = 5000; // refresh every 5s

  const tick = async () => {
    try {
      const res = await fetch("http://localhost:3002/api/edr/alerts/mitre", {
        method: "GET",
        cache: "no-store",
      });
      const json = (await res.json()) as ApiRespMitre;

      if (isMounted && json?.ok && Array.isArray(json.data)) {
        setMitreTechniques(json.data.slice(0, 3)); // ensure max 3
      }
    } catch (err) {
      console.error("Failed to fetch MITRE techniques:", err);
    } finally {
      if (isMounted) setLoadingMitre(false);
    }
  };

  tick(); // first fetch
  const interval = setInterval(tick, POLL_MS);

  return () => {
    isMounted = false;
    clearInterval(interval);
  };
}, []);
  // End For TOP 3 MITRE TECHNIQUES

  // For Confusion Matrix

  useEffect(() => {
  let isMounted = true;
  const POLL_MS = 5000; // refresh every 5s

  const tick = async () => {
    try {
      const res = await fetch("http://localhost:3002/api/edr/alerts/confusion", {
        method: "GET",
        cache: "no-store",
      });
      const json = (await res.json()) as ApiRespConfusion;

      if (isMounted && json?.ok && json.data) {
        setConfusion(json.data);
      }
    } catch (err) {
      console.error("Failed to fetch confusion matrix:", err);
    } finally {
      if (isMounted) setLoadingConfusion(false);
    }
  };

  tick(); // first run
  const interval = setInterval(tick, POLL_MS);

  return () => {
    isMounted = false;
    clearInterval(interval);
  };
}, []);
  // End For Confusion Matrix


  // Poll TIME METRICS (investigation mean, response mean, time saved)
useEffect(() => {
  let isMounted = true;
  const POLL_MS = 5000; // refresh every 5s

  const tick = async () => {
    try {
      const res = await fetch("http://localhost:3002/api/edr/alerts/timemetrics", {
        method: "GET",
        cache: "no-store",
      });
      const json = (await res.json()) as ApiRespTimeMetrics;

      if (isMounted && json?.ok && json.data) {
        setTimeMetrics(json.data);
      }
    } catch (err) {
      console.error("Failed to fetch time metrics:", err);
      if (isMounted) setTimeMetrics(null);
    } finally {
      if (isMounted) setLoadingTimeMetrics(false);
    }
  };

  tick(); // initial
  const interval = setInterval(tick, POLL_MS);

  return () => {
    isMounted = false;
    clearInterval(interval);
  };
}, []);
  // End For TIME METRICS

  // For TOTAL ALERTS
   // Poll TOTAL ALERTS
  useEffect(() => {
    let isMounted = true;
    const POLL_MS = 5000; // every 5s

    const tick = async () => {
      try {
        const res = await fetch("http://localhost:3002/api/edr/alerts/totalalerts", {
          method: "GET",
          cache: "no-store",
        });
        const json = (await res.json()) as ApiRespTotalAlerts;

        if (isMounted && json?.ok && json.data) {
          setTotalAlerts(json.data.alerts_count);
        }
      } catch (err) {
        console.error("Failed to fetch total alerts:", err);
        if (isMounted) setTotalAlerts(null);
      } finally {
        if (isMounted) setLoadingTotalAlerts(false);
      }
    };

    tick(); // initial
    const interval = setInterval(tick, POLL_MS);

    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  // End For TOTAL ALERTS

  // Increment AFTER pulse reaches TP/FP/ESC (callback from viz)
  const handleResultDelivered = ({
    alert_id,
    result,
  }: {
    alert_id: string;
    result: "tp" | "fp" | "esc";
  }) => {
    if (delivered.current.has(alert_id)) return;
    delivered.current.add(alert_id);

    setCounts((c) => ({
      tp: c.tp + (result === "tp" ? 1 : 0),
      fp: c.fp + (result === "fp" ? 1 : 0),
      esc: c.esc + (result === "esc" ? 1 : 0),
    }));
  };
  return (
    // Important: let this fill the Outlet area exactly
    <div className="h-full relative z-10 flex flex-col min-h-0">
      {/* 2-row page that exactly fills height: top (graph area) + bottom (4 cards) */}
      <div className="grid grid-rows-[auto_1fr] gap-3 flex-1 min-h-0">
        {/* Top row */}
        <div className="min-h-0">
          <div className="flex flex-col lg:flex-row gap-3 h-full min-h-0">
            {/* Left: Flow */}
            <div className="w-full lg:w-[85%] min-h-0">
              {/* <div className="h-full rounded-2xl overflow-hidden border border-black bg-gradient-to-l from-black to-[#0a2e2f]"> */}
                <ThreatVisualizationbeta
                  counts={counts}
                  vendorEvents={vendorEvents}
                  resultEvents={resultEvents}
                  onResultDelivered={handleResultDelivered}
                  vendorPulseMs={1400}
                  resultPulseMs={1600}
                />
              {/* </div> */}
            </div>

            {/* Right: 3 vertical time metrics */}
            <div className="w-full lg:w-[15%] flex flex-col gap-3 min-h-0">
  <TimeMetricBox
    title="Investigation Mean Time"
    value={
      loadingTimeMetrics || !timeMetrics
        ? "—"
        : fmtSeconds(timeMetrics.invest_mean_time)
    }
    className="bg-white/5 border border-white/10 backdrop-blur text-slate-200 flex-1"
    titleClassName="text-xs"
    valueClassName="text-3xl font-extrabold"
  />
  <TimeMetricBox
    title="Response Mean Time"
    value={
      loadingTimeMetrics || !timeMetrics
        ? "—"
        : fmtSeconds(timeMetrics.response_mean_time)
    }
    className="bg-white/5 border border-white/10 backdrop-blur text-slate-200 flex-1"
    titleClassName="text-xs"
    valueClassName="text-3xl font-extrabold"
  />
  <TimeMetricBox
    title="Time Saved"
    value={
      loadingTimeMetrics || !timeMetrics
        ? "—"
        : fmtSeconds(timeMetrics.time_saved)
    }
    className="bg-white/5 border border-white/10 backdrop-blur text-slate-200 flex-1"
    titleClassName="text-xs"
    valueClassName="text-3xl font-extrabold"
  />
</div>

          </div>
        </div>

        {/* Bottom row: 4 cards exactly filling remaining space */}
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3 min-h-0">
          <CustomTitleBox
            title="Alerts Ingested"
            className="bg-[hsl(0,0%,8%)]/80"
            
          >
            {loadingTotalAlerts ? (
    <div className="text-slate-400 text-sm">Loading...</div>
  ) : (
    <>
      <div className="text-3xl font-bebas text-white font-extrabold">
        {totalAlerts ?? "—"}
      </div>
      <div className="text-xs font-rubik text-slate-500 mt-1">last 24h</div>
    </>
  )}
          </CustomTitleBox>

          <CustomTitleBox
            title="Top MITRE Techniques">
            <div className="space-y-2">
              {loadingMitre ? (
                <div className="text-slate-400 text-sm">Loading...</div>
              ) : (
                mitreTechniques.map((technique) => (
                  <div key={technique.mitre_id} className="flex items-center justify-between">
                    <div className="flex-1 min-w-0">
                      <div className="text-[0.7rem] font-medium text-white font-roboto truncate">
                        {technique.mitre_name}
                      </div>
                      <div className="text-[0.6rem] text-gray-400 font-roboto">
                        {technique.mitre_id}
                      </div>
                    </div>
                    <div className="text-[0.9rem] font-bebas">{technique.count}</div>
                  </div>
                ))
              )}
            </div>
          </CustomTitleBox>

          {/* <CustomTitleBox
            title="Noise Reduction"
            className=" bg-[hsl(0,0%,8%)]/80 text-slate-200"
            titleClassName="text-slate-300 text-lg font-rubik"
          >
            <AiHandledPie labels={['AI','Escalate']} data={[18,2]}/>
          </CustomTitleBox> */}
          <CustomTitleBox
            title="Noise Reduction"
            
            
          >
            {loadingNoise ? (
              <div className="text-slate-400 text-sm">Loading...</div>
            ) : (
              <AiHandledPie labels={["AI", "Escalate"]} data={noiseReduction} />
            )}
          </CustomTitleBox>

          <CustomTitleBox
            title="Confusion Matrix"
            
            
          >
            {loadingConfusion || !confusion ? (
              <div className="text-slate-400 text-sm">Loading...</div>  ) : (
              <ConfusionMatrix
                truePositive={confusion.true_positive}
                falsePositive={confusion.false_positive}
                trueNegative={confusion.true_negative}
                falseNegative={confusion.false_negative}
              />  )}

          </CustomTitleBox>
        </div>
      </div>
    </div>
  );
}
