"use client";

import { useMemo, useEffect, useRef, useState } from "react";
import FuturisticShield from "./FuturisticShield";
import {
  ReactFlow,
  ReactFlowProvider,
  Position,
  Handle,
  BaseEdge,
  EdgeLabelRenderer,
  ConnectionMode,
  type Node,
  type Edge,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import type { Node as RFNode, XYPosition, ReactFlowInstance } from "@xyflow/react";

import { SentinalOne } from "@/assets/svg/SentinalOne";
import { CrowdStrike } from "@/assets/svg/CrowdStrike";
import { Checkpoint } from "@/assets/svg/Checkpoint";
import { PaloAlto } from "@/assets/svg/PaloAlto";
import { Fortinet } from "@/assets/svg/Fortinet";
import { Proofpoint } from "@/assets/svg/Proofpoint";
import { Azure } from "@/assets/svg/Azure";
import { Okta } from "@/assets/svg/Okta";
import { Aws } from "@/assets/svg/Aws";
import { Gcp } from "@/assets/svg/Gcp";
import { RotatingBrain } from "./RotatingBrain";

// ------------------ Constants ------------------
const TP_COLOR = "#00FF00";  // blue   
const FP_COLOR = "#FF2B2B";  // red
const ESC_COLOR = "#FFB000"; // mustard/amber

const TP_SIZE = 250;
const FP_SIZE = 120;
const ESC_SIZE = 120;

// ------------------ Types ------------------
type Vendor =
  | "SentinalOne" | "CrowdStrike" | "Checkpoint" | "PaloAlto" | "Fortinet"
  | "Proofpoint" | "Azure" | "Okta" | "Aws" | "Gcp";

type Result = "tp" | "fp" | "esc";

export type IncomingEvent = { alert_id: string; source: Vendor };
export type ResultEvent   = { alert_id: string; result: Result };

type Counts = { tp: number; fp: number; esc: number };

type Pulse = {
  id: string;            // alert_id
  color: string;         // ball color
  durationMs: number;    // animation length
};

type ThreatVizProps = {
  counts: Counts; // parent-controlled
  vendorEvents: IncomingEvent[]; // stream of vendor arrivals
  resultEvents: ResultEvent[];   // stream of classification results
  onResultDelivered?: (payload: { alert_id: string; result: Result }) => void; // fire AFTER pulse finishes on shield->section
  vendorPulseMs?: number; // default 1600
  resultPulseMs?: number; // default 1600
};

type RFNodeMeasured = RFNode & {
  positionAbsolute?: XYPosition;
  measured?: { width?: number; height?: number };
  width?: number;
  height?: number;
};


// ------------------ Helpers ------------------
const SourceIcons = {
  SentinalOne,
  CrowdStrike,
  Checkpoint,
  PaloAlto,
  Fortinet,
  Proofpoint,
  Azure,
  Okta,
  Aws,
  Gcp,
};

// ------------------ Nodes ------------------
function SourceNode({ data }: any) {
  const Icon =
    SourceIcons[data?.label as keyof typeof SourceIcons] || SentinalOne;

  return (
    <>
     <div className="flex items-center gap-2">
      <Icon />
      <div className="bg-white/10 px-3 rounded-2xl flex items-center justify-center">
      <span className="text-white text-lg font-bebas ">{data?.label}</span>
      </div>
      <Handle
        type="source"
        position={Position.Right}
        id="out"
        style={{ opacity: 0, width: 0, height: 0 }}
      />
    </div>
    </>
  );
}

function ShieldNode() {
  return (
    <div className="relative bottom-12 right-5">
      <div className="absolute inset-0 rounded-2xl blur-2xl" />
      <FuturisticShield />
      {new Array(10).fill(0).map((_, i) => (
        <Handle key={`in-${i}`} type="target" position={Position.Left} id={`in-${i}`} style={{ opacity: 0, width: 0, height: 0 }} />
      ))}
      <Handle key="out-tp"  type="source" position={Position.Right} id="out-tp"  style={{ opacity: 0, width: 0, height: 0, top: "30%" }} />
      <Handle key="out-fp"  type="source" position={Position.Right} id="out-fp"  style={{ opacity: 0, width: 0, height: 0, top: "50%" }} />
      <Handle key="out-esc" type="source" position={Position.Right} id="out-esc" style={{ opacity: 0, width: 0, height: 0, top: "70%" }} />
    </div>
  );
}

function TruePositiveNode({ data }: any) {
  return (
    <div className="relative top-8 left-6">
      <RotatingBrain color={TP_COLOR} size={TP_SIZE} value={data?.value ?? 0} />
      <Handle type="target" position={Position.Left} id="in" style={{ opacity: 0, width: 0, height: 0 }} />
    </div>
  );
}

function FalsePositiveNode({ data }: any) {
  return (
    <div className="relative top-8 left-6">
      <RotatingBrain color={FP_COLOR} size={FP_SIZE} value={data?.value ?? 0} />
      <Handle type="target" position={Position.Left} id="in" style={{ opacity: 0, width: 0, height: 0 }} />
    </div>
  );
}

function EscalateNode({ data }: any) {
  return (
    <div className="relative top-8 left-6">
      <RotatingBrain color={ESC_COLOR} size={ESC_SIZE} value={data?.value ?? 0} />
      <Handle type="target" position={Position.Left} id="in" style={{ opacity: 0, width: 0, height: 0 }} />
    </div>
  );
}

// ------------------ Edge Pulse Render ------------------
// Uses CSS offset-path to move balls along the cubic bezier path.
// Multiple pulses can exist simultaneously.
// When a pulse ends on Shield->Section, we call onPulseEnd(pulseId).

function EdgePulses({
  path,
  pulses,
  onPulseEnd,
}: {
  path: string;
  pulses: Pulse[];
  onPulseEnd?: (pulseId: string) => void;
}) {
  // we render HTML overlay and animate via CSS offset-path
  return (
    <EdgeLabelRenderer>
      <div style={{ position: "absolute", inset: 0, pointerEvents: "none" }}>
        {pulses.map((p) => (
          <div
            key={p.id}
            onAnimationEnd={() => onPulseEnd?.(p.id)}
            style={{
              position: "absolute",
              width: 10,
              height: 10,
              borderRadius: "9999px",
              background: p.color,
              boxShadow: `0 0 10px ${p.color}`,
              offsetPath: `path("${path}")`,
              offsetDistance: "0%",
              animation: `pulse-move ${p.durationMs}ms linear 1`,
            }}
          />
        ))}
      </div>
    </EdgeLabelRenderer>
  );
}

// ------------------ Custom Edges ------------------
// 1) VendorPulseEdge: vendor -> shield (always red dashed + red pulses)
function VendorPulseEdge(props: any) {
  const { sourceX, sourceY, targetX, targetY, data } = props;
  const color = FP_COLOR;

  const path = `M ${sourceX},${sourceY} C ${(sourceX + targetX) / 2},${sourceY} ${(sourceX + targetX) / 2},${targetY} ${targetX},${targetY}`;

  return (
    <>
      <BaseEdge path={path} style={{ stroke: color, strokeWidth: 0.5 }} />
      <BaseEdge
        path={path}
        style={{
          stroke: color,
          strokeWidth: 2,
          strokeDasharray: 12,
          animation: "dash-move 1.6s linear infinite",
        }}
      />
      <EdgePulses path={path} pulses={data?.pulses ?? []} />
    </>
  );
}

// 2) ShieldPulseEdge: shield -> brains (blue dashed + pulses colored per section)
function ShieldPulseEdge(props: any) {
  const { sourceX, sourceY, targetX, targetY, data, label } = props;
  const color = '#00D1FF';

  const path = `M ${sourceX},${sourceY} C ${(sourceX + targetX) / 2},${sourceY} ${(sourceX + targetX) / 2},${targetY} ${targetX},${targetY}`;

  const labelX = (sourceX + targetX) / 2;
  const labelY = (sourceY + targetY) / 2;

  return (
    <>
      <BaseEdge path={path} style={{ stroke: color, strokeWidth: 0.5 }} />
      <BaseEdge
        path={path}
        style={{
          stroke: color,
          strokeWidth: 2,
          strokeDasharray: 12,
          animation: "dash-move 1.6s linear infinite",
        }}
      />
      {label ? (
        <EdgeLabelRenderer>
          <div
            style={{
              position: "absolute",
              transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)`,
              pointerEvents: "none",
              fontSize: 16,
              fontWeight: 700,
              color,
              padding: "4px 12px",
              borderRadius: 8,
              background: "rgba(0,0,0,0.4)",
              border: `1px solid ${color}33`,
              boxShadow: `0 0 8px ${color}44`,
              userSelect: "none",
              whiteSpace: "nowrap",
            }}
          >
            {label}
          </div>
        </EdgeLabelRenderer>
      ) : null}
      <EdgePulses
        path={path}
        pulses={data?.pulses ?? []}
        onPulseEnd={data?.onPulseEnd}
      />
    </>
  );
}

const edgeTypes = {
  vendorBeam: VendorPulseEdge,
  shieldBeam: ShieldPulseEdge,
} as const;

const nodeTypes = {
  sourceNode: SourceNode,
  shieldNode: ShieldNode,
  tpNode: TruePositiveNode,
  fpNode: FalsePositiveNode,
  escNode: EscalateNode,
} as const;

// ------------------ Main ------------------
export default function ThreatVisualizationbeta({
  counts,
  vendorEvents,
  resultEvents,
  onResultDelivered,
  vendorPulseMs = 1600,
  resultPulseMs = 1600,
}: ThreatVizProps) {
  // display values are parent-controlled
  const [nodes, setNodes] = useState<Node[]>([
    { id: "SentinalOne", type: "sourceNode", position: { x: -300, y: 30 }, data: { label: "SentinalOne" } },
    { id: "CrowdStrike",  type: "sourceNode", position: { x: -300, y: 93.333 }, data: { label: "CrowdStrike" } },
    { id: "Checkpoint",  type: "sourceNode", position: { x: -300, y: 156.667}, data: { label: "Checkpoint" } },
    { id: "PaloAlto",     type: "sourceNode", position: { x: -300, y: 220.000 }, data: { label: "PaloAlto" } },
    { id: "Fortinet",    type: "sourceNode", position: { x: -300, y: 283.333}, data: { label: "Fortinet" } },
    { id: "Proofpoint",  type: "sourceNode", position: { x: -300, y: 346.667 }, data: { label: "Proofpoint" } },
    { id: "Azure",       type: "sourceNode", position: { x: -300, y: 410 }, data: { label: "Azure" } },
    { id: "Okta",        type: "sourceNode", position: { x: -300, y: 473.333 }, data: { label: "Okta" } },
    { id: "Aws",         type: "sourceNode", position: { x: -300, y: 536.667}, data: { label: "Aws" } },
    { id: "Gcp",         type: "sourceNode", position: { x: -300, y: 600 }, data: { label: "Gcp" } },
    { id: "shield",      type: "shieldNode", position: { x: 420, y: 160 }, data: {} },

    // values are parent-provided via counts
    { id: "tp",  type: "tpNode",  position: { x: 1050, y:  10 }, data: { value: counts.tp } },
    { id: "fp",  type: "fpNode",  position: { x: 1200, y: 230 }, data: { value: counts.fp } },
    { id: "esc", type: "escNode", position: { x: 1000, y: 450 }, data: { value: counts.esc } },
  ]);

  // Keep brain counts in sync with parent prop
  useEffect(() => {
    setNodes((nds) =>
      nds.map((n) =>
        n.id === "tp"  ? { ...n, data: { ...n.data, value: counts.tp } } :
        n.id === "fp"  ? { ...n, data: { ...n.data, value: counts.fp } } :
        n.id === "esc" ? { ...n, data: { ...n.data, value: counts.esc } } :
        n
      )
    );
  }, [counts.tp, counts.fp, counts.esc]);

  // Pulses per edge (edgeId -> Pulse[])
  const [edgePulses, setEdgePulses] = useState<Record<string, Pulse[]>>({});

  // Track processed events so new props diffs trigger only once
  const seenVendor = useRef<Set<string>>(new Set());
  const seenResult = useRef<Set<string>>(new Set());

  // Map vendor to edge id + target handle index
  const vendorEdgeId = (v: Vendor) => {
    const map: Record<Vendor, { edgeId: string; handle: string }> = {
      SentinalOne: { edgeId: "e-sentinal-shield", handle: "in-0" },
      CrowdStrike:  { edgeId: "e-crowdstrike-shield", handle: "in-1" },
      Checkpoint:  { edgeId: "e-checkpoint-shield", handle: "in-2" },
      PaloAlto:     { edgeId: "e-paloalto-shield", handle: "in-3" },
      Fortinet:    { edgeId: "e-fortinet-shield", handle: "in-4" },
      Proofpoint:  { edgeId: "e-proofpoint-shield", handle: "in-5" },
      Azure:       { edgeId: "e-azure-shield", handle: "in-6" },
      Okta:        { edgeId: "e-okta-shield", handle: "in-7" },
      Aws:         { edgeId: "e-aws-shield", handle: "in-8" },
      Gcp:         { edgeId: "e-gcp-shield", handle: "in-9" },
    };
    return map[v].edgeId;
  };

  const resultEdgeId = (r: Result) =>
    r === "tp" ? "e-shield-tp" : r === "fp" ? "e-shield-fp" : "e-shield-esc";

  const resultPulseColor = (r: Result) =>
    r === "tp" ? TP_COLOR : r === "fp" ? FP_COLOR : ESC_COLOR;

  // Queue a pulse on an edge
  const pushPulse = (edgeId: string, pulse: Pulse) => {
    setEdgePulses((prev) => {
      const q = prev[edgeId] ?? [];
      return { ...prev, [edgeId]: [...q, pulse] };
    });
  };

  // Remove a pulse on an edge
  const removePulse = (edgeId: string, pulseId: string) => {
    setEdgePulses((prev) => {
      const q = prev[edgeId] ?? [];
      return { ...prev, [edgeId]: q.filter((p) => p.id !== pulseId) };
    });
  };

  // Handle vendor arrivals -> red ball vendor->shield
  useEffect(() => {
    for (const evt of vendorEvents) {
      if (seenVendor.current.has(evt.alert_id)) continue;
      seenVendor.current.add(evt.alert_id);
      const eId = vendorEdgeId(evt.source);
      pushPulse(eId, { id: evt.alert_id, color: FP_COLOR, durationMs: vendorPulseMs });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vendorEvents, vendorPulseMs]);

  // Handle classification results -> colored ball shield->section
  useEffect(() => {
    for (const evt of resultEvents) {
      if (seenResult.current.has(evt.alert_id)) continue;
      seenResult.current.add(evt.alert_id);
      const eId = resultEdgeId(evt.result);
      pushPulse(eId, { id: evt.alert_id, color: resultPulseColor(evt.result), durationMs: resultPulseMs });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [resultEvents, resultPulseMs]);

  // Build edges with pulse queues + completion callbacks
  const edges: Edge[] = useMemo(() => {
    const vendorToShield: Edge[] = [
      { id: "e-sentinal-shield",  source: "SentinalOne", sourceHandle: "out", target: "shield", targetHandle: "in-0", type: "vendorBeam", data: { pulses: edgePulses["e-sentinal-shield"] ?? [] } },
      { id: "e-crowdstrike-shield", source: "CrowdStrike", sourceHandle: "out", target: "shield", targetHandle: "in-1", type: "vendorBeam", data: { pulses: edgePulses["e-crowdstrike-shield"] ?? [] } },
      { id: "e-checkpoint-shield", source: "Checkpoint", sourceHandle: "out", target: "shield", targetHandle: "in-2", type: "vendorBeam", data: { pulses: edgePulses["e-checkpoint-shield"] ?? [] } },
      { id: "e-paloalto-shield",  source: "PaloAlto",     sourceHandle: "out", target: "shield", targetHandle: "in-3", type: "vendorBeam", data: { pulses: edgePulses["e-paloalto-shield"] ?? [] } },
      { id: "e-fortinet-shield",  source: "Fortinet",    sourceHandle: "out", target: "shield", targetHandle: "in-4", type: "vendorBeam", data: { pulses: edgePulses["e-fortinet-shield"] ?? [] } },
      { id: "e-proofpoint-shield",source: "Proofpoint",  sourceHandle: "out", target: "shield", targetHandle: "in-5", type: "vendorBeam", data: { pulses: edgePulses["e-proofpoint-shield"] ?? [] } },
      { id: "e-azure-shield",     source: "Azure",       sourceHandle: "out", target: "shield", targetHandle: "in-6", type: "vendorBeam", data: { pulses: edgePulses["e-azure-shield"] ?? [] } },
      { id: "e-okta-shield",      source: "Okta",        sourceHandle: "out", target: "shield", targetHandle: "in-7", type: "vendorBeam", data: { pulses: edgePulses["e-okta-shield"] ?? [] } },
      { id: "e-aws-shield",       source: "Aws",         sourceHandle: "out", target: "shield", targetHandle: "in-8", type: "vendorBeam", data: { pulses: edgePulses["e-aws-shield"] ?? [] } },
      { id: "e-gcp-shield",       source: "Gcp",         sourceHandle: "out", target: "shield", targetHandle: "in-9", type: "vendorBeam", data: { pulses: edgePulses["e-gcp-shield"] ?? [] } },
    ];

    const mkShieldData = (edgeId: string, result: Result) => ({
      pulses: (edgePulses[edgeId] ?? []),
      onPulseEnd: (pulseId: string) => {
        // remove pulse locally
        removePulse(edgeId, pulseId);
        // notify parent to increment counts AFTER arrival
        onResultDelivered?.({ alert_id: pulseId, result });
      },
    });

    const shieldToBrains: Edge[] = [
      { id: "e-shield-tp",  source: "shield", sourceHandle: "out-tp",  target: "tp",  targetHandle: "in", type: "shieldBeam", label: "True Positive",  data: mkShieldData("e-shield-tp", "tp") },
      { id: "e-shield-fp",  source: "shield", sourceHandle: "out-fp",  target: "fp",  targetHandle: "in", type: "shieldBeam", label: "False Positive", data: mkShieldData("e-shield-fp", "fp") },
      { id: "e-shield-esc", source: "shield", sourceHandle: "out-esc", target: "esc", targetHandle: "in", type: "shieldBeam", label: "Escalate",       data: mkShieldData("e-shield-esc", "esc") },
    ];

    return [...vendorToShield, ...shieldToBrains];
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [edgePulses, onResultDelivered]);

   const wrapperRef = useRef<HTMLDivElement | null>(null);
  const rfRef = useRef<ReactFlowInstance | null>(null);
  const [containerHeight, setContainerHeight] = useState<number>(600);

    const computeBounds = (allNodes: RFNodeMeasured[]) => {
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;

    for (const n of allNodes) {
      const x = n.positionAbsolute?.x ?? n.position.x ?? 0;
      const y = n.positionAbsolute?.y ?? n.position.y ?? 0;
      const w = (n.measured?.width ?? n.width ?? 0) || 0;
      const h = (n.measured?.height ?? n.height ?? 0) || 0;
      if (!Number.isFinite(x) || !Number.isFinite(y)) continue;

      minX = Math.min(minX, x);
      minY = Math.min(minY, y);
      maxX = Math.max(maxX, x + w);
      maxY = Math.max(maxY, y + h);
    }

    return { width: Math.max(0, maxX - minX), height: Math.max(0, maxY - minY) };
  };

  const PADDING_FRAC = 0.2;

  const recomputeHeight = () => {
    const wrapper = wrapperRef.current;
    const inst = rfRef.current;
    if (!wrapper || !inst) return;

    const widthPx = wrapper.clientWidth || 800;
    const nodesNow = inst.getNodes() as RFNodeMeasured[];   // <-- cast here
    const { width: bw, height: bh } = computeBounds(nodesNow);

    const bwP = bw * (1 + PADDING_FRAC * 2);
    const bhP = bh * (1 + PADDING_FRAC * 2);
    const needed = Math.ceil((bhP / Math.max(bwP, 1)) * widthPx);

    setContainerHeight(Math.max(needed, 1));
    requestAnimationFrame(() => inst.fitView({ padding: PADDING_FRAC }));
  };

    const handleInit = (inst: ReactFlowInstance) => {
    rfRef.current = inst;
    requestAnimationFrame(recomputeHeight);
  };

  useEffect(() => {
    if (!wrapperRef.current) return;
    const ro = new ResizeObserver(() => recomputeHeight());
    ro.observe(wrapperRef.current);
    return () => ro.disconnect();
  }, []);

  // if your counts affect node sizes/labels, trigger a recompute
  useEffect(() => {
    const t = setTimeout(recomputeHeight, 0);
    return () => clearTimeout(t);
  }, [counts.tp, counts.fp, counts.esc]);

  const onNodesChange = () => requestAnimationFrame(recomputeHeight);


  return (
     <ReactFlowProvider>
      <div
        ref={wrapperRef}
        className="relative rounded-2xl overflow-hidden border border-slate-800 bg-gradient-to-l from-black to-[#0a2e2f]"
        style={{ width: "100%", height: `${containerHeight}px` }}
      >
        <style>{`
          @keyframes dash-move { to { stroke-dashoffset: -24; } }
          @keyframes pulse-move { to { offset-distance: 100%; } }
        `}</style>

        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          edgeTypes={edgeTypes}
          onInit={handleInit}
          onNodesChange={onNodesChange}
          fitView
          fitViewOptions={{ padding: PADDING_FRAC }}
          proOptions={{ hideAttribution: true }}
          connectionMode={ConnectionMode.Loose}
          panOnDrag={false}
          zoomOnScroll={false}
          zoomOnPinch={false}
          zoomOnDoubleClick={false}
          panOnScroll={false}
          selectionOnDrag={false}
          nodesDraggable={false}
          nodesConnectable={false}
        />
      </div>
    </ReactFlowProvider>
  );
}
