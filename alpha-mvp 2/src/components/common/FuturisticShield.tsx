import React, { useMemo, useId } from "react";
import { MultiBrain } from "@/assets/svg/MutliBrain";

interface FuturisticShieldProps {
  className?: string;
}

const clamp = (n: number, min: number, max: number) =>
  Math.max(min, Math.min(max, n));

const FuturisticShield: React.FC<FuturisticShieldProps> = React.memo(
  ({ className = "" }) => {
    // 🔹 Configurable values (modify directly here)
    const size = 500;      // range: 200–600 (overall size of shield)
    const intensity = 1;   // range: 0.3–2 (glow & brightness)
    const speed = 1;       // range: 0.5–3 (rotation/pulse speed)
    const brainSize = 120; // ⬅️ size (in SVG units) for the brain graphic

    const uid = useId(); // prevent defs collisions if multiple components render

    const steps = useMemo(() => {
      const N = 36;
      return new Array(N).fill(0).map((_, i) => {
        const rotation = i * (360 / N);
        return (
          <rect
            key={i}
            className="step"
            x="194"
            y="25"
            width="12"
            height="12"
            rx="1"
            transform={`rotate(${rotation} 200 200)`}
            style={{ ["--i" as any]: i } as React.CSSProperties }
          />
        );
      });
    }, []);

    const containerStyle: React.CSSProperties = {
      position: "relative",
      width: `${clamp(size, 200, 600)}px`,
      height: `${clamp(size, 200, 600)}px`,
    };

    const svgStyle: React.CSSProperties = {
      width: "100%",
      height: "100%",
      opacity: clamp(intensity, 0.3, 2),
      filter: `drop-shadow(0 0 ${20 * clamp(intensity, 0.3, 2)}px #00d4ff)`,
      ["--speed" as any]: clamp(speed, 0.5, 3),
      ["--outer-rot-s" as any]: `${20 / clamp(speed, 0.5, 3)}s`,
      ["--mid-rot-s" as any]: `${25 / clamp(speed, 0.5, 3)}s`,
      ["--inner-rot-s" as any]: `${30 / clamp(speed, 0.5, 3)}s`,
      ["--pulse-s" as any]: `${3.5 / clamp(speed, 0.5, 3)}s`,
      ["--step-s" as any]: `${4 / clamp(speed, 0.5, 3)}s`,
      ["--ring-s" as any]: `${3 / clamp(speed, 0.5, 3)}s`,
      ["--step-delay-unit" as any]: `${4 / 36 / clamp(speed, 0.5, 3)}s`,
    };

    // Center position for the brain (top-left corner) in the 400x400 viewBox
    const brainX = 200 - brainSize / 2;
    const brainY = 200 - brainSize / 2;

    return (
      <div className={`${className}`}>
        <div style={containerStyle}>
          {/* Main SVG */}
          <svg
            style={svgStyle}
            viewBox="0 0 400 400"
            xmlns="http://www.w3.org/2000/svg"
            role="img"
            aria-label="Futuristic cybersecurity shield visualization"
          >
            <defs>
              <radialGradient id={`shieldGradient-${uid}`} cx="50%" cy="30%" r="70%">
                <stop offset="0%" stopColor="#00d4ff" stopOpacity="0.8" />
                <stop offset="50%" stopColor="#0066cc" stopOpacity="0.4" />
                <stop offset="100%" stopColor="#003366" stopOpacity="0.2" />
              </radialGradient>

              <linearGradient id={`layerGradient1-${uid}`} x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#00d4ff" stopOpacity="0.6" />
                <stop offset="50%" stopColor="#0099cc" stopOpacity="0.3" />
                <stop offset="100%" stopColor="#006699" stopOpacity="0.1" />
              </linearGradient>

              <linearGradient id={`layerGradient2-${uid}`} x1="100%" y1="0%" x2="0%" y2="100%">
                <stop offset="0%" stopColor="#0099cc" stopOpacity="0.5" />
                <stop offset="50%" stopColor="#006699" stopOpacity="0.3" />
                <stop offset="100%" stopColor="#003366" stopOpacity="0.1" />
              </linearGradient>

              <filter id={`glow-${uid}`}>
                <feGaussianBlur stdDeviation="3" result="coloredBlur" />
                <feMerge>
                  <feMergeNode in="coloredBlur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>

              <filter id={`strongGlow-${uid}`}>
                <feGaussianBlur stdDeviation="5" result="coloredBlur" />
                <feMerge>
                  <feMergeNode in="coloredBlur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            </defs>

            {/* Outer Ring + Steps */}
            <g className="ring">
              <circle cx="200" cy="200" r="180" fill="none" stroke="#00d4ff" strokeWidth="1" strokeOpacity="0.2" />
              {steps}
            </g>

            {/* Layer 1 */}
            <g className="rot-cw">
              <circle
                cx="200"
                cy="200"
                r="150"
                fill="none"
                stroke={`url(#layerGradient1-${uid})`}
                strokeWidth="1"
                strokeDasharray="10,5"
                filter={`url(#glow-${uid})`}
              />
              <circle cx="280" cy="120" r="3" fill="#00d4ff" opacity="0.8" />
              <circle cx="120" cy="280" r="3" fill="#00d4ff" opacity="0.8" />
              <circle cx="260" cy="140" r="2" fill="#0099cc" opacity="0.6" />
              <circle cx="140" cy="260" r="2" fill="#0099cc" opacity="0.6" />
              <circle cx="300" cy="200" r="2.5" fill="#00d4ff" opacity="0.7" />
              <circle cx="100" cy="200" r="2.5" fill="#00d4ff" opacity="0.7" />
              <circle cx="250" cy="250" r="2" fill="#0099cc" opacity="0.5" />
              <circle cx="150" cy="150" r="2" fill="#0099cc" opacity="0.5" />
            </g>

            {/* Layer 2 */}
            <g className="rot-ccw">
              <circle
                cx="200"
                cy="200"
                r="120"
                fill="none"
                stroke={`url(#layerGradient2-${uid})`}
                strokeWidth="1.5"
                strokeDasharray="5,3"
                filter={`url(#glow-${uid})`}
              />
              <rect x="140" y="140" width="4" height="4" fill="#00d4ff" opacity="0.7" rx="1" />
              <rect x="256" y="140" width="4" height="4" fill="#0099cc" opacity="0.5" rx="1" />
              <rect x="256" y="256" width="4" height="4" fill="#00d4ff" opacity="0.7" rx="1" />
              <rect x="140" y="256" width="4" height="4" fill="#0099cc" opacity="0.5" rx="1" />
              <rect x="200" y="110" width="3" height="3" fill="#00d4ff" opacity="0.6" rx="0.5" />
              <rect x="200" y="287" width="3" height="3" fill="#00d4ff" opacity="0.6" rx="0.5" />
              <rect x="110" y="200" width="3" height="3" fill="#0099cc" opacity="0.4" rx="0.5" />
              <rect x="287" y="200" width="3" height="3" fill="#0099cc" opacity="0.4" rx="0.5" />
              <rect x="165" y="165" width="2" height="2" fill="#00d4ff" opacity="0.5" rx="0.5" />
              <rect x="235" y="235" width="2" height="2" fill="#00d4ff" opacity="0.5" rx="0.5" />
            </g>

            {/* Layer 3 */}
            <g className="rot-cw-slow">
              <circle
                cx="200"
                cy="200"
                r="90"
                fill="none"
                stroke="#00d4ff"
                strokeWidth="1"
                strokeOpacity="0.4"
                strokeDasharray="3,2"
              />
              <circle cx="230" cy="170" r="1.5" fill="#00d4ff" opacity="0.9" />
              <circle cx="170" cy="230" r="1.5" fill="#00d4ff" opacity="0.9" />
              <circle cx="230" cy="230" r="1" fill="#0099cc" opacity="0.7" />
              <circle cx="170" cy="170" r="1" fill="#0099cc" opacity="0.7" />
              <circle cx="200" cy="140" r="1.2" fill="#00d4ff" opacity="0.8" />
              <circle cx="200" cy="260" r="1.2" fill="#00d4ff" opacity="0.8" />
              <circle cx="140" cy="200" r="1" fill="#0099cc" opacity="0.6" />
              <circle cx="260" cy="200" r="1" fill="#0099cc" opacity="0.6" />
              <circle cx="215" cy="185" r="0.8" fill="#00d4ff" opacity="0.5" />
              <circle cx="185" cy="215" r="0.8" fill="#00d4ff" opacity="0.5" />
              <circle cx="185" cy="185" r="0.6" fill="#0099cc" opacity="0.4" />
              <circle cx="215" cy="215" r="0.6" fill="#0099cc" opacity="0.4" />
            </g>

            {/* 👉 Center: MultiBrain with glow & pulse */}
            <g
              className="pulse"
              filter={`url(#strongGlow-${uid})`}
              // If your MultiBrain uses "currentColor" for strokes/fills, this sets the color
              style={{ color: "#00d4ff" }}
            >
              {/* Position and size the brain */}
              <g transform={`translate(${brainX} ${brainY})`}>
                {/* If your MultiBrain supports width/height props, this will size it cleanly */}
                <MultiBrain width={brainSize} height={brainSize} />
                {/* If it doesn't, you can replace the line above with:
                   <g transform="scale(1.2)">
                     <MultiBrain />
                   </g>
                   ...and tweak the scale.
                */}
              </g>
            </g>
          </svg>
        </div>

        <style>{`
          @keyframes rotateCW { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
          @keyframes rotateCCW { from { transform: rotate(0deg); } to { transform: rotate(-360deg); } }
          @keyframes pulseSize { 0%,100% { transform: scale(1); opacity: 0.6; } 50% { transform: scale(1.08); opacity: 1; } }
          @keyframes stepGlow {
            0% { fill: #66d9ff; opacity: 0.4; }
            50% { fill: #00d4ff; opacity: 1; }
            100% { fill: #66d9ff; opacity: 0.4; }
          }

          .ring { animation: stepGlow var(--ring-s) infinite; }
          .rot-cw { animation: rotateCW var(--outer-rot-s) linear infinite; transform-origin: center; }
          .rot-ccw { animation: rotateCCW var(--mid-rot-s) linear infinite; transform-origin: center; }
          .rot-cw-slow { animation: rotateCW var(--inner-rot-s) linear infinite; transform-origin: center; }
          .pulse { animation: pulseSize var(--pulse-s) ease-in-out infinite; transform-origin: center; }

          .step {
            animation: stepGlow var(--step-s) infinite;
            opacity: 0.4;
            animation-delay: calc(var(--i) * var(--step-delay-unit));
          }
        `}</style>
      </div>
    );
  }
);

export default FuturisticShield;
