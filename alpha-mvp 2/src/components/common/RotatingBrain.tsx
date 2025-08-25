import React, { useMemo, useId } from "react";

interface RotatingBrainProps {
  /** Text shown above the shield */
  title?: string;
  /** Optional className for the title (to style font, spacing, etc.) */
  titleClassName?: string;
  /** Number or string shown in the center, glowing */
  value: number | string;

  /** Overall size (px) for the shield container */
  size?: number; // default 400
  /** Primary color for the rotating shield (CSS color) */
  color?: string; // default "#00d4ff"

  /** Optional wrapper className */
  className?: string;
}

const clamp = (n: number, min: number, max: number) =>
  Math.max(min, Math.min(max, n));

export const RotatingBrain: React.FC<RotatingBrainProps> = React.memo(
  ({
    title,
    titleClassName = "",
    value,
    size = 400,
    color = "#00d4ff",
    className = "",
  }) => {
    const uid = useId();

    
    // animation timing (kept simple & smooth)
    const speed = 1;       // feel free to tweak or expose later
    const intensity = 4;   // glow intensity baseline

    const containerPx = clamp(size, 200, 600);
    const containerStyle: React.CSSProperties = {
      position: "relative",
      width: `${containerPx}px`,
      height: `${containerPx}px`,
    };

    const svgStyle: React.CSSProperties = {
      width: "100%",
      height: "100%",
      opacity: clamp(intensity, 0.3, 10),
      filter: `drop-shadow(0 0 ${20 * clamp(intensity, 0.3, 2)}px var(--tint))`,
      ["--outer-rot-s" as any]: `${20 / clamp(speed, 0.5, 3)}s`,
      ["--mid-rot-s" as any]: `${25 / clamp(speed, 0.5, 3)}s`,
      ["--inner-rot-s" as any]: `${30 / clamp(speed, 0.5, 3)}s`,
      ["--pulse-s" as any]: `${3.5 / clamp(speed, 0.5, 3)}s`,
      ["--tint" as any]: color,
    };

    // gradients use CSS var(--tint) so you can pass any color string
    const gradients = useMemo(
      () => ({
        shield: `shieldGradient-${uid}`,
        g1: `layerGradient1-${uid}`,
        g2: `layerGradient2-${uid}`,
        glow: `glow-${uid}`,
        glowStrong: `strongGlow-${uid}`,
      }),
      [uid]
    );

    return (
      <div className={className} style={{ ["--tint" as any]: color } as React.CSSProperties}>
        {title ? (
          <div className={titleClassName} style={{ marginBottom: 8 }}>
            {title}
          </div>
        ) : null}

        <div style={containerStyle}>
          <svg
            style={svgStyle}
            viewBox="0 0 400 400"
            xmlns="http://www.w3.org/2000/svg"
            role="img"
            aria-label="Futuristic cybersecurity shield visualization"
          >
            <defs>
              <radialGradient id={gradients.shield} cx="50%" cy="30%" r="70%">
                <stop offset="0%" stopColor="var(--tint)" stopOpacity="0.8" />
                <stop offset="50%" stopColor="var(--tint)" stopOpacity="0.35" />
                <stop offset="100%" stopColor="var(--tint)" stopOpacity="0.15" />
              </radialGradient>

              <linearGradient id={gradients.g1} x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="var(--tint)" stopOpacity="0.6" />
                <stop offset="50%" stopColor="var(--tint)" stopOpacity="0.3" />
                <stop offset="100%" stopColor="var(--tint)" stopOpacity="0.1" />
              </linearGradient>

              <linearGradient id={gradients.g2} x1="100%" y1="0%" x2="0%" y2="100%">
                <stop offset="0%" stopColor="var(--tint)" stopOpacity="0.5" />
                <stop offset="50%" stopColor="var(--tint)" stopOpacity="0.3" />
                <stop offset="100%" stopColor="var(--tint)" stopOpacity="0.1" />
              </linearGradient>

              <filter id={gradients.glow}>
                <feGaussianBlur stdDeviation="3" result="coloredBlur" />
                <feMerge>
                  <feMergeNode in="coloredBlur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>

              <filter id={gradients.glowStrong}>
                <feGaussianBlur stdDeviation="5" result="coloredBlur" />
                <feMerge>
                  <feMergeNode in="coloredBlur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            </defs>

            {/* Outer Ring (no steps) */}
            <g className="ring">
              <circle
                cx="200"
                cy="200"
                r="180"
                fill="none"
                stroke="var(--tint)"
                strokeWidth="1"
                strokeOpacity="0.25"
              />
            </g>

            {/* Layer 1 */}
            <g className="rot-cw">
              <circle
                cx="200"
                cy="200"
                r="150"
                fill="none"
                stroke={`url(#${gradients.g1})`}
                strokeWidth="1"
                strokeDasharray="10,5"
                filter={`url(#${gradients.glow})`}
              />
              <circle cx="280" cy="120" r="3" fill="var(--tint)" opacity="0.8" />
              <circle cx="120" cy="280" r="3" fill="var(--tint)" opacity="0.8" />
              <circle cx="260" cy="140" r="2" fill="var(--tint)" opacity="0.6" />
              <circle cx="140" cy="260" r="2" fill="var(--tint)" opacity="0.6" />
              <circle cx="300" cy="200" r="2.5" fill="var(--tint)" opacity="0.7" />
              <circle cx="100" cy="200" r="2.5" fill="var(--tint)" opacity="0.7" />
              <circle cx="250" cy="250" r="2" fill="var(--tint)" opacity="0.5" />
              <circle cx="150" cy="150" r="2" fill="var(--tint)" opacity="0.5" />
            </g>

            {/* Layer 2 */}
            <g className="rot-ccw">
              <circle
                cx="200"
                cy="200"
                r="120"
                fill="none"
                stroke={`url(#${gradients.g2})`}
                strokeWidth="1.5"
                strokeDasharray="5,3"
                filter={`url(#${gradients.glow})`}
              />
              <rect x="140" y="140" width="4" height="4" fill="var(--tint)" opacity="0.7" rx="1" />
              <rect x="256" y="140" width="4" height="4" fill="var(--tint)" opacity="0.5" rx="1" />
              <rect x="256" y="256" width="4" height="4" fill="var(--tint)" opacity="0.7" rx="1" />
              <rect x="140" y="256" width="4" height="4" fill="var(--tint)" opacity="0.5" rx="1" />
              <rect x="200" y="110" width="3" height="3" fill="var(--tint)" opacity="0.6" rx="0.5" />
              <rect x="200" y="287" width="3" height="3" fill="var(--tint)" opacity="0.6" rx="0.5" />
              <rect x="110" y="200" width="3" height="3" fill="var(--tint)" opacity="0.4" rx="0.5" />
              <rect x="287" y="200" width="3" height="3" fill="var(--tint)" opacity="0.4" rx="0.5" />
              <rect x="165" y="165" width="2" height="2" fill="var(--tint)" opacity="0.5" rx="0.5" />
              <rect x="235" y="235" width="2" height="2" fill="var(--tint)" opacity="0.5" rx="0.5" />
            </g>

            {/* Layer 3 */}
            <g className="rot-cw-slow">
              <circle
                cx="200"
                cy="200"
                r="90"
                fill="none"
                stroke="var(--tint)"
                strokeWidth="1"
                strokeOpacity="0.4"
                strokeDasharray="3,2"
              />
              <circle cx="230" cy="170" r="1.5" fill="var(--tint)" opacity="0.9" />
              <circle cx="170" cy="230" r="1.5" fill="var(--tint)" opacity="0.9" />
              <circle cx="230" cy="230" r="1" fill="var(--tint)" opacity="0.7" />
              <circle cx="170" cy="170" r="1" fill="var(--tint)" opacity="0.7" />
              <circle cx="200" cy="140" r="1.2" fill="var(--tint)" opacity="0.8" />
              <circle cx="200" cy="260" r="1.2" fill="var(--tint)" opacity="0.8" />
              <circle cx="140" cy="200" r="1" fill="var(--tint)" opacity="0.6" />
              <circle cx="260" cy="200" r="1" fill="var(--tint)" opacity="0.6" />
              <circle cx="215" cy="185" r="0.8" fill="var(--tint)" opacity="0.5" />
              <circle cx="185" cy="215" r="0.8" fill="var(--tint)" opacity="0.5" />
              <circle cx="185" cy="185" r="0.6" fill="var(--tint)" opacity="0.4" />
              <circle cx="215" cy="215" r="0.6" fill="var(--tint)" opacity="0.4" />
            </g>

            {/* Center value with glow & pulse */}
            <g className="pulse">
  {/* Circular glowing background */}
  <circle
    cx="200"
    cy="200"
    r="50"
    fill="var(--tint)"
    opacity="0.1"
    filter={`url(#${gradients.glowStrong})`}
  />

  {/* The text in front */}
  <text
    x="200"
    y="200"
    textAnchor="middle"
    dominantBaseline="central"
    fill="var(--tint)"
    fontSize="72"
    fontWeight={800}
    style={{
      letterSpacing: "0.02em",
      textShadow: "0 0 12px var(--tint)",
    }}
  >
    {value}
  </text>
</g>

          </svg>
        </div>

        <style>{`
          @keyframes rotateCW { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
          @keyframes rotateCCW { from { transform: rotate(0deg); } to { transform: rotate(-360deg); } }
          @keyframes pulseSize { 0%,100% { transform: scale(1); opacity: 0.75; } 50% { transform: scale(1.08); opacity: 1; } }

          .rot-cw { animation: rotateCW var(--outer-rot-s) linear infinite; transform-origin: center; }
          .rot-ccw { animation: rotateCCW var(--mid-rot-s) linear infinite; transform-origin: center; }
          .rot-cw-slow { animation: rotateCW var(--inner-rot-s) linear infinite; transform-origin: center; }
          .pulse { animation: pulseSize var(--pulse-s) ease-in-out infinite; transform-origin: center; }
          .ring { opacity: 0.9; }
        `}</style>
      </div>
    );
  }
);

