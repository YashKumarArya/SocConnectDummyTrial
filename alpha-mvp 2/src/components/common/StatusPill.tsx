export type PillTone =
  | "red"
  | "orange"
  | "amber"   // mustard-y
  | "yellow"
  | "green"
  | "blue"
  | "purple"
  | "gray";

const TONE_CLASSES: Record<PillTone, string> = {
  red:    "bg-red-500/15 text-red-300 border-red-400/30",
  orange: "bg-orange-500/15 text-orange-300 border-orange-400/30",
  amber:  "bg-amber-500/15 text-amber-300 border-amber-400/30",
  yellow: "bg-yellow-500/15 text-yellow-300 border-yellow-400/30",
  green:  "bg-green-500/15 text-green-300 border-green-400/30",
  blue:   "bg-blue-500/15 text-blue-300 border-blue-400/30",
  purple: "bg-purple-500/15 text-purple-300 border-purple-400/30",
  gray:   "bg-gray-500/15 text-gray-300 border-gray-400/30",
};

export interface StatusPillProps {
  label: string;
  tone?: PillTone;
  className?: string;
}

export default function StatusPill({
  label,
  tone = "gray",
  className = "",
}: StatusPillProps) {
  return (
    <span
      className={[
        "inline-flex items-center rounded-full border px-2.5 py-1 text-xs font-medium whitespace-nowrap",
        TONE_CLASSES[tone],
        className,
      ].join(" ")}
    >
      {label}
    </span>
  );
}
