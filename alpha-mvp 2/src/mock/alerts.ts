// src/mock/alerts.ts
export type AlertRow = {
  id: string;                 // Alert ID
  source: "Email" | "Firewall" | "Endpoint" | "Network" | "Cloud" | "Other";
  title: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  status: "Active" | "Investigating" | "Resolved" | "Pending Patch" | "Dismissed";
  analyst: string;
  recommendation: string;
};

export const mockAlerts: AlertRow[] = [
  {
    id: "ALT-2024-001",
    source: "Network",
    title: "Suspicious Network Traffic Detected",
    severity: "Critical",
    status: "Active",
    analyst: "Sarah Chen",
    recommendation: "Isolate hosts and inspect outbound traffic patterns.",
  },
  {
    id: "ALT-2024-002",
    source: "Cloud",
    title: "Potential Data Exfiltration",
    severity: "High",
    status: "Investigating",
    analyst: "Marcus Johnson",
    recommendation: "Check egress logs and DLP policies for anomalies.",
  },
  {
    id: "ALT-2024-003",
    source: "Endpoint",
    title: "Unauthorized Access Attempt",
    severity: "Medium",
    status: "Active",
    analyst: "AI Auto-Triage",
    recommendation: "Enable MFA challenges and review user behavior.",
  },
  {
    id: "ALT-2024-004",
    source: "Endpoint",
    title: "Malware Infection Detected",
    severity: "Critical",
    status: "Active",
    analyst: "Sarah Chen",
    recommendation: "Isolate infected systems and kick off forensics.",
  },
  {
    id: "ALT-2024-005",
    source: "Email",
    title: "Phishing Attempt Identified",
    severity: "High",
    status: "Resolved",
    analyst: "Marcus Johnson",
    recommendation: "Block sender, notify targets, and train users.",
  },
  {
    id: "ALT-2024-006",
    source: "Network",
    title: "DDoS Attack Underway",
    severity: "Critical",
    status: "Active",
    analyst: "AI Auto-Triage",
    recommendation: "Scale mitigation and throttle hostile traffic.",
  },
  {
    id: "ALT-2024-007",
    source: "Endpoint",
    title: "Privilege Escalation Alert",
    severity: "High",
    status: "Investigating",
    analyst: "Sarah Chen",
    recommendation: "Review permissions, audit logs, and revoke access.",
  },
  {
    id: "ALT-2024-008",
    source: "Cloud",
    title: "Suspicious Login Activity",
    severity: "Medium",
    status: "Active",
    analyst: "Marcus Johnson",
    recommendation: "Reset password, verify identity, enable MFA.",
  },
  {
    id: "ALT-2024-009",
    source: "Cloud",
    title: "Unusual Database Access",
    severity: "High",
    status: "Active",
    analyst: "AI Auto-Triage",
    recommendation: "Monitor queries and restrict risky roles.",
  },
  {
    id: "ALT-2024-010",
    source: "Endpoint",
    title: "Outdated Software Vulnerability",
    severity: "Low",
    status: "Pending Patch",
    analyst: "Sarah Chen",
    recommendation: "Schedule updates and confirm patch compliance.",
  },
  {
    id: "ALT-2024-011",
    source: "Endpoint",
    title: "Endpoint Protection Alert",
    severity: "Medium",
    status: "Resolved",
    analyst: "Marcus Johnson",
    recommendation: "Confirm malware removal and posture is up-to-date.",
  },
  {
    id: "ALT-2024-012",
    source: "Cloud",
    title: "Unauthorized Cloud Resource Access",
    severity: "Medium",
    status: "Active",
    analyst: "AI Auto-Triage",
    recommendation: "Revoke keys, audit configs, tighten IAM policies.",
  },
];
