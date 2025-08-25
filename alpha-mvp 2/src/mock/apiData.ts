// mock/apiData.ts
// Deterministic sequences that match your API shapes exactly.
// No randomness; always the same order and values.

import type {
  IncomingEvent,
  ResultEvent,
} from "@/components/common/DynamicDashboard"

export const MOCK_VENDOR_EVENTS: IncomingEvent[] = [
  { alert_id: "ALERT-0001", source: "SentinalOne" },
  { alert_id: "ALERT-0002", source: "CrowdStrike" },
  { alert_id: "ALERT-0003", source: "Checkpoint" },
  { alert_id: "ALERT-0004", source: "PaloAlto" },
  { alert_id: "ALERT-0005", source: "Fortinet" },
  { alert_id: "ALERT-0006", source: "Proofpoint" },
  { alert_id: "ALERT-0007", source: "Azure" },
  { alert_id: "ALERT-0008", source: "Okta" },
  { alert_id: "ALERT-0009", source: "Aws" },
  { alert_id: "ALERT-0010", source: "Gcp" },
  { alert_id: "ALERT-0011", source: "SentinalOne" },
  { alert_id: "ALERT-0012", source: "CrowdStrike" },
  { alert_id: "ALERT-0013", source: "Checkpoint" },
  { alert_id: "ALERT-0014", source: "PaloAlto" },
  { alert_id: "ALERT-0015", source: "Fortinet" },
  { alert_id: "ALERT-0016", source: "Proofpoint" },
  { alert_id: "ALERT-0017", source: "Azure" },
  { alert_id: "ALERT-0018", source: "Okta" },
  { alert_id: "ALERT-0019", source: "Aws" },
  { alert_id: "ALERT-0020", source: "Gcp" },
  { alert_id: "ALERT-0021", source: "SentinalOne" },
  { alert_id: "ALERT-0022", source: "CrowdStrike" },
  { alert_id: "ALERT-0023", source: "Checkpoint" },
  { alert_id: "ALERT-0024", source: "PaloAlto" },
];

export const MOCK_RESULT_EVENTS: ResultEvent[] = [
  { alert_id: "ALERT-0001", result: "tp" },
  { alert_id: "ALERT-0002", result: "fp" },
  { alert_id: "ALERT-0003", result: "esc" },
  { alert_id: "ALERT-0004", result: "tp" },
  { alert_id: "ALERT-0005", result: "fp" },
  { alert_id: "ALERT-0006", result: "fp" },
  { alert_id: "ALERT-0007", result: "tp" },
  { alert_id: "ALERT-0008", result: "fp" },
  { alert_id: "ALERT-0009", result: "esc" },
  { alert_id: "ALERT-0010", result: "fp" },
  { alert_id: "ALERT-0011", result: "fp" },
  { alert_id: "ALERT-0012", result: "esc" },
  { alert_id: "ALERT-0013", result: "tp" },
  { alert_id: "ALERT-0014", result: "fp" },
  { alert_id: "ALERT-0015", result: "tp" },
  { alert_id: "ALERT-0016", result: "tp" },
  { alert_id: "ALERT-0017", result: "fp" },
  { alert_id: "ALERT-0018", result: "tp" },
  { alert_id: "ALERT-0019", result: "tp" },
  { alert_id: "ALERT-0020", result: "fp" },
  { alert_id: "ALERT-0021", result: "esc" },
  { alert_id: "ALERT-0022", result: "tp" },
  { alert_id: "ALERT-0023", result: "fp" },
  { alert_id: "ALERT-0024", result: "esc" },
];
