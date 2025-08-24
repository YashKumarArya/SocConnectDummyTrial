#!/usr/bin/env ts-node
/*
  EDR → OCSF normalizer (TypeScript, aligned to DDL)

  Alignments vs prior TS version:
  ✓ Emit actor.process.user.domain by splitting threatInfo.processUser (DOMAIN\\user)
  ✓ Fallback: threat.indicators ← top-level indicators[] if threatInfo.indicators missing/empty
  ✓ NEW: Emit file.signature.certificate.is_valid (boolean) alongside .status
  ✓ NEW: Emit agentMachineType (camelCase) in addition to device.type/agent_machine_type
  ✓ Align: file.analysis.depth (instead of file.depth)
  ✓ Align: VT stats key uses confirmed_timeout (underscore)
  ✗ Removed alias output process.is_fileless (keep only process.isFileless)

  CLI:
    ts-node normalizer_patched_aligned.ts --in ./in --out ./out [--flat]
*/

import * as fs from "fs/promises";
import * as path from "path";

export type Json = any;

// ------------------- Helpers -------------------
function getNested(obj: Json, dotPath: string, defaultVal: any = null): any {
  let cur: any = obj;
  for (const raw of dotPath.split(".")) {
    if (cur == null) return defaultVal;
    if (raw.endsWith("[]")) {
      const key = raw.slice(0, -2);
      if (typeof cur !== "object" || !(key in cur)) return defaultVal;
      const arr = cur[key];
      if (!Array.isArray(arr) || arr.length === 0) return defaultVal;
      cur = arr[0];
    } else {
      if (typeof cur === "object" && raw in cur) cur = cur[raw];
      else return defaultVal;
    }
  }
  return cur;
}

function isEmpty(v: any): boolean {
  if (v === null || v === undefined) return true;
  if (typeof v === "string" && v.trim() === "") return true;
  if (Array.isArray(v) && v.length === 0) return true;
  if (typeof v === "object" && v && Object.keys(v).length === 0) return true;
  return false;
}

function toConfidence(val: any): number | null {
  if (typeof val === "number") return Math.max(0, Math.min(100, Math.trunc(val)));
  if (typeof val === "string") {
    const m = val.trim().toLowerCase();
    const map: Record<string, number> = {
      critical: 95,
      malicious: 90,
      high: 85,
      medium: 60,
      suspicious: 50,
      low: 30,
      benign: 10,
      informational: 10,
    };
    return map[m] ?? 70;
  }
  return null;
}

function boolToCertStatus(v: boolean | null | undefined): "valid" | "invalid" | null {
  if (v === true) return "valid";
  if (v === false) return "invalid";
  return null;
}

function extFromPath(fp: string | null | undefined): string | null {
  if (typeof fp === "string" && fp.includes(".")) {
    const ext = fp.split(".").pop()!.trim().toLowerCase();
    return ext || null;
  }
  return null;
}

function splitProcessUser(raw: string | null | undefined): { domain: string | null; username: string | null } {
  if (typeof raw !== "string" || !raw.includes("\\")) return { domain: null, username: null };
  const [dom, usr] = raw.split("\\", 1 + 1);
  return { domain: dom || null, username: usr || null };
}

function buildIPv4List(src: Json): string[] {
  const ips: string[] = [];
  const p1 = getNested(src, "agentDetectionInfo.agentIpV4");
  if (typeof p1 === "string" && p1.trim()) ips.push(p1.trim());

  const nis = getNested(src, "agentRealtimeInfo.networkInterfaces");
  if (Array.isArray(nis)) {
    for (const iface of nis) {
      if (iface && typeof iface === "object" && Array.isArray(iface.inet)) {
        for (const ip of iface.inet) if (typeof ip === "string" && ip.trim()) ips.push(ip.trim());
      }
    }
  }

  const seen = new Set<string>();
  const out: string[] = [];
  for (const ip of ips) { if (!seen.has(ip)) { seen.add(ip); out.push(ip); } }
  return out;
}

// ------------------- Unflatten (dot/list → nested) -------------------
const SEG_RE = /^([^\.\[]+)(?:\[(\d*)\])?$/;
export function unflattenDotmap(flat: Record<string, any>): Json {
  const root: any = {};
  for (const [fullPath, value] of Object.entries(flat)) {
    let cur: any = root;
    const parts = fullPath.split(".");
    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];
      const m = SEG_RE.exec(part);
      const key = m ? m[1] : part;
      const idxStr = m ? m[2] : undefined;
      const last = i === parts.length - 1;

      if (idxStr === undefined) {
        if (last) cur[key] = value;
        else {
          if (!(key in cur) || typeof cur[key] !== "object" || Array.isArray(cur[key])) cur[key] = {};
          cur = cur[key];
        }
      } else {
        const index = idxStr === "" ? 0 : parseInt(idxStr, 10);
        if (!(key in cur) || !Array.isArray(cur[key])) cur[key] = [];
        while (cur[key].length <= index) cur[key].push({});
        if (last) cur[key][index] = value;
        else {
          if (typeof cur[key][index] !== "object" || Array.isArray(cur[key][index])) cur[key][index] = {};
          cur = cur[key][index];
        }
      }
    }
  }
  return root;
}

// ------------------- Mappings -------------------
const OCSF_MAPPED: Array<[string, string]> = [
  ["threatInfo.filePath", "file.path"],
  ["threatInfo.fileExtensionType", "file.extension"],
  ["threatInfo.sha256", "file.hashes.sha256"],
  ["threatInfo.sha1", "file.hashes.sha1"],
  ["threatInfo.md5", "file.hashes.md5"],
  ["threatInfo.originatorProcess", "process.name"],
  ["threatInfo.detectionType", "threat.detection.type"],
  ["threatInfo.processUser (username)", "actor.process.user.name"],
  ["threatInfo.processUser (domain)", "actor.process.user.domain"],
  ["agentRealtimeInfo.agentComputerName", "device.hostname"],
  ["agentRealtimeInfo.agentOsType", "device.os.type"],
  ["threatInfo.fileVerificationType", "file.verification.type"],
  ["threatInfo.isValidCertificate", "file.signature.certificate.status"],
  ["threatInfo.isValidCertificate", "file.signature.certificate.is_valid"], // NEW boolean
  ["mitigationStatus[].status", "remediation.status"],
  ["threatInfo.indicators", "threat.indicators"],
  ["agentRealtimeInfo.networkInterfaces[].inet", "device.ipv4_addresses"],
  ["threatInfo.incidentStatus", "incident.status"],
  ["threatInfo.maliciousProcessArguments", "process.cmd.args"],
  ["threatInfo.fileSize", "file.size"],
  ["threatInfo.isFileless", "process.isFileless"],
  ["threatInfo.confidenceLevel", "threat.confidence"],
  ["threatInfo.classification", "threat.classification"],
  ["threatInfo.mitigationStatus", "remediation.status"],
  ["agentDetectionInfo.agentDomain", "device.domain"],
  ["agentDetectionInfo.agentIpV4", "device.ipv4_addresses"],
  ["agentDetectionInfo.agentVersion", "device.agents[].version"],
  ["agentDetectionInfo.agentLastLoggedInUserName", "actor.user.name"],
  ["agentDetectionInfo.agentMitigationMode", "device.agents.state"],
  ["agentRealtimeInfo.agentNetworkStatus", "device.network.status"],
  ["agentRealtimeInfo.agentIsActive", "device.is_active"],
  ["threatInfo.identifiedAt", "threat.detected_time"],
  ["threatInfo.threatId", "threat.id"],
  ["threatInfo.analystVerdict", "threat.verdict"],
  ["threatInfo.threatName", "threat.name"],

  // Extended
  ["threatInfo.createdAt", "time"],
  ["agentRealtimeInfo.agentUuid", "device.uuid"],
  ["agentRealtimeInfo.agentOsName", "device.os.name"],
  ["threatInfo.filePath + agentRealtimeInfo.agentUuid", "file.uid"],
  ["threatInfo.publisherName", "file.signature.certificate.issuer"],
  ["threatInfo.cloudFilesHashVerdict", "file.reputation.score"],
  ["agentDetectionInfo.externalIp", "device.interface.ip"],
  ["mitigationStatus[].action", "remediation.desc"],
  ["mitigationStatus[].mitigationStartedAt", "remediation.start_time"],
  ["mitigationStatus[].mitigationEndedAt", "remediation.end_time"],
  ["mitigationStatus[].reportId", "remediation.uid"],
  ["threatInfo.detectionEngines[].key", "metadata.product.feature.name"],
  ["threatInfo.detectionEngines[].title", "metadata.product.feature.version"],
  ["agentDetectionInfo.siteId", "device.location.uid"],
  ["agentDetectionInfo.siteName", "device.location.desc"],
  ["agentDetectionInfo.groupId", "device.groups[].uid"],
  ["agentDetectionInfo.groupName", "device.groups[].name"],
  ["agentRealtimeInfo.networkInterfaces[].name", "device.interface.name"],
  ["agentRealtimeInfo.networkInterfaces[].physical", "device.interface.mac"],
  ["threatInfo.incidentStatusDescription", "incident.desc"],
  ["agentRealtimeInfo.agentOsRevision", "device.os.build"],
  ["whiteningOptions[]", "remediation.result"],

  // Identity & aliases
  ["id", "alert.id"],
  ["threatInfo.threatName", "file.name"],
  ["id", "id"],
  ["agentDetectionInfo.agentMitigationMode", "device.agents.state"],
  ["agentRealtimeInfo.agentMachineType", "agent_machine_type"],
  ["agentRealtimeInfo.agentMachineType", "agentMachineType"], // NEW camelCase
  ["agentRealtimeInfo.agentMachineType", "device.type"],
  ["threatInfo.analystVerdict", "analyst_verdict"],
  ["threatInfo.classification", "classification"],
  ["threatInfo.confidenceLevel", "confidence_level"],
  ["agentDetectionInfo.agentMitigationMode", "device.agents[].state"],
  ["threatInfo.fileExtensionType", "file.extension_type"],
  ["threatInfo.fileDepth", "file.analysis.depth"], // aligned
  ["threatInfo.severity", "severity_id"],
  ["threatInfo.threatName", "threat_name"],
  ["threatInfo.behavior", "threat.behavior.observed"],
  ["threatInfo.malwareClassification", "malware[].classification_ids[]"],
  ["threatInfo.malwareName", "malware[].name[]"],
  ["agentRealtimeInfo.productName", "metadata.product.name[]"],
  ["threatInfo.detectionEngines[].key", "metadata.product.feature.name[].key"],
  ["threatInfo.detectionEngines[].title", "metadata.product.feature.name[].title"],
  ["cp_enrichment.risk", "gnn_score.false_positive"],
  ["vt_enrichment.score", "ml_score.false_positive"],
  ["baseline_score", "rule_base_score.false_positive"],
  ["cp_enrichment.reputation.classification", "enrichments[].data.classification"],
  ["cp_enrichment.reputation.confidence", "enrichments[].data.confidence"],
  ["cp_enrichment.findings.first_seen", "enrichments[].data.first_seen_time"],
  ["cp_enrichment.reputation.malicious", "enrichments[].data.malicious"],
  ["cp_enrichment.resource", "enrichments[].data.name"],
  ["cp_enrichment.findings.positives", "enrichments[].data.positives"],
  ["cp_enrichment.resource", "enrichments[].data.resource"],
  ["cp_enrichment.risk", "enrichments[].data.risk_score"],
  ["vt_enrichment.scan_date", "enrichments[].data.scan_time"],
  ["cp_enrichment.reputation.severity", "enrichments[].data.severity"],
  ["cp_enrichment.findings.file_size", "enrichments[].data.size"],
  ["vt_enrichment.last_analysis_stats.confirmed-timeout", "enrichments[].data.stats.confirmed_timeout"],
  ["vt_enrichment.last_analysis_stats.failure", "enrichments[].data.stats.failure"],
  ["vt_enrichment.last_analysis_stats.harmless", "enrichments[].data.stats.harmless"],
  ["vt_enrichment.last_analysis_stats.malicious", "enrichments[].data.stats.malicious"],
  ["vt_enrichment.last_analysis_stats.suspicious", "enrichments[].data.stats.suspicious"],
  ["vt_enrichment.last_analysis_stats.timeout", "enrichments[].data.stats.timeout"],
  ["vt_enrichment.last_analysis_stats.undetected", "enrichments[].data.stats.undetected"],
  ["vt_enrichment.last_analysis_stats.type-unsupported", "enrichments[].data.stats.unsupported"],
  ["cp_enrichment.reputation.suspicious", "enrichments[].data.suspicious"],
  ["vt_enrichment.total", "enrichments[].data.total"],
  ["cp_enrichment.findings.file_type", "enrichments[].data.type"],
];

// ------------------- Special builders -------------------
function buildMetadataProductNames(src: Json): string[] {
  const vals: string[] = [];
  const initBy = getNested(src, "threatInfo.initiatedBy");
  if (typeof initBy === "string" && initBy.trim()) vals.push(initBy.trim());
  const engines = getNested(src, "threatInfo.engines");
  if (Array.isArray(engines)) {
    for (const e of engines) if (typeof e === "string" && e.trim()) vals.push(e.trim());
  }
  const seen = new Set<string>();
  const out: string[] = [];
  for (const v of vals) if (!seen.has(v)) { seen.add(v); out.push(v); }
  return out;
}

function buildEnrichmentsFlat(src: Json): Record<string, any> {
  const out: Record<string, any> = {};

  // CP → enrichments[0]
  const cpMap: Record<string, any> = {
    "enrichments[0].data.classification":  getNested(src, "cp_enrichment.reputation.classification"),
    "enrichments[0].data.confidence":      getNested(src, "cp_enrichment.reputation.confidence"),
    "enrichments[0].data.severity":        getNested(src, "cp_enrichment.reputation.severity"),
    "enrichments[0].data.risk_score":      getNested(src, "cp_enrichment.risk"),
    "enrichments[0].data.name":            getNested(src, "cp_enrichment.context.protection_name"),
    "enrichments[0].data.type":            getNested(src, "cp_enrichment.findings.file_type"),
    "enrichments[0].data.size":            getNested(src, "cp_enrichment.findings.file_size"),
    "enrichments[0].data.first_seen_time": getNested(src, "cp_enrichment.findings.first_seen"),
    "enrichments[0].data.positives":       getNested(src, "cp_enrichment.findings.positives"),
    "enrichments[0].data.total":           getNested(src, "cp_enrichment.findings.total"),
    "enrichments[0].data.resource":        getNested(src, "cp_enrichment.resource"),
  };
  for (const [k, v] of Object.entries(cpMap)) out[k] = isEmpty(v) ? null : v;

  const fam = getNested(src, "cp_enrichment.context.malware_family");
  const mtys = getNested(src, "cp_enrichment.context.malware_types");
  out["malware[0].classification_ids"] = !isEmpty(fam) ? [fam] : null;
  out["malware[0].name"] = Array.isArray(mtys) && mtys.length ? mtys : null;

  // VT → enrichments[1]
  const vtMap: Record<string, any> = {
    "enrichments[1].data.positives":       getNested(src, "vt_enrichment.vt_positives"),
    "enrichments[1].data.total":           getNested(src, "vt_enrichment.total"),
    "enrichments[1].data.malicious":       getNested(src, "vt_enrichment.malicious"),
    "enrichments[1].data.suspicious":      getNested(src, "vt_enrichment.suspicious"),
    "enrichments[1].data.scan_time":       getNested(src, "vt_enrichment.scan_date"),
    "enrichments[1].data.stats.malicious": getNested(src, "vt_enrichment.last_analysis_stats.malicious"),
    "enrichments[1].data.stats.suspicious":getNested(src, "vt_enrichment.last_analysis_stats.suspicious"),
    "enrichments[1].data.stats.undetected":getNested(src, "vt_enrichment.last_analysis_stats.undetected"),
    "enrichments[1].data.stats.harmless":  getNested(src, "vt_enrichment.last_analysis_stats.harmless"),
    "enrichments[1].data.stats.unsupported":getNested(src, "vt_enrichment.last_analysis_stats.type-unsupported"),
    // underscore aligned
    "enrichments[1].data.stats.timeout":   getNested(src, "vt_enrichment.last_analysis_stats.timeout") || 0,
    "enrichments[1].data.stats.confirmed_timeout": getNested(src, "vt_enrichment.last_analysis_stats.confirmed-timeout") || 0,
    "enrichments[1].data.stats.failure":   getNested(src, "vt_enrichment.last_analysis_stats.failure") || 0,
  };
  for (const [k, v] of Object.entries(vtMap)) out[k] = isEmpty(v) ? null : v;

  return out;
}

// ------------------- Normalize one alert → nested OCSF -------------------
export function normalizeOneToNested(src: Json): Json {
  const flat: Record<string, any> = {};

  for (const [edrPath, ocsfPath] of OCSF_MAPPED) {
    let val: any;
    if (edrPath === "threatInfo.processUser (username)") {
      const rawUser = getNested(src, "threatInfo.processUser");
      const { username } = splitProcessUser(rawUser);
      val = username;
    } else if (edrPath === "threatInfo.processUser (domain)") {
      const rawUser = getNested(src, "threatInfo.processUser");
      const { domain } = splitProcessUser(rawUser);
      val = domain;
    } else if (edrPath === "threatInfo.indicators") {
      val = getNested(src, "threatInfo.indicators");
      if (isEmpty(val)) val = (src && typeof src === "object") ? src["indicators"] : null;
    } else if (ocsfPath === "threat.confidence") {
      val = toConfidence(getNested(src, edrPath));
    } else if (ocsfPath === "file.signature.certificate.status") {
      val = boolToCertStatus(getNested(src, edrPath));
    } else if (ocsfPath === "device.ipv4_addresses") {
      val = buildIPv4List(src);
    } else if (ocsfPath === "file.extension") {
      let v0 = getNested(src, edrPath);
      if (isEmpty(v0)) {
        const fp = getNested(src, "threatInfo.filePath");
        v0 = extFromPath(fp);
      }
      val = v0;
    } else if (edrPath === "threatInfo.filePath + agentRealtimeInfo.agentUuid") {
      const fp = getNested(src, "threatInfo.filePath");
      const uuid = getNested(src, "agentRealtimeInfo.agentUuid");
      val = (typeof fp === "string" && typeof uuid === "string") ? `${fp}_${uuid}` : null;
    } else {
      val = getNested(src, edrPath);
    }

    flat[ocsfPath] = isEmpty(val) ? null : val;
  }

  // Aggregate product names (initiatedBy + engines[])
  flat["metadata.product.name"] = buildMetadataProductNames(src);

  // Enrichments & malware
  Object.assign(flat, buildEnrichmentsFlat(src));

  // Coalesce agent state to agents[].state
  if ("device.agents.state" in flat) {
    const stateVal = flat["device.agents.state"];
    delete flat["device.agents.state"];
    flat["device.agents[].state"] = stateVal;
  }

  return unflattenDotmap(flat);
}

// ------------------- Flatten -------------------
export function flatten(obj: any, prefix = "", out: Record<string, any> = {}): Record<string, any> {
  if (obj !== null && typeof obj === "object" && !Array.isArray(obj)) {
    for (const [k, v] of Object.entries(obj)) flatten(v, prefix ? `${prefix}.${k}` : k, out);
  } else if (Array.isArray(obj)) {
    if (obj.length === 0) out[prefix] = [];
    else obj.forEach((v, i) => flatten(v, `${prefix}[${i}]`, out));
  } else {
    out[prefix] = obj;
  }
  return out;
}

// ------------------- CLI -------------------
async function mainCLI() {
  const args = process.argv.slice(2);
  let inDir = "";
  let outDir = "";
  let writeFlat = false;

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--in" && args[i + 1]) inDir = args[++i];
    else if (a === "--out" && args[i + 1]) outDir = args[++i];
    else if (a === "--flat") writeFlat = true;
  }

  if (!inDir) inDir = process.env.INPUT_DIR || "./in";
  if (!outDir) outDir = process.env.OUTPUT_DIR || "./out";

  await fs.mkdir(outDir, { recursive: true });
  const files = (await fs.readdir(inDir)).filter(f => f.toLowerCase().endsWith(".json"));
  let total = 0, ok = 0;

  for (const f of files) {
    total++;
    const p = path.join(inDir, f);
    try {
      const rawText = await fs.readFile(p, "utf8");
      const parsed = JSON.parse(rawText);
      const src = (parsed && typeof parsed === "object" && Array.isArray(parsed.data) && parsed.data.length)
        ? parsed.data[0]
        : parsed;

      const nested = normalizeOneToNested(src);
      const outPath = path.join(outDir, f);
      await fs.writeFile(outPath, JSON.stringify(nested, null, 2));

      if (writeFlat) {
        const flat = flatten(nested);
        const flatPath = path.join(outDir, `${path.parse(f).name}.flat.json`);
        await fs.writeFile(flatPath, JSON.stringify(flat, null, 2));
      }

      ok++;
    } catch (e: any) {
      console.error(`[ERROR] ${f}:`, e?.message || e);
    }
  }

  console.log(`Processed: ${total} | Normalized & saved: ${ok} | Output: ${outDir}`);
}

if (require.main === module) {
  mainCLI().catch(err => { console.error(err); process.exit(1); });
}

// Compatibility wrapper for existing code that imports normalizeHybrid
export const normalizeHybrid = (rawData: any, _options?: any, _sourceType?: string) => {
  try {
    return normalizeOneToNested(rawData);
  } catch (e) {
    console.warn('normalizeHybrid wrapper: error converting using normalizeOneToNested', (e as any)?.message || e);
    return rawData || {};
  }
};
