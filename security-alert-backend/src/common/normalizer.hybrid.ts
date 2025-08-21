// normalizer.hybrid.ts
// Hybrid Attribute-First then Value-Based Normalizer -> OCSF-like output
// TypeScript (Node 18+)

import net from 'net';

type AnyObj = { [k: string]: any };

export interface NormalizerOptions {
  preferAttributeFirst?: boolean;
  preferKeyHints?: boolean;
  useValueMap?: boolean;
  valueMap?: Map<string, string>;
  maxObservables?: number;
  storeAmbiguous?: boolean;
  logUnmappedFields?: boolean;
  minConfidenceThreshold?: number;
  enableHardcodedOverrides?: boolean;
  maxDepth?: number;
}

export interface NormalizedOCSF {
  timestamp?: string;
  event?: any;
  user?: { name?: string; email?: string; id?: string; confidence?: number };
  src?: { ip?: string; port?: number; confidence?: number };
  dst?: { ip?: string; port?: number; confidence?: number };
  file?: { name?: string; path?: string; hash?: any; confidence?: number };
  process?: { name?: string; uid?: string; confidence?: number };
  email?: any;
  threat?: any;
  observables?: Array<{ type: string; value: string; confidence?: number; note?: string }>;
  original?: AnyObj;
  mappings?: Array<{ value: string; mappedTo: string; confidence: number; method: 'attribute'|'value'|'valueMap'|'ambiguous'|'hardcoded' }>;
  unmappedFields?: Array<{ key: string; value: any; reason: string; needsAttention: boolean }>;
  qualityMetrics?: {
    totalFields: number;
    mappedFields: number;
    lowConfidenceFields: number;
    unmappedFields: number;
    averageConfidence: number;
    needsHumanReview: boolean;
  };
}

// ---------- detection helpers ----------
const re = {
  email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  sha256: /^[A-Fa-f0-9]{64}$/,
  sha1: /^[A-Fa-f0-9]{40}$/,
  md5: /^[A-Fa-f0-9]{32}$/,
  isoDate: /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?$/,
  windowsPath: /^[a-zA-Z]:\\[^\n\r]+/,
  unixPath: /^\/[^\n\r]*/,
  numeric: /^-?\d+$/,
  hostname: /^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$/,
  usernameLike: /^[a-zA-Z0-9._-]{2,64}$/
};

function looksLikeTimestamp(s: string): boolean {
  if (!s || typeof s !== 'string') return false;
  if (re.isoDate.test(s)) return true;
  const parsed = Date.parse(s);
  return !Number.isNaN(parsed);
}

function isUrl(s: string): boolean {
  try {
    // will throw for invalid
    // allow protocol-less by prepending scheme for parse attempts
    const as = s.startsWith('http://') || s.startsWith('https://') ? s : `http://${s}`;
    // eslint-disable-next-line no-new
    new URL(as);
    return true;
  } catch {
    return false;
  }
}

function detectValueType(v: any): string | null {
  if (v === null || v === undefined) return null;
  if (typeof v === 'number') return 'number';
  if (typeof v !== 'string') return null;
  const s = v.trim();
  if (!s.length) return null;
  if (re.sha256.test(s)) return 'sha256';
  if (re.sha1.test(s)) return 'sha1';
  if (re.md5.test(s)) return 'md5';
  if (net.isIP(s)) return 'ip';
  if (re.email.test(s)) return 'email';
  if (isUrl(s)) return 'url';
  if (looksLikeTimestamp(s)) return 'timestamp';
  if (re.windowsPath.test(s) || re.unixPath.test(s)) return 'filepath';
  if (re.hostname.test(s)) return 'domain';
  if (re.usernameLike.test(s)) return 'username';
  return 'text';
}

// ---------- attribute alias dictionary (expandable) ----------
const attributeAliasMap: Array<{ aliases: string[]; canonical: string; priority: number }> = [
  { aliases: ['src', 'src_ip', 'source_ip', 'sourceip', 'source-address', 'srcaddr', 'clientip'], canonical: 'src.ip', priority: 10 },
  { aliases: ['dst', 'dest', 'dst_ip', 'destination_ip', 'destaddr', 'remote_ip', 'remote'], canonical: 'dst.ip', priority: 10 },
  { aliases: ['src_port', 'sport'], canonical: 'src.port', priority: 9 },
  { aliases: ['dst_port', 'dport', 'dest_port'], canonical: 'dst.port', priority: 9 },
  { aliases: ['user', 'user.name', 'username', 'account', 'acct'], canonical: 'user.name', priority: 9 },
  { aliases: ['email', 'email_addr', 'sender', 'from', 'mail_from', 'sender_email', 'from_email'], canonical: 'email.sender', priority: 11 },
  { aliases: ['to', 'recipient', 'rcpt', 'recipient_email'], canonical: 'email.recipient', priority: 11 },
  { aliases: ['subject', 'email_subject'], canonical: 'email.subject', priority: 11 },
  { aliases: ['file', 'file_name', 'filename', 'file.name', 'process.file.name'], canonical: 'file.name', priority: 10 },
  { aliases: ['path', 'filepath', 'file_path', 'process.path'], canonical: 'file.path', priority: 10 },
  { aliases: ['sha256', 'hash', 'file_hash', 'file.hash.sha256'], canonical: 'file.hash.sha256', priority: 12 },
  { aliases: ['sha1', 'file.hash.sha1'], canonical: 'file.hash.sha1', priority: 12 },
  { aliases: ['md5', 'file.hash.md5'], canonical: 'file.hash.md5', priority: 12 },
  { aliases: ['url', 'uri', 'link'], canonical: 'event.url', priority: 10 },
  { aliases: ['severity', 'severity_id', 'level'], canonical: 'event.severity', priority: 9 },
  { aliases: ['time', 'timestamp', 'original_time', 'event_time', 'date'], canonical: 'timestamp', priority: 12 },
  { aliases: ['process', 'proc', 'process.name', 'pid'], canonical: 'process.name', priority: 8 },
  { aliases: ['threat', 'malware', 'threat_name'], canonical: 'threat.name', priority: 9 },
  { aliases: ['protocol'], canonical: 'network.protocol', priority: 8 },
  { aliases: ['device_name', 'hostname', 'host', 'computer_name'], canonical: 'src.hostname', priority: 10 },
  { aliases: ['alert_name', 'rule_name', 'title'], canonical: 'event.title', priority: 9 },
  { aliases: ['tactic', 'technique', 'alert_type', 'threat_type'], canonical: 'event.type', priority: 9 }
];

const hardcodedSourceOverrides: { [sourceType: string]: { [fieldName: string]: string } } = {
  crowdstrike: {
    falcon_event_id: 'event.id',
    detection_id: 'event.detection_id',
    cid: 'event.customer_id',
    machine_domain: 'src.domain',
    parent_process_id: 'process.parent.pid',
    cmdline: 'process.command_line',
    ioa_count: 'event.ioa_count'
  },
  sentinelone: {
    agent_id: 'event.agent_id',
    site_id: 'event.site_id',
    group_id: 'event.group_id',
    endpoint_name: 'src.hostname',
    endpoint_type: 'src.device_type',
    threat_classification_source: 'threat.classification_source',
    file_content_hash: 'file.hash.sha1',
    storyline: 'event.storyline'
  },
  email: {
    message_id: 'email.message_id',
    mail_from: 'email.sender',
    rcpt_to: 'email.recipient',
    x_originating_ip: 'src.ip',
    spam_score: 'email.spam_score',
    verdict: 'email.verdict',
    attachment_count: 'email.attachment_count',
    dkim_result: 'email.dkim_result',
    spf_result: 'email.spf_result'
  },
  firewall: {
    rule_id: 'event.rule_id',
    policy_name: 'event.policy_name',
    zone_src: 'network.src_zone',
    zone_dst: 'network.dst_zone',
    bytes_sent: 'network.bytes_sent',
    bytes_received: 'network.bytes_received',
    packets_sent: 'network.packets_sent',
    packets_received: 'network.packets_received',
    connection_state: 'network.connection_state'
  }
};

function normalizeKey(k: string) {
  return String(k || '').toLowerCase().replace(/[\s\-_]/g, '');
}

function attributeLookup(key: string) {
  if (!key) return null;
  const k = normalizeKey(key);
  let best: { canonical: string; priority: number } | null = null;
  for (const entry of attributeAliasMap) {
    for (const a of entry.aliases) {
      const aNorm = normalizeKey(a);
      if (k === aNorm || k.includes(aNorm) || aNorm.includes(k)) {
        if (!best || entry.priority > best.priority) best = { canonical: entry.canonical, priority: entry.priority };
      }
    }
  }
  return best;
}

function scoreAttributePriority(priority: number) {
  const maxPriority = 12;
  const base = Math.min(Math.max(priority, 1), maxPriority);
  return 0.6 + (base / maxPriority) * 0.4; // 0.6..1.0
}

function scoreValueType(type: string | null) {
  if (!type) return 0.3;
  switch (type) {
    case 'sha256': return 0.98;
    case 'sha1': return 0.92;
    case 'md5': return 0.9;
    case 'ip': return 0.95;
    case 'email': return 0.95;
    case 'url': return 0.9;
    case 'timestamp': return 0.9;
    case 'filepath': return 0.75;
    case 'domain': return 0.7;
    case 'username': return 0.6;
    case 'text': return 0.3;
    case 'number': return 0.3;
    default: return 0.3;
  }
}

function valueTypeToCanonicalFallback(type: string | null): string {
  switch (type) {
    case 'ip': return 'src.ip';
    case 'email': return 'user.email';
    case 'sha256': return 'file.hash.sha256';
    case 'sha1': return 'file.hash.sha1';
    case 'md5': return 'file.hash.md5';
    case 'timestamp': return 'timestamp';
    case 'filepath': return 'file.path';
    case 'domain': return 'src.hostname';
    case 'username': return 'user.name';
    case 'url': return 'event.url';
    default: return 'observables';
  }
}

function applyCanonical(normalized: NormalizedOCSF, canonical: string, val: any, confidence: number) {
  const parts = canonical.split('.');
  if (canonical === 'timestamp') {
    normalized.timestamp = String(val);
    return;
  }
  switch (parts[0]) {
    case 'user':
      normalized.user = normalized.user || {};
      if (parts[1] === 'name') normalized.user.name = val, normalized.user.confidence = confidence;
      else if (parts[1] === 'email') normalized.user.email = val, normalized.user.confidence = confidence;
      else if (parts[1] === 'id') (normalized.user as any).id = val;
      break;
    case 'src':
      normalized.src = normalized.src || {};
      if (parts[1] === 'ip') normalized.src.ip = val, normalized.src.confidence = confidence;
      if (parts[1] === 'port') normalized.src.port = Number(val), normalized.src.confidence = confidence;
      if (parts[1] === 'hostname') (normalized.src as any).hostname = val;
      break;
    case 'dst':
      normalized.dst = normalized.dst || {};
      if (parts[1] === 'ip') normalized.dst.ip = val, normalized.dst.confidence = confidence;
      if (parts[1] === 'port') normalized.dst.port = Number(val), normalized.dst.confidence = confidence;
      break;
    case 'file':
      normalized.file = normalized.file || { hash: {} };
      if (parts[1] === 'name') normalized.file.name = val, normalized.file.confidence = confidence;
      if (parts[1] === 'path') normalized.file.path = val, normalized.file.confidence = confidence;
      if (parts[1] === 'hash') {
        const algo = parts[2] || 'sha256';
        normalized.file.hash = normalized.file.hash || {};
        (normalized.file.hash as AnyObj)[algo] = val;
        normalized.file.confidence = confidence;
      }
      break;
    case 'process':
      normalized.process = normalized.process || {};
      if (parts[1] === 'name') normalized.process.name = val, normalized.process.confidence = confidence;
      break;
    case 'email':
      normalized.email = normalized.email || {};
      if (!normalized.email[parts[1]]) normalized.email[parts[1]] = val;
      break;
    case 'event':
      normalized.event = normalized.event || {};
      normalized.event[parts[1]] = val;
      break;
    case 'threat':
      normalized.threat = normalized.threat || {};
      normalized.threat[parts[1]] = val;
      break;
    case 'network':
      normalized.event = normalized.event || {};
      normalized.event.network = normalized.event.network || {};
      normalized.event.network[parts[1]] = val;
      break;
    case 'observables':
      normalized.observables = normalized.observables || [];
      const valueType = detectValueType(val);
      normalized.observables.push({
        type: valueType || 'text',
        value: String(val),
        confidence,
        note: `Fallback mapping for ${canonical}`
      });
      break;
    default:
      normalized.event = normalized.event || {};
      normalized.event.raw = normalized.event.raw || {};
      (normalized.event.raw as AnyObj)[canonical] = val;
  }
}

function normalizeValueKey(s: string) {
  return String(s || '').trim().toLowerCase();
}

function redactValue(val: any) {
  if (val === null || val === undefined) return val;
  const s = String(val);
  // redact long strings or obvious secrets/hashes
  if (s.length > 120) return `${s.slice(0, 60)}...<redacted:${s.length}>`;
  if (re.sha256.test(s) || re.sha1.test(s) || re.md5.test(s)) return `<redacted_hash:${s.length}>`;
  return s;
}

// protective walker with maxDepth and cycle detection
function walkHybrid(
  obj: AnyObj,
  normalized: NormalizedOCSF,
  opts: Required<NormalizerOptions>,
  valueMap: Map<string, string>,
  sourceType?: string,
  parentKey?: string,
  depth = 0,
  seen: WeakSet<object> | null = null
) {
  if (!seen) seen = new WeakSet();
  if (!obj || typeof obj !== 'object') return;
  if (depth > opts.maxDepth) return;
  if (seen.has(obj)) return; // cycle
  seen.add(obj);

  normalized.unmappedFields = normalized.unmappedFields || [];

  for (const [rawKey, rawVal] of Object.entries(obj)) {
    const key = String(rawKey);
    if (rawVal === null || rawVal === undefined) continue;

    if (typeof rawVal === 'string' || typeof rawVal === 'number' || typeof rawVal === 'boolean') {
      const asStr = String(rawVal).trim();
      if (!asStr.length) continue;

      // hardcoded overrides
      if (opts.enableHardcodedOverrides && sourceType && hardcodedSourceOverrides[sourceType]) {
        const normalizedKey = normalizeKey(key);
        const override = Object.entries(hardcodedSourceOverrides[sourceType]).find(([k]) => normalizeKey(k) === normalizedKey);
        if (override) {
          const canonical = override[1];
          const conf = 0.99;
          applyCanonical(normalized, canonical, asStr, conf);
          normalized.mappings = normalized.mappings || [];
          normalized.mappings.push({ value: asStr, mappedTo: canonical, confidence: conf, method: 'hardcoded' });
          if (opts.logUnmappedFields) console.log(`HARDCODED: ${sourceType}.${key} → ${canonical}`);
          continue;
        }
      }

      // valueMap lookup (normalize key)
      if (opts.useValueMap && valueMap && valueMap.size) {
        const vk = normalizeValueKey(asStr);
        if (valueMap.has(vk)) {
          const canonical = valueMap.get(vk)!;
          const conf = 0.96;
          applyCanonical(normalized, canonical, asStr, conf);
          normalized.mappings = normalized.mappings || [];
          normalized.mappings.push({ value: asStr, mappedTo: canonical, confidence: conf, method: 'valueMap' });
          continue;
        }
      }

      // attribute-first
      let attrCandidate = null;
      if (opts.preferAttributeFirst) {
        const attr = attributeLookup(key);
        if (attr) attrCandidate = attr;
      }

      const valueType = detectValueType(asStr);

      if (attrCandidate) {
        const attrConf = scoreAttributePriority(attrCandidate.priority);
        const valConf = scoreValueType(valueType || 'text');

        const attrMatchesValue = attrCandidate.canonical.includes(valueType || '');
        if (attrMatchesValue || attrConf >= valConf) {
          applyCanonical(normalized, attrCandidate.canonical, asStr, attrConf);
          normalized.mappings = normalized.mappings || [];
          normalized.mappings.push({ value: asStr, mappedTo: attrCandidate.canonical, confidence: attrConf, method: 'attribute' });
          if (opts.useValueMap) valueMap.set(normalizeValueKey(asStr), attrCandidate.canonical);
          continue;
        } else {
          const valueCanonical = valueTypeToCanonicalFallback(valueType);
          const valScore = scoreValueType(valueType || 'text');

          applyCanonical(normalized, attrCandidate.canonical, asStr, attrConf * 0.9);
          applyCanonical(normalized, valueCanonical, asStr, valScore);

          normalized.mappings = normalized.mappings || [];
          normalized.mappings.push({ value: asStr, mappedTo: attrCandidate.canonical, confidence: attrConf * 0.9, method: 'ambiguous' });
          normalized.mappings.push({ value: asStr, mappedTo: valueCanonical, confidence: valScore, method: 'value' });

          if (opts.useValueMap) valueMap.set(normalizeValueKey(asStr), valueCanonical);
          continue;
        }
      } else {
        if (valueType && scoreValueType(valueType) > 0.7) {
          const valueCanonical = valueTypeToCanonicalFallback(valueType);
          const valScore = scoreValueType(valueType);
          applyCanonical(normalized, valueCanonical, asStr, valScore);
          normalized.mappings = normalized.mappings || [];
          normalized.mappings.push({ value: asStr, mappedTo: valueCanonical, confidence: valScore, method: 'value' });
          if (opts.useValueMap) valueMap.set(normalizeValueKey(asStr), valueCanonical);
          continue;
        } else {
          normalized.observables = normalized.observables || [];
          if (normalized.observables.length < opts.maxObservables) {
            normalized.observables.push({ type: valueType || 'text', value: asStr, confidence: scoreValueType(valueType), note: `Unmapped field: ${key}` });
          }
          const needsAttention = scoreValueType(valueType) > 0.5;
          normalized.unmappedFields!.push({ key, value: redactValue(asStr), reason: `Weak value type: ${valueType}, low confidence: ${scoreValueType(valueType)}`, needsAttention });
          if (opts.logUnmappedFields && needsAttention) {
            console.warn(`UNMAPPED FIELD: ${key} -> ${redactValue(asStr)} (type=${valueType}, conf=${scoreValueType(valueType)})`);
            console.warn(` Suggestion: Add to hardcodedSourceOverrides['${sourceType || 'unknown'}']['${key}'] = 'canonical.field.name'`);
          }
        }
      }
    } else if (Array.isArray(rawVal)) {
      // Arrays: if primitives, process similarly to primitives; if objects, recurse
      const primitives = rawVal.filter((x: any) => (typeof x !== 'object'));
      const objects = rawVal.filter((x: any) => (typeof x === 'object' && x !== null));
      for (const p of primitives) {
        // treat as individual values
        walkHybrid({ [key]: p }, normalized, opts, valueMap, sourceType, key, depth + 1, seen);
      }
      for (const o of objects) {
        walkHybrid(o, normalized, opts, valueMap, sourceType, key, depth + 1, seen);
      }
    } else if (typeof rawVal === 'object') {
      // nested object
      walkHybrid(rawVal, normalized, opts, valueMap, sourceType, key, depth + 1, seen);
    }
  }
}

export function normalizeHybrid(rawData: AnyObj, options: NormalizerOptions = {}, sourceType?: string): NormalizedOCSF {
  const opts: Required<NormalizerOptions> = {
    preferAttributeFirst: options.preferAttributeFirst ?? true,
    preferKeyHints: options.preferKeyHints ?? true,
    useValueMap: options.useValueMap ?? true,
    valueMap: options.valueMap ?? new Map<string, string>(),
    maxObservables: options.maxObservables ?? 50,
    storeAmbiguous: options.storeAmbiguous ?? true,
    logUnmappedFields: options.logUnmappedFields ?? true,
    minConfidenceThreshold: options.minConfidenceThreshold ?? 0.7,
    enableHardcodedOverrides: options.enableHardcodedOverrides ?? true,
    maxDepth: options.maxDepth ?? 10
  } as Required<NormalizerOptions>;

  const valueMap = opts.valueMap || new Map<string, string>();
  const normalized: NormalizedOCSF = { original: rawData, mappings: [], observables: [], unmappedFields: [] };

  // Walk with cycle protection
  walkHybrid(rawData, normalized, opts, valueMap, sourceType);

  const totalFields = countTotalFields(rawData);
  const mappedFields = normalized.mappings?.length || 0;
  const lowConfidenceFields = normalized.mappings?.filter(m => m.confidence < opts.minConfidenceThreshold).length || 0;
  const unmappedFields = normalized.unmappedFields?.length || 0;
  const averageConfidence = mappedFields > 0 ? normalized.mappings!.reduce((sum, m) => sum + m.confidence, 0) / mappedFields : 0;
  const needsHumanReview = lowConfidenceFields > 0 || normalized.unmappedFields?.some(f => f.needsAttention) || averageConfidence < opts.minConfidenceThreshold;

  normalized.qualityMetrics = { totalFields, mappedFields, lowConfidenceFields, unmappedFields, averageConfidence, needsHumanReview };

  if (opts.logUnmappedFields) logQualityReport(normalized, sourceType);

  return normalized;
}

function countTotalFields(obj: any): number {
  let count = 0;
  if (!obj || typeof obj !== 'object') return 0;
  for (const [key, value] of Object.entries(obj)) {
    if (value !== null && value !== undefined) {
      if (typeof value === 'object' && !Array.isArray(value)) {
        count += countTotalFields(value);
      } else if (Array.isArray(value)) {
        for (const item of value) {
          if (typeof item === 'object' && item !== null) count += countTotalFields(item);
          else count++;
        }
      } else {
        count++;
      }
    }
  }
  return count;
}

function logQualityReport(normalized: NormalizedOCSF, sourceType?: string) {
  const metrics = normalized.qualityMetrics!;
  const coverage = metrics.totalFields > 0 ? (metrics.mappedFields / metrics.totalFields * 100).toFixed(1) : '0';
  console.log(`\nNORMALIZATION QUALITY REPORT - ${sourceType || 'Unknown'}`);
  console.log(` Field Coverage: ${coverage}% (${metrics.mappedFields}/${metrics.totalFields})`);
  console.log(` Average Confidence: ${(metrics.averageConfidence * 100).toFixed(1)}%`);
  console.log(` Low Confidence Fields: ${metrics.lowConfidenceFields}`);
  console.log(` Unmapped Fields: ${metrics.unmappedFields}`);
  console.log(` Needs Human Review: ${metrics.needsHumanReview ? 'YES' : 'NO'}`);
  if (metrics.needsHumanReview) {
    const attentionFields = normalized.unmappedFields?.filter(f => f.needsAttention) || [];
    attentionFields.forEach(field => {
      console.log(`  Suggest: hardcodedSourceOverrides['${sourceType || 'unknown'}']['${field.key}'] = 'canonical.field.name'`);
    });
  }
}

export function convertToSOCAlert(hybridResult: NormalizedOCSF, sourceType?: string) {
  const mappings = hybridResult.mappings || [];
  const mappingConfidence = mappings.length ? mappings.reduce((sum, m) => sum + m.confidence, 0) / mappings.length : 0;

  return {
    timestamp: hybridResult.timestamp ? new Date(hybridResult.timestamp) : new Date(),
    sourceType: sourceType || 'hybrid',
    severity: hybridResult.event?.severity || 'medium',
    alertType: hybridResult.event?.type || 'anomaly',
    title: hybridResult.event?.title || 'Hybrid Normalized Alert',
    description: hybridResult.event?.description || 'Alert processed by hybrid normalizer',
    sourceIp: hybridResult.src?.ip,
    sourcePort: hybridResult.src?.port,
    destinationIp: hybridResult.dst?.ip,
    destinationPort: hybridResult.dst?.port,
    hostname: (hybridResult.src as any)?.hostname,
    username: hybridResult.user?.name,
    userEmail: hybridResult.user?.email,
    fileName: hybridResult.file?.name,
    filePath: hybridResult.file?.path,
    fileHash: hybridResult.file?.hash,
    processName: hybridResult.process?.name,
    emailSender: hybridResult.email?.sender,
    emailRecipient: hybridResult.email?.recipient,
    emailSubject: hybridResult.email?.subject,
    threatName: hybridResult.threat?.name,
    mappingConfidence: mappingConfidence,
    totalMappings: mappings.length || 0,
    highConfidenceMappings: mappings.filter(m => m.confidence > 0.8).length || 0,
    observables: hybridResult.observables || [],
    mappings: mappings || [],
    additionalData: hybridResult.original,
    qualityMetrics: hybridResult.qualityMetrics,
    unmappedFields: hybridResult.unmappedFields
  };
}
