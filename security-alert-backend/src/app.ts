import express from 'express';
import routes from './routes';
import { errorHandler } from './middleware/error';
import { loggerMiddleware } from './observability/logging';
import path from 'path';
import fs from 'fs';
import { config as appConfig } from './config';
import multer from 'multer';

const upload = multer({ storage: multer.memoryStorage() });

const app = express();
app.use(express.json());
app.use(loggerMiddleware);

// Serve static docs (non-UI assets) at /api/docs/static
app.use('/api/docs/static', express.static(path.join(__dirname, 'docs')));

// Serve OpenAPI spec reliably by reading the JSON file and returning as JSON
let openapiSpec: any = null;
const openapiPath = path.join(__dirname, 'docs', 'openapi.json');
if (fs.existsSync(openapiPath)) {
  try {
    const raw = fs.readFileSync(openapiPath, 'utf8');
    openapiSpec = JSON.parse(raw);
  } catch (err) {
    console.warn('Could not read openapi.json:', err);
  }
}
// Serve the latest on-disk openapi.json so edits are visible without a full server restart.
app.get('/api/openapi.json', (_req, res) => {
  try {
    if (fs.existsSync(openapiPath)) {
      const raw = fs.readFileSync(openapiPath, 'utf8');
      const spec = JSON.parse(raw);
      return res.json(spec);
    }
  } catch (err) {
    console.warn('Could not read openapi.json on request:', err);
  }
  if (!openapiSpec) return res.status(404).json({ error: 'openapi spec not found' });
  res.json(openapiSpec);
});

// Swagger UI (prefer swagger-ui-express). If not installed, fall back to Redoc single-file UI.
try {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const swaggerUi = require('swagger-ui-express');
  // Use runtime fetch of the on-disk spec so Swagger UI always displays the latest /api/openapi.json
  app.use('/api/docs/ui', swaggerUi.serve, swaggerUi.setup(undefined, { explorer: true, swaggerOptions: { url: '/api/openapi.json' } }));
  console.log('swagger-ui-express mounted at /api/docs/ui (fetching spec from /api/openapi.json)');
} catch (e) {
  console.warn('swagger-ui-express not available or openapi missing, serving Redoc fallback at /api/docs/ui');
  app.get('/api/docs/ui', (_req, res) => {
    // lightweight Redoc fallback (CDN) — works without local dependencies
    const html = `<!doctype html>
    <html>
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>API Docs (Redoc)</title>
        <style>body{margin:0;padding:0}redoc{display:block;height:100vh}</style>
      </head>
      <body>
        <redoc spec-url="/api/openapi.json"></redoc>
        <script src="https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js"></script>
      </body>
    </html>`;
    res.send(html);
  });
}

// In-memory triage debug store (circular buffer style)
const TRIAGE_STORE_MAX = Number(process.env.TRIAGE_STORE_MAX || 50);
const triageStore: any[] = [];

// Debug triage receiver (development only) — logs incoming triage payloads so you can inspect them
app.post('/triage', upload.single('file'), (req, res) => {
  try {
    // If a file was uploaded, try to parse it as JSON; otherwise fall back to body
    let payload: any = req.body;
    if (req.file && req.file.buffer) {
      try {
        const text = req.file.buffer.toString('utf8');
        // Keep dot-notation keys as-is (1.json style) by parsing into an object
        payload = JSON.parse(text);
      } catch (e) {
        // not JSON — attach raw text and metadata
        payload = { _uploaded_file_text: req.file.buffer.toString('utf8'), _uploaded_file_name: req.file.originalname, _uploaded_file_mimetype: req.file.mimetype, ...req.body };
      }
    }

    // store most recent payloads
    triageStore.push({ receivedAt: Date.now(), payload });
    if (triageStore.length > TRIAGE_STORE_MAX) triageStore.shift();

    // log a compact preview and the full JSON on debug
    console.log('=== TRIAGE DEBUG RECEIVED ===');
    console.log(JSON.stringify(payload, null, 2));
    console.log('=== END TRIAGE DEBUG ===');

    // Run local mock predictor and return model-like response so tests can be end-to-end
    const samplePrediction = {
      prediction: {
        predicted_verdict: 'true_positive',
        confidence: 0.9057955741882324,
        probabilities: {
          false_positive: 0.027794601395726204,
          true_positive: 0.9057955741882324,
          undefined: 0.06640981882810593
        }
      },
      metadata: {
        top_contributing_features: {
          'threat.detection.type': { value: -1.2917195229006553, importance_weight: 0.12923437356948853, contribution_score: 0.16693456336954476 },
          'file.extension': { value: 1.1476380835140088, importance_weight: 0.13603204488754272, contribution_score: 0.15611555529123114 },
          'remediation.status': { value: -1.1685890055328445, importance_weight: 0.12087996304035187, contribution_score: 0.14125899579817178 }
        },
        all_features: {
          'process.name': { value: -0.3526773614545564, importance_weight: 0.11075733602046967, contribution_score: 0.03906160502943494 },
          'file.path': { value: 0.3830278414198296, importance_weight: 0.1066397950053215, contribution_score: 0.04084601049034142 },
          'file.size': { value: 0.8967948710061774, importance_weight: 0.09464701265096664, contribution_score: 0.08487895550144367 }
        }
      },
      model_version: 'local-mock-v1',
      timestamp: new Date().toISOString()
    };

    return res.json({ ok: true, debug: true, received: payload, model: samplePrediction });
  } catch (e) {
    console.error('failed to log triage payload', e);
    return res.status(500).json({ ok: false, error: 'failed to parse triage payload' });
  }
});

// Fetch last N triage payloads (debug)
app.get('/triage/debug', async (req, res) => {
  const n = Math.min(Number(req.query.n || 20), TRIAGE_STORE_MAX);

  const normalizeTo28 = (p: any) => ({
    id: p.id || p.alert_id || p.alpha_id || null,
    alpha_id: p.alpha_id || p.alert_id || null,
    severity_id: p.severity_id ?? null,
    file_verification_type: p.file_verification_type ?? p['file.verification.type'] ?? null,
    file_signature_certificate_status: p.file_signature_certificate_status ?? p['file.signature.certificate.status'] ?? null,
    file_path: p.file_path ?? p['file.path'] ?? null,
    file_name: p.file_name ?? p['file.name'] ?? null,
    file_size: p.file_size ?? p['file.size'] ?? null,
    file_extension: p.file_extension ?? p['file.extension'] ?? null,
    file_extension_type: p.file_extension_type ?? p['file.extension_type'] ?? null,
    originator_process: p.originator_process ?? p['process.name'] ?? null,
    malicious_process_arguments: p.malicious_process_arguments ?? p['process.cmd.args'] ?? null,
    process_user: p.process_user ?? p['actor.process.user.name'] ?? null,
    threat_confidence: p.threat_confidence ?? p['threat.confidence'] ?? null,
    metadata_product_feature_name: p.metadata_product_feature_name ?? p['metadata.product.feature.name'] ?? null,
    device_type: p.device_type ?? p['device.type'] ?? null,
    enrichments_data_positives: p.enrichments_data_positives ?? p['enrichments[1].data.positives'] ?? null,
    enrichments_data_total: p.enrichments_data_total ?? p['enrichments[1].data.total'] ?? null,
    enrichments_data_malicious: p.enrichments_data_malicious ?? p['enrichments[1].data.malicious'] ?? null,
    enrichments_data_suspicious: p.enrichments_data_suspicious ?? p['enrichments[1].data.suspicious'] ?? null,
    enrichments_data_stats_malicious: p.enrichments_data_stats_malicious ?? p['enrichments[1].data.stats.malicious'] ?? null,
    enrichments_data_stats_suspicious: p.enrichments_data_stats_suspicious ?? p['enrichments[1].data.stats.suspicious'] ?? null,
    enrichments_data_stats_undetected: p.enrichments_data_stats_undetected ?? p['enrichments[1].data.stats.undetected'] ?? null,
    enrichments_data_stats_harmless: p.enrichments_data_stats_harmless ?? p['enrichments[1].data.stats.harmless'] ?? null,
    enrichments_data_stats_unsupported: p.enrichments_data_stats_unsupported ?? p['enrichments[1].data.stats.unsupported'] ?? null,
    enrichments_data_stats_timeout: p.enrichments_data_stats_timeout ?? p['enrichments[1].data.stats.timeout'] ?? null,
    enrichments_data_stats_confirmed_timeout: p.enrichments_data_stats_confirmed_timeout ?? p['enrichments[1].data.stats.confirmed-timeout'] ?? p['enrichments[1].data.stats.confirmed_timeout'] ?? null,
    enrichments_data_stats_failure: p.enrichments_data_stats_failure ?? p['enrichments[1].data.stats.failure'] ?? null,
    enrichments_data_scan_time: p.enrichments_data_scan_time ?? p['enrichments[1].data.scan_time'] ?? null
  });

  // If we have stored triage payloads, return them normalized to the 28-field shape
  const stored = triageStore.slice(-n).map((r) => ({ receivedAt: r.receivedAt, payload: normalizeTo28(r.payload || {}) }));
  if (stored.length > 0) return res.json({ count: stored.length, results: stored });

  // Otherwise synthesize from ClickHouse last N rows
  try {
    const limit = n;
    const sql = `SELECT alpha_id, alert_id, file_name, sha256, sha1, file_path, severity_id, threat_name, source_vendor, source_product, event_time FROM soc.edr_alerts_ocsf ORDER BY ingested_at DESC LIMIT ${limit} FORMAT JSON`;

    const fetchFn = (globalThis as any).fetch || (await import('node-fetch')).default;
    const headers: any = { 'Content-Type': 'text/plain' };
    const chUser = process.env.CLICKHOUSE_USER || '';
    const chPass = process.env.CLICKHOUSE_PASSWORD || '';
    if (chUser && chPass) {
      const token = Buffer.from(`${chUser}:${chPass}`).toString('base64');
      headers.Authorization = `Basic ${token}`;
    }

    const resp = await fetchFn(appConfig.clickhouseUrl, { method: 'POST', headers, body: sql });
    if (!resp.ok) {
      const txt = await resp.text().catch(() => '<no body>');
      return res.status(502).json({ error: 'clickhouse fetch failed', status: resp.status, body: txt });
    }

    const bodyText = await resp.text();
    const parsed = JSON.parse(bodyText);
    const rows = parsed.data || parsed;

    const mapped = (rows || []).map((r: any) => ({ receivedAt: Date.now(), payload: normalizeTo28({
      id: r.alert_id || r.alpha_id,
      alpha_id: r.alpha_id,
      severity_id: r.severity_id,
      file_verification_type: null,
      file_signature_certificate_status: null,
      file_path: r.file_path,
      file_name: r.file_name,
      file_size: null,
      file_extension: null,
      file_extension_type: null,
      originator_process: null,
      malicious_process_arguments: null,
      process_user: null,
      threat_confidence: null,
      metadata_product_feature_name: null,
      device_type: null,
      enrichments_data_positives: null,
      enrichments_data_total: null,
      enrichments_data_malicious: null,
      enrichments_data_suspicious: null,
      enrichments_data_stats_malicious: null,
      enrichments_data_stats_suspicious: null,
      enrichments_data_stats_undetected: null,
      enrichments_data_stats_harmless: null,
      enrichments_data_stats_unsupported: null,
      enrichments_data_stats_timeout: null,
      enrichments_data_stats_confirmed_timeout: null,
      enrichments_data_stats_failure: null,
      enrichments_data_scan_time: null
    }) }));

    return res.json({ count: mapped.length, results: mapped });
  } catch (e: any) {
    console.error('triage/debug clickhouse synth failed', e?.message || e);
    return res.status(500).json({ error: 'failed to synthesize triage payloads', message: String(e?.message || e) });
  }
});

// Development mock of the external triage model API (POST /predict)
// Returns a model-like JSON structure so you can point TRIAGE_URL at this
// server during local development and integration testing.
app.post('/predict', (req, res) => {
  try {
    // payload can be inspected if needed: const incoming = req.body;
    const sample = {
      prediction: {
        predicted_verdict: 'true_positive',
        confidence: 0.9057955741882324,
        probabilities: {
          false_positive: 0.027794601395726204,
          true_positive: 0.9057955741882324,
          undefined: 0.06640981882810593
        }
      },
      metadata: {
        top_contributing_features: {
          'threat.detection.type': { value: -1.2917195229006553, importance_weight: 0.12923437356948853, contribution_score: 0.16693456336954476 },
          'file.extension': { value: 1.1476380835140088, importance_weight: 0.13603204488754272, contribution_score: 0.15611555529123114 },
          'remediation.status': { value: -1.1685890055328445, importance_weight: 0.12087996304035187, contribution_score: 0.14125899579817178 },
          'agentMachineType': { value: 1.2322475355073934, importance_weight: 0.08754466474056244, contribution_score: 0.10787669737337907 },
          'actor.process.user.name': { value: -1.0123601335478567, importance_weight: 0.09886893630027771, contribution_score: 0.10009096955668367 }
        },
        all_features: {
          'process.name': { value: -0.3526773614545564, importance_weight: 0.11075733602046967, contribution_score: 0.03906160502943494 },
          'process.cmd.args': { value: 0.0, importance_weight: 0.0, contribution_score: 0.0 },
          'actor.process.user.name': { value: -1.0123601335478567, importance_weight: 0.09886893630027771, contribution_score: 0.10009096955668367 },
          'file.path': { value: 0.3830278414198296, importance_weight: 0.1066397950053215, contribution_score: 0.04084601049034142 },
          'file.size': { value: 0.8967948710061774, importance_weight: 0.09464701265096664, contribution_score: 0.08487895550144367 },
          'file.extension': { value: 1.1476380835140088, importance_weight: 0.13603204488754272, contribution_score: 0.15611555529123114 },
          'file.verification.type': { value: 0.0, importance_weight: 0.0, contribution_score: 0.0 },
          'process.isFileless': { value: 0.0, importance_weight: 0.0, contribution_score: 0.0 },
          'remediation.status': { value: -1.1685890055328445, importance_weight: 0.12087996304035187, contribution_score: 0.14125899579817178 },
          'device.os.type': { value: 0.0, importance_weight: 0.0, contribution_score: 0.0 },
          'device.agents.state': { value: 0.0, importance_weight: 0.0, contribution_score: 0.0 },
          'threat.behavior.observed': { value: 0.0, importance_weight: 0.0, contribution_score: 0.0 },
          'threat.detection.type': { value: -1.2917195229006553, importance_weight: 0.12923437356948853, contribution_score: 0.16693456336954476 },
          'agentMachineType': { value: 1.2322475355073934, importance_weight: 0.08754466474056244, contribution_score: 0.10787669737337907 },
          'file.depth': { value: -0.5471392532315906, importance_weight: 0.11539589613676071, contribution_score: 0.06313762443825745 }
        }
      },
      model_version: 'local-mock-v1',
      timestamp: new Date().toISOString()
    };

    res.json(sample);
  } catch (e) {
    console.error('mock /predict failed', e);
    res.status(500).json({ error: 'mock predict failed' });
  }
});

// Mount application routes
app.use('/api', routes);

app.use(errorHandler);

export default app;
