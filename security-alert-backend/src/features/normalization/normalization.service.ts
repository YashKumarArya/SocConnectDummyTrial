import { normalizeHybrid } from '../../common/normalizer.hybrid';
import { normalizationRepo } from './normalization.repo';
import clickhouse from '../../libs/clickhouse/client';
import { postTriage } from '../../libs/triage';
import { fromTriageToWideRow, insertTriageWide } from '../../libs/clickhouse/insert_model_scores';

// In-process dedupe for triage wide inserts to avoid duplicate rows when
// normalize() is called multiple times for the same alert in quick succession.
const triageDedup = new Set<string>();

export const normalizationService = {
  async normalize(id: string, raw: any, sourceType?: string, options = {}) {
    // Removed unused buildTriageJson helper to avoid unused local errors

    // If this alert id has already been normalized and saved, skip reprocessing
    // unless caller explicitly requests a forced re-run via options.force.
    const prior = await normalizationRepo.get(id as string);
    if (prior && !(options as any)?.force) {
      // already normalized — return cached normalized object
      return prior.normalized;
    }

    const normalized = normalizeHybrid(raw, { logUnmappedFields: false }, sourceType);

    // prepare a best-effort original object to populate ClickHouse columns
    const orig = raw || (normalized as any).original || {};

    // derive canonical alpha id for this normalization run and keep it in outer scope
    let alphaId = (orig as any)?.alpha_id || (orig as any)?.alphaId || id;

    try {
      const row = {
        alpha_id: alphaId,
        // existing minimal normalized row for alerts_normalized table
        alert_id: id,
        vendor: (orig as any)?.vendor || null,
        product: (orig as any)?.product || null,
        severity: (normalized as any).event?.severity || (orig as any)?.severity || null,
        category: (normalized as any).event?.type || (orig as any)?.event || null,
        event_action: (normalized as any).event?.action || (orig as any)?.action || null,
        source_ip: (normalized as any).src?.ip || (orig as any)?.source?.ip || (orig as any)?.src_ip || (orig as any)?.src || null,
        dest_ip: (normalized as any).dst?.ip || (orig as any)?.destination?.ip || (orig as any)?.dst_ip || null,
        src_username: (normalized as any).user?.name || null,
        dest_username: null,
        file_name: (normalized as any).file?.name || null,
        file_hash: (normalized as any).file?.hash || null,
        url: (normalized as any).event?.url || (orig as any)?.url || null,
        email_from: (normalized as any).email?.sender || (orig as any)?.email?.from || null,
        email_to: (normalized as any).email?.recipient || (orig as any)?.email?.to || null,
        email_subject: (normalized as any).email?.subject || (orig as any)?.email?.subject || null,
        timestamp: (normalized as any).timestamp || (orig as any)?.timestamp || new Date().toISOString(),
        normalized: normalized,
        embedding_id: null
      };

      // Insert normalized row which maps to `soc.edr_alerts_ocsf` columns.
      // insertNormalized is idempotent by alpha_id/version in ClickHouse.
      await clickhouse.insertNormalized([row]);

      // Save normalized only after successful persistence to ClickHouse
      try {
        await normalizationRepo.save(id, normalized);
      } catch (e) {
        // non-fatal: log but continue
        console.warn('normalizationRepo.save failed', e);
      }

      // Post triage payload (compact) to configured triage endpoint (best-effort)
      try {
        // Build a flattened dot-notation payload for the ML triage model.
        // Prefer orig if it already uses dotted keys (like 1.json), otherwise flatten the nested object.
        let flatForTriage: Record<string, any> = {};
        try {
          const normMod: any = await import('../../common/normalizer.hybrid');
          const flattenFn = normMod.flatten as (obj: any) => Record<string, any>;
          const looksFlattened = orig && typeof orig === 'object' && Object.keys(orig).some((k) => String(k).includes('.') || String(k).includes('['));
          flatForTriage = looksFlattened ? (orig as Record<string, any>) : (flattenFn ? flattenFn(orig || {}) : (orig as any) || {});
        } catch (e) {
          flatForTriage = (orig as any) || {};
        }

        // Derive scalar snake_case fields from flattened map to include as form fields
        let snakeScalars: Record<string, any> = {};
        try {
          const fm: any = await import('../../libs/flatten_mapper');
          const mapFlatToSnake = fm.mapFlatToSnake as (f: Record<string, any>) => Record<string, any>;
          snakeScalars = mapFlatToSnake(flatForTriage || {});
        } catch (e) {
          snakeScalars = {};
        }

        const triagePayload = {
          id: (row as any).alert_id || id,
          alpha_id: (row as any).alpha_id,
          // attach the flattened dot-notation object as the file content (ML expects flattened keys)
          triage_file_content: flatForTriage,
          // prefer original file name when available so uploaded filename reflects the source
          triage_file_name: ((orig as any) && ((orig as any)['file.name'] || ((orig as any).file && (orig as any).file.name))) || `${(row as any).alpha_id}.json`,
          triage_file_content_type: 'application/json',
          file: {
            name: snakeScalars['file_name'] ?? (normalized as any).file?.name ?? (row as any).file_name ?? null,
            path: snakeScalars['file_path'] ?? (normalized as any).file?.path ?? (orig as any)?.file_path ?? null,
            hashes: { sha256: snakeScalars['sha256'] ?? (normalized as any).file?.hash?.sha256 ?? (orig as any)?.sha256 ?? null, sha1: snakeScalars['sha1'] ?? (normalized as any).file?.hash?.sha1 ?? (orig as any)?.sha1 ?? null }
          },
          file_name: snakeScalars['file_name'] ?? (normalized as any).file?.name ?? (row as any).file_name ?? null,
          sha256: snakeScalars['sha256'] ?? (normalized as any).file?.hash?.sha256 ?? (orig as any)?.sha256 ?? null,
          sha1: snakeScalars['sha1'] ?? (normalized as any).file?.hash?.sha1 ?? (orig as any)?.sha1 ?? null,
          file_path: snakeScalars['file_path'] ?? (normalized as any).file?.path ?? (orig as any)?.file_path ?? null,
          severity_id: snakeScalars['severity_id'] ?? (normalized as any).threat?.severity ?? (orig as any)?.severity_id ?? null,
          threat_name: snakeScalars['threat_name'] ?? (normalized as any).threat?.name ?? (orig as any)?.threat_name ?? null,
          source_vendor: snakeScalars['source_vendor'] ?? (row as any).vendor ?? null,
          source_product: snakeScalars['source_product'] ?? (row as any).product ?? null,
          event_time: snakeScalars['event_time'] ?? (normalized as any).timestamp ?? (row as any).timestamp ?? null
        };

        // Helpers to send create-graph with the same multipart/form-data file as triage
        async function buildGraphFormDataFromTriage(triage: any) {
          const FormDataPkg: any = await import('form-data');
          const FormData = FormDataPkg.default || FormDataPkg;
          const fd = new FormData();
          let fileBuffer: Buffer;
          const val = (triage as any)?.triage_file_content;
          if (Buffer.isBuffer(val)) {
            fileBuffer = val as Buffer;
          } else if (typeof val === 'string') {
            fileBuffer = Buffer.from(val);
          } else if (val && typeof val === 'object') {
            fileBuffer = Buffer.from(JSON.stringify(val, null, 2));
          } else {
            fileBuffer = Buffer.from(JSON.stringify(triage || {}));
          }
          let fileNameToUse = String((triage as any)?.triage_file_name || `${String((triage as any)?.alpha_id || id)}.json`);
          try {
            if (!fileNameToUse.toLowerCase().endsWith('.json')) {
              fileNameToUse = fileNameToUse.replace(/\.[^.]+$/, '') + '.json';
            }
          } catch {}
          fd.append('file', fileBuffer, {
            filename: fileNameToUse,
            contentType: (triage as any)?.triage_file_content_type || 'application/json'
          });
          const includeScalars = process.env.TRIAGE_INCLUDE_SCALARS === '1';
          if (includeScalars) {
            const scalarFields = ['id','alpha_id','file_name','sha256','sha1','file_path','severity_id','threat_name','source_vendor','source_product','event_time'];
            for (const k of scalarFields) {
              const v = (triage as any)[k];
              if (v !== undefined && v !== null) (fd as any).append(k, String(v));
            }
          }
          return fd;
        }
        async function submitFormData(url: string, fd: any, timeoutMs: number) {
          return await new Promise((resolve, reject) => {
            let timedOut = false;
            let req: any = null;
            const onError = (err: any) => { if (timedOut) return; reject(err); };
            try {
              req = (fd as any).submit(url, (err: any, resp: any) => {
                if (err) return onError(err);
                const chunks: any[] = [];
                resp.on('data', (c: any) => chunks.push(c));
                resp.on('end', async () => {
                  if (timedOut) return;
                  const bodyText = Buffer.concat(chunks).toString('utf8');
                  try {
                    const parsed = JSON.parse(bodyText);
                    resolve({ ok: resp.statusCode >= 200 && resp.statusCode < 300, status: resp.statusCode, json: parsed, bodyText });
                  } catch {
                    resolve({ ok: resp.statusCode >= 200 && resp.statusCode < 300, status: resp.statusCode, json: null, bodyText });
                  }
                });
                resp.on('error', onError);
              });
            } catch (e) {
              return reject(e);
            }
            const to = setTimeout(() => {
              timedOut = true;
              try { if (req && typeof req.abort === 'function') req.abort(); } catch {}
              reject(new Error(`create-graph request timeout after ${timeoutMs}ms`));
            }, timeoutMs);
          });
        }

        console.log('triagePayload:', JSON.stringify(triagePayload, null, 2));

        const triageResp = await postTriage(triagePayload);
        console.log('triageResp:', JSON.stringify(triageResp, null, 2));
        if (triageResp) {
          try {
            const key = `${(row as any).alert_id || ''}::${(row as any).alpha_id || ''}`;
            // Persistent dedupe: try Redis-backed set-if-not-exists; falls back to in-process Set
            let acquired = false;
            try {
              const { setIfNotExists } = await import('../../libs/redis');
              acquired = await setIfNotExists(`triage_dedupe:${key}`, 24 * 60 * 60 * 1000);
            } catch (e) {
              // If redis import fails, fall back to in-memory dedupe
              acquired = !triageDedup.has(key);
            }
            if (acquired) {
              triageDedup.add(key);
              let wide = fromTriageToWideRow(String((row as any).alert_id || ''), String((row as any).alpha_id || ''), triageResp as any, { v4_fields_present: undefined });
              console.log('triageWideRow:', JSON.stringify(wide, null, 2));

              // Evaluate supervisor condition and log decision
              const ruleScoreRaw = (triageResp as any)?.prediction?.risk_score;
              const ruleScore = Number(ruleScoreRaw);
              const shouldCallSupervisor = Number.isFinite(ruleScore) && ruleScore >= 0 && ruleScore <= 79;
              const verdictRaw = (triageResp as any)?.prediction?.predicted_verdict;
              const vnorm = String(verdictRaw || '').trim().toLowerCase().replace(/\s+|_/g, ' ');
              const isTruePositive = vnorm.includes('true positive') || vnorm === 'tp' || vnorm.includes('escalate') || vnorm.includes('malicious');
              console.log('supervisorCheck', { key, acquired: true, ruleScore, verdict: verdictRaw, isTruePositive, source: 'prediction.risk_score', shouldCallSupervisor });

              // Early create-graph when triage is 0–79 and true positive, then continue supervisor flow
              let graphAlreadyPosted = false;
              if (shouldCallSupervisor && isTruePositive) {
                try {
                  const defaultGraph = 'https://91baa41b9d55.ngrok-free.app/create-graph';
                  let graphUrl = process.env.GRAPH_URL || process.env.CREATE_GRAPH_URL || defaultGraph;
                  graphUrl = graphUrl.replace(/\{alert_id\}/g, '');
                  const graphTimeout = Number(process.env.GRAPH_TIMEOUT_MS || process.env.CREATE_GRAPH_TIMEOUT_MS || '60000');
                  const fd = await buildGraphFormDataFromTriage(triagePayload);
                  console.log('createGraphCall(early)', { url: graphUrl, verdict: verdictRaw, timeoutMs: graphTimeout });
                  const res: any = await submitFormData(graphUrl, fd, graphTimeout);
                  console.log('createGraphResp(early)', { status: res.status, body: res.bodyText?.slice(0, 500) });
                  graphAlreadyPosted = true;
                } catch (e: any) {
                  console.warn('early create-graph failed', e?.message || e);
                }
              }

              // If triage indicates a low-to-medium rule risk (0-79) call external supervisor agent
              try {
                if (shouldCallSupervisor) {
                  let supervisorResp: any = null; // visible for post-call gating
                  try {
                    const fetchFn = (globalThis as any).fetch || (await import('node-fetch')).default;
                    const rawSupervisor = process.env.SUPERVISOR_URL || 'https://91baa41b9d55.ngrok-free.app/supervisor-agent';
                    let supervisorUrl = rawSupervisor;
                    try {
                      const u = new URL(rawSupervisor);
                      if (!u.searchParams.has('source')) u.searchParams.set('source', 'edr');
                      supervisorUrl = u.toString();
                    } catch {
                      supervisorUrl = rawSupervisor + (rawSupervisor.includes('?') ? '&' : '?') + 'source=edr';
                    }
                    const timeoutMs = Number(process.env.SUPERVISOR_TIMEOUT_MS || '8000');
                    const controller = new AbortController();
                    const to = setTimeout(() => controller.abort(), timeoutMs);
                    try {
                      // Supervisor expects nested JSON (or { alert_json: {...} }). Convert dotted -> nested.
                      const dotted = (triagePayload as any)?.triage_file_content ?? flatForTriage ?? {};
                      let nested = dotted;
                      try {
                        const normMod: any = await import('../../common/normalizer.hybrid');
                        if (typeof normMod.unflattenDotmap === 'function') nested = normMod.unflattenDotmap(dotted);
                      } catch {}
                      const outgoing = { alert_json: nested };
                      const body = JSON.stringify(outgoing);
                      console.log('supervisorCall', { url: supervisorUrl, wrapper: 'alert_json', keys: Object.keys(dotted).slice(0, 5), timeoutMs });
                      const supRes = await fetchFn(supervisorUrl, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' }, body, signal: controller.signal });
                      try {
                        supervisorResp = await supRes.json();
                      } catch (e) {
                        supervisorResp = { status: (supRes as any).status, text: await (supRes as any).text().catch(() => '') };
                      }
                    } finally {
                      clearTimeout(to);
                    }

                    // Do not merge supervisor response into wide.meta for now
                    try {
                      console.log('supervisorResp received (not persisted)', typeof supervisorResp === 'string' ? supervisorResp : JSON.stringify(supervisorResp));
                    } catch {}

                    // Persist supervisor-derived fields into wide row
                    try {
                      const meta = (supervisorResp && (supervisorResp.metadata || supervisorResp.meta || (supervisorResp as any).data?.metadata)) || {};
                      const agentResults = Array.isArray((meta as any).agent_results) ? (meta as any).agent_results : (Array.isArray((meta as any).agents) ? (meta as any).agents : []);

                      const findAgent = (name: string) => agentResults.find((a: any) => String(a?.agent || a?.name || '').toUpperCase().includes(name));
                      const agGnn = findAgent('GNN');
                      const agEdr = findAgent('EDR');

                      if (agGnn) {
                        (wide as any).gnn_confidence = Number(agGnn.confidence ?? agGnn.score ?? 0) || 0;
                        (wide as any).gnn_verdict = String(agGnn.verdict ?? agGnn.decision ?? '');
                        (wide as any).gnn_meta = JSON.stringify(agGnn);
                      }
                      if (agEdr) {
                        (wide as any).edr_score = Number(agEdr.score ?? agEdr.confidence ?? 0) || 0;
                        (wide as any).edr_verdict = String(agEdr.verdict ?? agEdr.decision ?? '');
                        (wide as any).edr_meta = JSON.stringify(agEdr);
                      }

                      const supAnalysis = (meta as any).supervisor_analysis || (meta as any).analysis || {};
                      if (supAnalysis || (supervisorResp as any)?.prediction) {
                        const supScore = (supAnalysis && ((supAnalysis as any).consolidated_score ?? (supAnalysis as any).score))
                          ?? ((supervisorResp as any)?.prediction?.consolidated_score);
                        const supVerdict = (supAnalysis && ((supAnalysis as any).final_decision ?? (supAnalysis as any).verdict))
                          ?? ((supervisorResp as any)?.prediction?.predicted_verdict);
                        (wide as any).supervisor_score = Number(supScore ?? 0) || 0;
                        (wide as any).supervisor_verdict = String(supVerdict ?? '');
                        (wide as any).supervisor_meta = JSON.stringify(supervisorResp ?? meta ?? {});
                        if (Array.isArray((meta as any).actionable_messages) && !(wide as any).summary) {
                          (wide as any).summary = (meta as any).actionable_messages.join(' | ');
                        }
                      }

                      console.log('wide updated with supervisor fields:', JSON.stringify(wide));
                    } catch (e) {
                      console.warn('failed to map supervisor response into wide', (e as any)?.message || e);
                    }

                    // After supervisor has done its work, conditionally call create-graph/summary or investigate based on supervisor confidence
                    try {
                      const supConfRaw = Number((supervisorResp as any)?.prediction?.confidence);
                      const supConfPct = Number.isFinite(supConfRaw) ? (supConfRaw <= 1 ? supConfRaw * 100 : supConfRaw) : NaN;
                      const highSupervisorConfidence = Number.isFinite(supConfPct) && supConfPct >= 80 && supConfPct <= 100;
                      const lowToMediumSupervisorConfidence = Number.isFinite(supConfPct) && supConfPct >= 0 && supConfPct <= 79;
                      console.log('supervisorConfidenceCheck', { supConfRaw, supConfPct, highSupervisorConfidence, lowToMediumSupervisorConfidence });

                      const alertIdForNext = String((row as any).alert_id || id || (triagePayload as any)?.id || '');

                      if (highSupervisorConfidence && !graphAlreadyPosted) {
                        const defaultGraph = 'https://91baa41b9d55.ngrok-free.app/create-graph';
                        let graphUrl = process.env.GRAPH_URL || process.env.CREATE_GRAPH_URL || defaultGraph;
                        graphUrl = graphUrl.replace(/\{alert_id\}/g, '');
                        const graphTimeout = Number(process.env.GRAPH_TIMEOUT_MS || process.env.CREATE_GRAPH_TIMEOUT_MS || '60000');
                        try {
                          const fd = await buildGraphFormDataFromTriage(triagePayload);
                          console.log('createGraphCall', { url: graphUrl, mode: 'multipart.form-data.file', timeoutMs: graphTimeout });
                          const res: any = await submitFormData(graphUrl, fd, graphTimeout);
                          console.log('createGraphResp', { status: res.status, body: res.bodyText?.slice(0, 500) });
                          graphAlreadyPosted = true;
                        } catch (e: any) {
                          console.warn('createGraph submit failed', e?.message || e);
                        }
                      }

                      // Summary call (only in high confidence branch)
                      if (highSupervisorConfidence) {
                        const defaultSummary = 'https://ec2f9a613e8c.ngrok-free.app/summary/{alert_id}';
                        let sumUrlTmpl = process.env.SUMMARY_URL || defaultSummary;
                        if (!sumUrlTmpl.includes('{alert_id}')) {
                          sumUrlTmpl = sumUrlTmpl.replace(/\/+$/, '') + '/{alert_id}';
                        }
                        const sumUrl = sumUrlTmpl.replace('{alert_id}', encodeURIComponent(alertIdForNext));
                        const sumTimeout = Number(process.env.SUMMARY_TIMEOUT_MS || '60000');
                        const controller = new AbortController();
                        const to = setTimeout(() => controller.abort(), sumTimeout);
                        try {
                          console.log('summaryCall', { url: sumUrl, timeoutMs: sumTimeout });
                          const fetchAny = (globalThis as any).fetch || (await import('node-fetch')).default;
                          const resp = await fetchAny(sumUrl, { method: 'POST', headers: { 'Accept': 'application/json' }, signal: controller.signal });
                          let out: any = null; try { out = await resp.json(); } catch { out = await resp.text().catch(() => ''); }
                          const summaryText = typeof out === 'string' ? out : (out?.summary ?? out?.data?.summary ?? out?.result?.summary ?? '');
                          if (summaryText) {
                            (wide as any).summary = String(summaryText);
                          }
                          console.log('summaryResp', { status: (resp as any).status, body: typeof out === 'string' ? out : JSON.stringify(out) });
                        } catch (e: any) {
                          console.warn('summaryCall failed', e?.name === 'AbortError' ? `timeout after ${sumTimeout}ms` : (e?.message || e));
                        } finally { clearTimeout(to); }
                      }

                      if (lowToMediumSupervisorConfidence && !graphAlreadyPosted) {
                        const defaultGraph = 'https://91baa41b9d55.ngrok-free.app/create-graph';
                        let graphUrl = process.env.GRAPH_URL || process.env.CREATE_GRAPH_URL || defaultGraph;
                        graphUrl = graphUrl.replace(/\{alert_id\}/g, '');
                        const graphTimeout = Number(process.env.GRAPH_TIMEOUT_MS || process.env.CREATE_GRAPH_TIMEOUT_MS || '60000');
                        try {
                          const fd = await buildGraphFormDataFromTriage(triagePayload);
                          console.log('createGraphCall(lowConf)', { url: graphUrl, mode: 'multipart.form-data.file', timeoutMs: graphTimeout });
                          const res: any = await submitFormData(graphUrl, fd, graphTimeout);
                          console.log('createGraphResp(lowConf)', { status: res.status, body: res.bodyText?.slice(0, 500) });
                          graphAlreadyPosted = true;
                        } catch (e: any) {
                          console.warn('createGraph submit failed(lowConf)', e?.message || e);
                        }
                      }

                      // Investigate call (only in low/medium branch)
                      if (lowToMediumSupervisorConfidence) {
                        const defaultInvestigate = 'https://ec2f9a613e8c.ngrok-free.app/investigate-agentic/{alert_id}';
                        let invUrlTmpl = process.env.INVESTIGATE_AGENTIC_URL || defaultInvestigate;
                        if (!invUrlTmpl.includes('{alert_id}')) {
                          invUrlTmpl = invUrlTmpl.replace(/\/+$/, '') + '/{alert_id}';
                        }
                        const invUrl = invUrlTmpl.replace('{alert_id}', encodeURIComponent(alertIdForNext));
                        const invTimeout = Number(process.env.INVESTIGATE_AGENTIC_TIMEOUT_MS || '180000');
                        const controller = new AbortController();
                        const to = setTimeout(() => controller.abort(), invTimeout);
                        try {
                          console.log('investigateAgenticCall', { url: invUrl, timeoutMs: invTimeout });
                          const fetchAny = (globalThis as any).fetch || (await import('node-fetch')).default;
                          const resp = await fetchAny(invUrl, { method: 'POST', headers: { 'Accept': 'application/json' }, signal: controller.signal });
                          let out: any = null; try { out = await resp.json(); } catch { out = await resp.text().catch(() => ''); }
                          try {
                            const existing = (wide as any).supervisor_meta ? JSON.parse((wide as any).supervisor_meta) : {};
                            (existing as any).investigate_agentic = out;
                            (wide as any).supervisor_meta = JSON.stringify(existing);
                          } catch {
                            (wide as any).supervisor_meta = JSON.stringify({ investigate_agentic: out });
                          }
                          console.log('investigateAgenticResp', { status: (resp as any).status, body: typeof out === 'string' ? out : JSON.stringify(out) });
                        } catch (e: any) {
                          console.warn('investigateAgenticCall failed', e?.name === 'AbortError' ? `timeout after ${invTimeout}ms` : (e?.message || e));
                        } finally { clearTimeout(to); }
                      }
                    } catch (e: any) {
                      console.warn('post-supervisor gating for graph/summary/investigate failed', (e as any)?.message || e);
                    }
                  } catch (e: any) {
                    console.warn('supervisor call failed', (e as any)?.message || e);
                  }
                } else {
                  console.log('supervisor skipped due to ruleScore outside 0-79', { ruleScore });
                }
              } catch (e) {
                console.warn('error evaluating ruleScore or calling supervisor', e);
              }

              await insertTriageWide([wide]);
            } else {
              console.log('skip duplicate triage wide insert for', key);
            }
          } catch (e: any) {
            console.error('insertTriageWide failed', (e as any)?.message || e);
          }
        }
      } catch (e: any) {
        console.error('postTriage failed', (e as any)?.message || e);
      }

    } catch (err: any) {
      console.error('clickhouse persist failed, writing to dlq', err?.message || err);
      try {
        await clickhouse.insertDLQ([
          {
            alpha_id: alphaId,
            alert_id: id,
            vendor: (raw as any)?.vendor || null,
            product: (raw as any)?.product || null,
            normalized: typeof normalized === 'string' ? normalized : JSON.stringify(normalized || {}),
            error_message: String(err?.message || err),
            attempts: 1,
            last_error_at: new Date().toISOString()
          }
        ], String(err?.message || err));
      } catch (e) {
        console.error('failed to write to clickhouse dlq', e);
      }
    }

    return normalized;
  },
  async get(id: string) {
    return normalizationRepo.get(id);
  }
};