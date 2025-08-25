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
    // helper: build a 1.json-like flattened payload for triage from either the original raw or the v4 row
    function buildTriageJson(origObj: any, normalizedObj: any) {
      // Return the raw/original object when it looks like the 1.json sample so ML receives the complete alert
      if (!origObj) origObj = {};
      const looksLikeSample = typeof origObj === 'object' && (origObj['file.name'] || origObj.file || orig.id);
      if (looksLikeSample) return (typeof origObj === 'string') ? (() => {
        try { return JSON.parse(origObj); } catch (e) { return { data: origObj }; }
      })() : origObj;

      // If original didn't look like the raw sample, fall back to the normalized nested OCSF output when available
      if (normalizedObj && typeof normalizedObj === 'object') return normalizedObj;

      return origObj || {};
    }

    // If this alert id has already been normalized and saved, skip reprocessing
    // unless caller explicitly requests a forced re-run via options.force.
    const prior = await normalizationRepo.get(id as string);
    if (prior && !(options as any)?.force) {
      // already normalized — return cached normalized object
      return prior.normalized;
    }

    const normalized = normalizeHybrid(raw, { logUnmappedFields: false }, sourceType);

    // prepare a best-effort original object to populate ClickHouse columns
    const orig = raw || normalized.original || {};

    // derive canonical alpha id for this normalization run and keep it in outer scope
    let alphaId = orig?.alpha_id || orig?.alphaId || id;

    try {
      const row = {
        alpha_id: alphaId,
        // existing minimal normalized row for alerts_normalized table
        alert_id: id,
        vendor: orig?.vendor || null,
        product: orig?.product || null,
        severity: (normalized as any).event?.severity || orig?.severity || null,
        category: (normalized as any).event?.type || orig?.event || null,
        event_action: (normalized as any).event?.action || orig?.action || null,
        source_ip: (normalized as any).src?.ip || orig?.source?.ip || orig?.src_ip || orig?.src || null,
        dest_ip: (normalized as any).dst?.ip || orig?.destination?.ip || orig?.dst_ip || null,
        src_username: (normalized as any).user?.name || null,
        dest_username: null,
        file_name: (normalized as any).file?.name || null,
        file_hash: (normalized as any).file?.hash || null,
        url: (normalized as any).event?.url || orig?.url || null,
        email_from: (normalized as any).email?.sender || orig?.email?.from || null,
        email_to: (normalized as any).email?.recipient || orig?.email?.to || null,
        email_subject: (normalized as any).email?.subject || orig?.email?.subject || null,
        timestamp: (normalized as any).timestamp || orig?.timestamp || new Date().toISOString(),
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
          flatForTriage = looksFlattened ? (orig as Record<string, any>) : (flattenFn ? flattenFn(orig || {}) : orig || {});
        } catch (e) {
          flatForTriage = orig || {};
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
          id: row.alert_id || id,
          alpha_id: row.alpha_id,
          // attach the flattened dot-notation object as the file content (ML expects flattened keys)
          triage_file_content: flatForTriage,
          // prefer original file name when available so uploaded filename reflects the source
          triage_file_name: (orig && (orig['file.name'] || (orig.file && orig.file.name))) || `${row.alpha_id}.json`,
          triage_file_content_type: 'application/json',
          file: {
            name: snakeScalars['file_name'] ?? (normalized as any).file?.name ?? row.file_name ?? null,
            path: snakeScalars['file_path'] ?? (normalized as any).file?.path ?? orig?.file_path ?? null,
            hashes: { sha256: snakeScalars['sha256'] ?? (normalized as any).file?.hash?.sha256 ?? orig?.sha256 ?? null, sha1: snakeScalars['sha1'] ?? (normalized as any).file?.hash?.sha1 ?? orig?.sha1 ?? null }
          },
          file_name: snakeScalars['file_name'] ?? (normalized as any).file?.name ?? row.file_name ?? null,
          sha256: snakeScalars['sha256'] ?? (normalized as any).file?.hash?.sha256 ?? orig?.sha256 ?? null,
          sha1: snakeScalars['sha1'] ?? (normalized as any).file?.hash?.sha1 ?? orig?.sha1 ?? null,
          file_path: snakeScalars['file_path'] ?? (normalized as any).file?.path ?? orig?.file_path ?? null,
          severity_id: snakeScalars['severity_id'] ?? (normalized as any).threat?.severity ?? orig?.severity_id ?? null,
          threat_name: snakeScalars['threat_name'] ?? (normalized as any).threat?.name ?? orig?.threat_name ?? null,
          source_vendor: snakeScalars['source_vendor'] ?? row.vendor ?? null,
          source_product: snakeScalars['source_product'] ?? row.product ?? null,
          event_time: snakeScalars['event_time'] ?? (normalized as any).timestamp ?? row.timestamp ?? null
        };

        console.log('triagePayload:', JSON.stringify(triagePayload, null, 2));

        const triageResp = await postTriage(triagePayload);
        console.log('triageResp:', JSON.stringify(triageResp, null, 2));
        if (triageResp) {
          try {
            const key = `${row.alert_id || ''}::${row.alpha_id || ''}`;
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
               const wide = fromTriageToWideRow(String(row.alert_id || ''), String(row.alpha_id || ''), triageResp as any, { v4_fields_present: undefined });
               console.log('triageWideRow:', JSON.stringify(wide, null, 2));

               // Evaluate supervisor condition and log decision
               const ruleScoreRaw = (triageResp as any)?.prediction?.risk_score;
               const ruleScore = Number(ruleScoreRaw);
               const shouldCallSupervisor = Number.isFinite(ruleScore) && ruleScore >= 0 && ruleScore <= 79;
               console.log('supervisorCheck', { key, acquired: true, ruleScore, source: 'prediction.risk_score', shouldCallSupervisor });

               // If triage indicates a low-to-medium rule risk (0-79) call external supervisor agent
               try {
                 if (shouldCallSupervisor) {
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
                     let supervisorResp: any = null;
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
                       console.log('supervisorCall', { url: supervisorUrl, wrapper: 'alert_json', keys: Object.keys(dotted).slice(0,5), timeoutMs });
                       const supRes = await fetchFn(supervisorUrl, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' }, body, signal: controller.signal });
                       try {
                         supervisorResp = await supRes.json();
                       } catch (e) {
                         supervisorResp = { status: supRes.status, text: await supRes.text().catch(() => '') };
                       }
                     } finally {
                       clearTimeout(to);
                     }

                     // Do not merge supervisor response into wide.meta for now
                     try {
                       // intentionally skipping persistence of supervisorResp
                       console.log('supervisorResp received (not persisted)', typeof supervisorResp === 'string' ? supervisorResp : JSON.stringify(supervisorResp));
                     } catch (e) {
                       // ignore logging issues
                     }
                   } catch (e: any) {
                     console.warn('supervisor call failed', e?.message || e);
                   }

                   // After supervisor has done its work, call create-graph with the same triage payload
                   try {
                     const createGraphUrl = process.env.CREATE_GRAPH_URL || 'https://91baa41b9d55.ngrok-free.app/create-graph';
                     const createGraphTimeout = Number(process.env.CREATE_GRAPH_TIMEOUT_MS || '30000');

                     // Build dotted payload and pretty JSON bytes (same as triage)
                     const dotted = (triagePayload as any)?.triage_file_content ?? flatForTriage ?? {};
                     const prettyJson = JSON.stringify(dotted, null, 2);
                     let fileNameToUse = String(triagePayload?.triage_file_name || `${String(row.alpha_id || 'alert')}.json`);
                     try { if (!fileNameToUse.toLowerCase().endsWith('.json')) fileNameToUse = fileNameToUse.replace(/\.[^.]+$/, '') + '.json'; } catch {}

                     const FormDataMod: any = await import('form-data');
                     const FormDataCtor = (FormDataMod && (FormDataMod.default || FormDataMod));
                     const fd = new FormDataCtor();
                     fd.append('file', Buffer.from(prettyJson), { filename: fileNameToUse, contentType: 'application/json' });

                     if (process.env.TRIAGE_INCLUDE_SCALARS === '1') {
                       const scalarFields = ['id','alpha_id','file_name','sha256','sha1','file_path','severity_id','threat_name','source_vendor','source_product','event_time'];
                       for (const k of scalarFields) {
                         const v = (triagePayload as any)[k];
                         if (v !== undefined && v !== null) fd.append(k, String(v));
                       }
                     }

                     console.log('createGraphCall', { url: createGraphUrl, mode: 'multipart.submit.like.triage', timeoutMs: createGraphTimeout });

                     async function submitMultipart(timeoutMs: number): Promise<{ ok: boolean; status: number; bodyText: string }> {
                         return await new Promise((resolve, reject) => {
                           let timedOut = false;
                           const req: any = (fd as any).submit(createGraphUrl, (err: any, resp: any) => {
                             if (timedOut) return;
                             if (err) return reject(err);
                             const chunks: any[] = [];
                             resp.on('data', (c: any) => chunks.push(c));
                             resp.on('end', () => {
                               const bodyText = Buffer.concat(chunks).toString('utf8');
                               resolve({ ok: resp.statusCode >= 200 && resp.statusCode < 300, status: resp.statusCode, bodyText });
                             });
                             resp.on('error', reject);
                           });
                           setTimeout(() => { timedOut = true; try { req && req.abort && req.abort(); } catch {} reject(new Error('create-graph timeout')); }, timeoutMs);
                         });
                       }

                       let cgRes1: any = null;
                       try {
                         cgRes1 = await submitMultipart(createGraphTimeout);
                       } catch (e: any) {
                         console.warn('createGraph multipart submit error', e?.message || e);
                       }

                       if (!cgRes1 || !cgRes1.ok) {
                         const body1 = cgRes1 ? cgRes1.bodyText : '';
                         if (cgRes1) console.warn('createGraph attempt1 failed', { status: cgRes1.status, body: String(body1).slice(0,200) });
                         // Fallback 1: raw dotted JSON
                         try {
                           const localFetch = (globalThis as any).fetch || (await import('node-fetch')).default;
                           console.log('createGraphCall', { url: createGraphUrl, mode: 'json.dotted', timeoutMs: createGraphTimeout });
                           const r2 = await localFetch(createGraphUrl, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' }, body: prettyJson });
                           let out2: any = null; try { out2 = await r2.json(); } catch { out2 = await r2.text().catch(() => ''); }
                           console.log('createGraphResp', { status: r2.status, body: typeof out2 === 'string' ? out2 : JSON.stringify(out2) });
                         } catch (e: any) {
                           console.warn('createGraph raw json fallback failed', e?.message || e);
                         }
                       } else {
                         console.log('createGraphResp', { status: cgRes1.status, body: String(cgRes1.bodyText).slice(0,200) });
                       }
                     } catch (e: any) {
                       console.warn('create-graph call failed', e?.message || e);
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
             console.error('insertTriageWide failed', e?.message || e);
           }
         }
       } catch (e: any) {
         console.error('postTriage failed', e?.message || e);
       }

    } catch (err: any) {
      console.error('clickhouse persist failed, writing to dlq', err?.message || err);
      try {
        await clickhouse.insertDLQ([
          {
            alpha_id: alphaId,
            alert_id: id,
            vendor: raw?.vendor || null,
            product: raw?.product || null,
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
