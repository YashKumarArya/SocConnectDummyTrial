// Simple triage poster used by normalization flow
async function getFetch() {
  if (typeof fetch !== 'undefined') return (globalThis as any).fetch.bind(globalThis);
  // dynamic import so node-fetch is optional in some environments
  const nf: any = await import('node-fetch');
  return (nf && (nf.default || nf)) as any;
}

export async function postTriage(payload: any): Promise<any | null> {
  try {
    const fetchFn = await getFetch();
    const url = process.env.TRIAGE_URL || 'https://043cebff3dba.ngrok-free.app/triage';

    // Determine file bytes: preferring triage_file_path, then triage_file_content, else attach the payload JSON
    let fileBuffer: Buffer | undefined = undefined;
    if (payload && payload.triage_file_path) {
      try {
        const { readFileSync } = await import('fs');
        fileBuffer = readFileSync(String(payload.triage_file_path));
      } catch (e: any) {
        console.error('postTriage: failed to read triage_file_path', e?.message || e);
      }
    }
    if (fileBuffer === undefined && payload && payload.triage_file_content !== undefined) {
      fileBuffer = typeof payload.triage_file_content === 'string' ? Buffer.from(payload.triage_file_content) : Buffer.from(JSON.stringify(payload.triage_file_content));
    }
    if (fileBuffer === undefined) {
      fileBuffer = Buffer.from(JSON.stringify(payload));
    }

    // Debug: write the file buffer to /tmp for byte-for-byte comparison with a working curl/Postman upload
    try {
      const { writeFileSync } = await import('fs');
      const idForFile = String(payload?.alpha_id || payload?.id || Date.now());
      const outBinPath = `/tmp/triage-out-${idForFile}.bin`;
      const outJsonPath = `/tmp/triage-out-${idForFile}.json`;
      writeFileSync(outBinPath, fileBuffer as Buffer);
      // If buffer contains valid JSON text, also write a .json file for easy inspection
      try {
        const text = (fileBuffer as Buffer).toString('utf8');
        JSON.parse(text);
        writeFileSync(outJsonPath, text);
      } catch (e) {
        // not valid JSON, ignore
      }
      console.log('postTriage debug: wrote fileBuffer to', outBinPath, 'byteLength=', Buffer.byteLength(fileBuffer as Buffer));
    } catch (e: any) {
      console.warn('postTriage debug: could not write debug files', e?.message || e);
    }

    // Always use the 'form-data' package and submit() for reliable multipart streaming
    const FormDataPkg: any = await import('form-data');
    const FormData = FormDataPkg.default || FormDataPkg;
    const fd = new FormData();

    // Append the file part with filename 'file'
    fd.append('file', fileBuffer as Buffer, {
      filename: payload?.triage_file_name || 'file.json',
      contentType: payload?.triage_file_content_type || 'application/json'
    });

    // Optionally include scalar fields
    const includeScalars = process.env.TRIAGE_INCLUDE_SCALARS === '1';
    if (includeScalars) {
      const scalarFields = ['id','alpha_id','file_name','sha256','sha1','file_path','severity_id','threat_name','source_vendor','source_product','event_time'];
      for (const k of scalarFields) {
        const v = (payload as any)[k];
        if (v !== undefined && v !== null) {
          fd.append(k, String(v));
        }
      }
    }

    // Compute headers and Content-Length when possible
    const headers: any = fd.getHeaders ? fd.getHeaders() : { 'Content-Type': 'multipart/form-data' };
    if (typeof (fd as any).getLength === 'function') {
      try {
        const len: any = await new Promise((resolve, reject) => (fd as any).getLength((err: any, length: any) => (err ? reject(err) : resolve(length))));
        if (len) headers['Content-Length'] = String(len);
      } catch (e: any) {
        console.warn('postTriage: could not compute Content-Length for multipart body', e?.message || e);
      }
    }

    // Debug headers and preview
    try {
      console.log('postTriage url=', url, 'headers= (keys only)', Object.keys(headers));
      console.log('postTriage file-preview:', (fileBuffer as Buffer).slice(0, 1024).toString('utf8'));
    } catch (e) { /* ignore */ }

    // Submit using form-data's submit for Node compatibility
    const res: any = await new Promise((resolve, reject) => {
      try {
        (fd as any).submit(url, (err: any, resp: any) => {
          if (err) return reject(err);
          const chunks: any[] = [];
          resp.on('data', (c: any) => chunks.push(c));
          resp.on('end', () => {
            const bodyText = Buffer.concat(chunks).toString('utf8');
            try {
              const parsed = JSON.parse(bodyText);
              resolve({ ok: resp.statusCode >= 200 && resp.statusCode < 300, status: resp.statusCode, text: () => Promise.resolve(bodyText), json: () => Promise.resolve(parsed) });
            } catch (e) {
              resolve({ ok: resp.statusCode >= 200 && resp.statusCode < 300, status: resp.statusCode, text: () => Promise.resolve(bodyText), json: () => Promise.reject(new Error('invalid json')) });
            }
          });
          resp.on('error', (e: any) => reject(e));
        });
      } catch (e) { reject(e); }
    });

    if (!res.ok) {
      const txt = await res.text().catch(() => '<no body>');
      console.error(`postTriage failed ${res.status}: ${txt}`);
      return null;
    }

    try {
      const json = await res.json();
      return json;
    } catch (err: any) {
      console.error('postTriage: failed to parse JSON response', err?.message || err);
      return null;
    }
  } catch (err: any) {
    console.error('postTriage error', err?.message || err);
    return null;
  }
}
