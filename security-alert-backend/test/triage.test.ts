import http from 'http';
import assert from 'assert';
import { postTriage } from '../src/libs/triage';

async function run() {
  // start a simple HTTP server that fails first two attempts then succeeds
  let callCount = 0;
  const server = http.createServer((req, res) => {
    callCount++;
    let bufs: Buffer[] = [];
    req.on('data', (c) => bufs.push(c));
    req.on('end', () => {
      if (callCount < 3) {
        // respond with 500 to force retry
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        return res.end('temporary error');
      }
      // successful response
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ prediction: { predicted_verdict: 'true_positive', risk_score: 0.9, confidence: 0.8 }, model_version: 'test-mock', timestamp: new Date().toISOString() }));
    });
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  // @ts-ignore
  const port = (server.address() as any).port;
  const url = `http://127.0.0.1:${port}/triage`;
  process.env.TRIAGE_URL = url;
  process.env.TRIAGE_MAX_RETRIES = '4';
  console.log('Started mock triage at', url, 'expecting eventual success');

  const payload = {
    triage_file_content: { hello: 'world', ts: Date.now() },
    triage_file_name: 'payload.json',
    triage_file_content_type: 'application/json'
  };

  try {
    const resp = await postTriage(payload);
    console.log('postTriage returned:', resp);
    assert(resp && resp.prediction && typeof resp.prediction.risk_score === 'number');
    console.log('TEST PASSED: triage client returned expected structure after retries');
  } catch (e) {
    console.error('TEST FAILED', e);
    process.exitCode = 1;
  } finally {
    server.close();
  }
}

if (require.main === module) {
  run().catch((e) => { console.error(e); process.exit(1); });
}
