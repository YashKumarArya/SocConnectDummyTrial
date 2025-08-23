// Minimal service demo: uploads raw and enriched alerts and lists by alpha_id
// Usage: node security-alert-backend/scripts/minio/minio_service_demo.js

const { uploadRawAlert, uploadEnrichedAlert, listByAlphaId, getObject } = require('./minio_store');

async function demo() {
  const alphaId = `A-${Math.floor(Math.random()*100000)}`;
  console.log('Using alphaId:', alphaId);

  const raw = { source: 'edr', message: 'suspicious', ts: new Date().toISOString(), details: { ip: '1.2.3.4' } };
  const enriched = { ...raw, normalized: { severity: 'high', category: 'malware' }, extra: { tags: ['demo'] } };

  const rawRes = await uploadRawAlert({ alphaId, rawPayload: raw });
  console.log('Uploaded raw:', rawRes);

  const enrichedRes = await uploadEnrichedAlert({ alphaId, enrichedPayload: enriched });
  console.log('Uploaded enriched:', enrichedRes);

  const list = await listByAlphaId({ alphaId });
  console.log('List by alphaId:', list);

  if (list.length) {
    const content = await getObject({ key: list[0].Key });
    console.log('Sample object content:', content.substring(0,200));
  }
}

if (require.main === module) {
  demo().catch(err => {
    console.error('Demo failed:', err.message);
    process.exit(1);
  });
}
