import dotenv from 'dotenv';
dotenv.config();

import http from 'http';
import app from './app';
import { initKafka } from './libs/kafka';
import { queryClickhouse } from './libs/clickhouse';
import { initMetrics } from './observability/metrics';
import { startNormalizeWorker } from './workers/normalize.worker';
import { startMlWorker } from './workers/ml.worker';
import { startFaissWorker } from './workers/faiss.worker';
import { startExportWorker } from './workers/export.worker';

const PORT = Number(process.env.PORT || 3002);

const server = http.createServer(app);

async function bootstrap() {
  try {
    await initKafka();
    await queryClickhouse('SELECT 1');
    initMetrics();

    // start workers (in-process for dev)
    startNormalizeWorker().catch((err) => console.error('normalize worker', err));
    startMlWorker().catch((err) => console.error('ml worker', err));
    startFaissWorker().catch((err) => console.error('faiss worker', err));
    startExportWorker().catch((err) => console.error('export worker', err));

    server.listen(PORT, () => {
      // eslint-disable-next-line no-console
      console.log(`Server listening on port ${PORT}`);
    });
  } catch (err) {
    console.error('Failed to bootstrap services', err);
    process.exit(1);
  }
}

bootstrap();

export default server;
