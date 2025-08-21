import express from 'express';

// Prometheus metrics exporter stub
export function initMetrics() {
  // in dev we don't create a separate server; metrics exposed via route by admin router
  // placeholder: does nothing, real implementation would register metrics collectors
  console.log('Metrics initialized (stub)');
}

export function metricsHandler(req: express.Request, res: express.Response) {
  res.set('Content-Type', 'text/plain');
  res.send('# HELP placeholder_metric A placeholder metric\n# TYPE placeholder_metric counter\nplaceholder_metric 1\n');
}
