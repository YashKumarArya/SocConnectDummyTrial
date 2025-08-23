import express from 'express';
import routes from './routes';
import { errorHandler } from './middleware/error';
import { loggerMiddleware } from './observability/logging';
import path from 'path';
import fs from 'fs';

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

// Mount application routes
app.use('/api', routes);

app.use(errorHandler);

export default app;
