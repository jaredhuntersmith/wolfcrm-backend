import { randomUUID } from 'node:crypto';

// Never echo a supplied header or secret-bearing URL in a diagnostic ID.
export function apiRequestID(req, res, next) {
  req.apiRequestID = randomUUID();
  res.set('X-Request-ID', req.apiRequestID);
  next();
}

// Install only after ALL route installers, immediately before listening.
// Public pages and webhooks outside /api retain their existing fallbacks.
export function installAPIFallback(app) {
  app.use('/api', (req, res) => {
    res.set('Cache-Control', 'private, no-store');
    res.status(404).json({error: 'api_route_not_found', message: 'API route not found.'});
  });
  app.use('/api', (error, req, res, next) => {
    if (res.headersSent) return next(error);
    const status = error.type === 'entity.too.large' ? 413 : error.type === 'entity.parse.failed' ? 400 : 500;
    res.set('Cache-Control', 'private, no-store');
    res.status(status).json({error: status === 413 ? 'request_too_large' : status === 400 ? 'invalid_json' : 'server_error', message: status === 500 ? 'The server could not complete this request.' : 'The request body is invalid.'});
  });
}
