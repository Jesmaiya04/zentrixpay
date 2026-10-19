import pino from 'pino';

/**
 * Names of upstream headers that may carry provider secrets.
 * These are redacted from any logged request/header objects.
 */
const SECRET_HEADER_NAMES = [
  'x-api-key',
  'x-provider-key',
  'x-upstream-secret',
  'authorization',
  'proxy-authorization',
];

/**
 * Build the list of pino redaction paths for the configured secret headers.
 * Covers both `req.headers[...]` and bare `headers[...]` shapes, plus the
 * `upstreamHeader.value` / `upstreamQueryParam.value` fields in request bodies.
 */
function buildRedactPaths(): string[] {
  const paths: string[] = [];

  for (const name of SECRET_HEADER_NAMES) {
    paths.push(`req.headers['${name}']`);
    paths.push(`headers['${name}']`);
    paths.push(`request.headers['${name}']`);
  }

  paths.push('upstreamHeader.value');
  paths.push('upstreamQueryParam.value');
  paths.push('req.body.upstreamHeader.value');
  paths.push('req.body.upstreamQueryParam.value');
  paths.push('body.upstreamHeader.value');
  paths.push('body.upstreamQueryParam.value');

  return paths;
}

export const logger = pino({
  level: process.env.LOG_LEVEL ?? 'info',
  redact: {
    paths: buildRedactPaths(),
    censor: '[REDACTED]',
  },
  mixin() {
    return {
      service: 'server',
    };
  },
});

export default logger;