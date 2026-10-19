import type { NextFunction, Request, Response } from 'express';
import { Router } from 'express';
import { eq } from 'drizzle-orm';
import { db } from '../db/client.js';
import { apis } from '../db/schema.js';
import type { ApiRow } from '../db/schema.js';
import { config } from '../config.js';
import { paymentHeader, payerFromPayment } from '../lib/payer.js';
import { sharedX402ResourceServer } from '../lib/x402.js';

export interface ApiPaywallOptions {
  price?: string;
  priceForRequest?: (req: Request, api: ApiRow) => string;
  network?: string;
  description?: string;
}

const middlewareCache = new Map<string, ReturnType<typeof buildMiddleware>>();

function buildMiddleware(api: ApiRow, options: ApiPaywallOptions) {
  const price = options.price ?? api.price ?? '$0.01';
  const network = options.network ?? config.NETWORK;
  const payTo = api.walletAddress;

  const router = Router();

  router.use(async (req: Request, res: Response, next: NextFunction) => {
    try {
      const resourceServer = await sharedX402ResourceServer({
        network,
        payTo,
        price,
      });

      const middleware = resourceServer.middleware({
        price,
        network,
        payTo,
        description: options.description ?? api.description ?? undefined,
      });

      return middleware(req, res, next);
    } catch (err) {
      return next(err);
    }
  });

  return router;
}

export function apiPaywall(options: ApiPaywallOptions = {}) {
  return (req: Request, res: Response, next: NextFunction) => {
    const api = res.locals.api as ApiRow | undefined;

    if (!api) {
      return res.status(500).json({ error: 'apiPaywall requires res.locals.api' });
    }

    if (res.locals.creditPayer) return next();

    const pathParam = req.params.path as unknown;
    const path = Array.isArray(pathParam)
      ? (pathParam as string[]).length
        ? `/${(pathParam as string[]).join('/')}`
        : '/'
      : typeof pathParam === 'string' && pathParam
        ? `/${pathParam}`
        : '/';
    const price =
      options.price ??
      options.priceForRequest?.(req, api) ??
      resolveApiPrice(api, req.method, path);
    res.locals.apiCallPrice = price;
    const network = options.network ?? config.NETWORK;
    const cacheKey = `${api.id}:${price}:${network}`;

    let middleware = middlewareCache.get(cacheKey);
    if (!middleware) {
      middleware = buildMiddleware(api, { ...options, price, network });
      middlewareCache.set(cacheKey, middleware);
    }

    return middleware(req, res, next);
  };
}

function matchesPathPattern(pattern: string, path: string): boolean {
  if (!pattern.includes('*')) return pattern === path;

  const parts = pattern.split('*');
  let offset = 0;
  if (parts[0]) {
    if (!path.startsWith(parts[0])) return false;
    offset = parts[0].length;
  }

  for (let index = 1; index < parts.length; index++) {
    const part = parts[index];
    if (!part) continue;
    if (index === parts.length - 1 && !pattern.endsWith('*')) {
      return path.endsWith(part) && path.length - part.length >= offset;
    }
    const foundAt = path.indexOf(part, offset);
    if (foundAt === -1) return false;
    offset = foundAt + part.length;
  }
  return pattern.endsWith('*') || offset === path.length;
}

export function resolveApiPrice(api: Pick<ApiRow, 'price' | 'priceRules'>, method: string, path: string) {
  const matched = (api.priceRules ?? [])
    .filter((rule) => rule.method === method.toUpperCase())
    .filter((rule) => matchesPathPattern(rule.pathPattern, path))
    .sort((a, b) => {
      const wildcards =
        (a.pathPattern.match(/\*/g)?.length ?? 0) -
        (b.pathPattern.match(/\*/g)?.length ?? 0);
      if (wildcards !== 0) return wildcards;
      const literalLength =
        b.pathPattern.replace(/\*/g, '').length - a.pathPattern.replace(/\*/g, '').length;
      return literalLength;
    })[0];

  return matched?.price ?? api.price;
}

export function checkPayerAccess(req: Request, res: Response, next: NextFunction) {
  const header = paymentHeader(req);
  if (!header) return next();

  const api = res.locals.api as ApiRow;
  const payer = payerFromPayment(header);
  if (!payer.address || !payer.signed) return next();
  if (api.payerDenylist?.includes(payer.address)) {
    return res.status(403).json({ error: 'This wallet is not allowed to call this API' });
  }
  if (api.payerAllowlist?.length && !api.payerAllowlist.includes(payer.address)) {
    return res.status(403).json({ error: 'This API is restricted to approved wallets' });
  }
  return next();
}

export async function loadProxiedApi(req: Request, res: Response, next: NextFunction) {
  const apiId = req.params.apiId ?? req.params.id;

  if (!apiId) {
    return res.status(404).json({ error: 'API not found' });
  }

  const rows = await db.select().from(apis).where(eq(apis.id, apiId)).limit(1);
  const api = rows[0];

  if (!api || !api.listed) {
    return res.status(404).json({ error: 'API not found' });
  }

  const method = req.method.toUpperCase();
  const allowed = (api.allowedMethods ?? ['GET', 'POST']).map((m) => m.toUpperCase());

  if (!allowed.includes(method)) {
    res.setHeader('Allow', allowed.join(', '));
    return res.status(405).json({ error: 'Method not allowed' });
  }

  res.locals.api = api;
  return next();
}

export function clearApiPaywallCache() {
  middlewareCache.clear();
}