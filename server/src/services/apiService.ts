import { promises as dnsPromises } from 'node:dns';
import { randomUUID } from 'node:crypto';
import { db } from '../db';
import { logger } from '../logger';
import { notificationService } from './notificationService';

export interface ApiRecord {
  id: string;
  publisherId: string;
  name: string;
  description: string | null;
  upstreamUrl: string;
  upstreamMethod: string;
  upstreamHeaderValueEnc: string | null;
  upstreamQueryValueEnc: string | null;
  price: string;
  walletAddress: string;
  ownershipToken: string;
  ownershipVerified: boolean;
  listed: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface ApiChangeRecord {
  id: string;
  apiId: string;
  field: string;
  oldValue: string | null;
  newValue: string | null;
  actor: string;
  createdAt: string;
}

export interface OwnerApi {
  id: string;
  name: string;
  description: string | null;
  upstreamUrl: string;
  upstreamMethod: string;
  price: string;
  walletAddress: string;
  listed: boolean;
  ownershipVerified: boolean;
  ownershipVerification: {
    token: string;
    methods: string[];
    wellKnownFile: {
      url: string;
      expectedLine: string;
    };
    dnsTxt: {
      host: string;
      expectedRecord: string;
    };
  };
  createdAt: string;
  updatedAt: string;
}

export interface CreateApiInput {
  publisherId: string;
  name: string;
  description?: string | null;
  upstreamUrl: string;
  upstreamMethod?: string;
  upstreamHeaderValueEnc?: string | null;
  upstreamQueryValueEnc?: string | null;
  price: string;
  walletAddress: string;
}

export interface UpdateApiInput {
  name?: string;
  description?: string | null;
  upstreamUrl?: string;
  upstreamMethod?: string;
  upstreamHeaderValueEnc?: string | null;
  upstreamQueryValueEnc?: string | null;
  price?: string;
  walletAddress?: string;
}

const WELL_KNOWN_PATH = '/.well-known/zentrixpay.txt';
const DNS_TXT_PREFIX = 'zentrixpay-verification=';

// Fields that are audited when changed. Secrets are masked in the audit log.
const AUDITED_FIELDS: Array<keyof UpdateApiInput> = [
  'name',
  'description',
  'upstreamUrl',
  'upstreamMethod',
  'upstreamHeaderValueEnc',
  'upstreamQueryValueEnc',
  'price',
  'walletAddress',
];

const SECRET_FIELDS = new Set<string>([
  'upstreamHeaderValueEnc',
  'upstreamQueryValueEnc',
]);

const MASKED_VALUE = '***';

// Injectable DNS resolver so tests can mock DNS lookups.
export type TxtResolver = (host: string) => Promise<string[][]>;

let txtResolver: TxtResolver = async (host: string) => {
  return dnsPromises.resolveTxt(host);
};

export function setTxtResolver(resolver: TxtResolver): void {
  txtResolver = resolver;
}

export function resetTxtResolver(): void {
  txtResolver = async (host: string) => {
    return dnsPromises.resolveTxt(host);
  };
}

function maskValue(field: string, value: unknown): string | null {
  if (value === undefined || value === null) {
    return null;
  }
  if (SECRET_FIELDS.has(field)) {
    return MASKED_VALUE;
  }
  return String(value);
}

function normalizeForCompare(value: unknown): string | null {
  if (value === undefined || value === null) {
    return null;
  }
  return String(value);
}

function getUpstreamHost(upstreamUrl: string): string {
  try {
    return new URL(upstreamUrl).hostname;
  } catch {
    return upstreamUrl;
  }
}

async function checkWellKnownFile(
  upstreamUrl: string,
  token: string,
): Promise<boolean> {
  try {
    const url = new URL(WELL_KNOWN_PATH, upstreamUrl);
    const response = await fetch(url.toString(), {
      method: 'GET',
      redirect: 'follow',
    });
    if (!response.ok) {
      return false;
    }
    const body = await response.text();
    const expectedLine = `${DNS_TXT_PREFIX}${token}`;
    const lines = body.split(/\r?\n/).map((line) => line.trim());
    return lines.includes(expectedLine) || body.trim() === expectedLine;
  } catch (err) {
    logger.warn(
      { err, upstreamUrl },
      'Failed to check well-known ownership file',
    );
    return false;
  }
}

async function checkDnsTxt(upstreamUrl: string, token: string): Promise<boolean> {
  try {
    const host = getUpstreamHost(upstreamUrl);
    const records = await txtResolver(host);
    const expectedRecord = `${DNS_TXT_PREFIX}${token}`;
    for (const chunks of records) {
      const joined = chunks.join('');
      if (joined.trim() === expectedRecord) {
        return true;
      }
    }
    return false;
  } catch (err) {
    logger.warn({ err, upstreamUrl }, 'Failed to check DNS TXT ownership record');
    return false;
  }
}

async function verifyOwnership(
  upstreamUrl: string,
  token: string,
): Promise<boolean> {
  const [fileOk, dnsOk] = await Promise.all([
    checkWellKnownFile(upstreamUrl, token),
    checkDnsTxt(upstreamUrl, token),
  ]);
  return fileOk || dnsOk;
}

function toOwnerApi(api: ApiRecord): OwnerApi {
  const host = getUpstreamHost(api.upstreamUrl);
  let wellKnownUrl: string;
  try {
    wellKnownUrl = new URL(WELL_KNOWN_PATH, api.upstreamUrl).toString();
  } catch {
    wellKnownUrl = `${api.upstreamUrl.replace(/\/+$/, '')}${WELL_KNOWN_PATH}`;
  }
  return {
    id: api.id,
    name: api.name,
    description: api.description,
    upstreamUrl: api.upstreamUrl,
    upstreamMethod: api.upstreamMethod,
    price: api.price,
    walletAddress: api.walletAddress,
    listed: api.listed,
    ownershipVerified: api.ownershipVerified,
    ownershipVerification: {
      token: api.ownershipToken,
      methods: ['well-known-file', 'dns-txt'],
      wellKnownFile: {
        url: wellKnownUrl,
        expectedLine: `${DNS_TXT_PREFIX}${api.ownershipToken}`,
      },
      dnsTxt: {
        host,
        expectedRecord: `${DNS_TXT_PREFIX}${api.ownershipToken}`,
      },
    },
    createdAt: api.createdAt,
    updatedAt: api.updatedAt,
  };
}

export async function createApi(input: CreateApiInput): Promise<OwnerApi> {
  const now = new Date().toISOString();
  const id = randomUUID();
  const ownershipToken = randomUUID().replace(/-/g, '');
  const record: ApiRecord = {
    id,
    publisherId: input.publisherId,
    name: input.name,
    description: input.description ?? null,
    upstreamUrl: input.upstreamUrl,
    upstreamMethod: input.upstreamMethod ?? 'GET',
    upstreamHeaderValueEnc: input.upstreamHeaderValueEnc ?? null,
    upstreamQueryValueEnc: input.upstreamQueryValueEnc ?? null,
    price: input.price,
    walletAddress: input.walletAddress,
    ownershipToken,
    ownershipVerified: false,
    listed: false,
    createdAt: now,
    updatedAt: now,
  };

  await db('apis').insert(record);

  const verified = await verifyOwnership(record.upstreamUrl, ownershipToken);
  if (verified) {
    await db('apis')
      .where({ id })
      .update({ ownershipVerified: true, listed: true, updatedAt: now });
    record.ownershipVerified = true;
    record.listed = true;
  }

  return toOwnerApi(record);
}

export async function getApiById(id: string): Promise<ApiRecord | null> {
  const row = await db<ApiRecord>('apis').where({ id }).first();
  return row ?? null;
}

export async function getOwnerApi(
  id: string,
  publisherId: string,
): Promise<OwnerApi | null> {
  const row = await db<ApiRecord>('apis')
    .where({ id, publisherId })
    .first();
  return row ? toOwnerApi(row) : null;
}

export async function listOwnerApis(publisherId: string): Promise<OwnerApi[]> {
  const rows = await db<ApiRecord>('apis')
    .where({ publisherId })
    .orderBy('createdAt', 'desc');
  return rows.map(toOwnerApi);
}

async function recordChange(
  apiId: string,
  field: string,
  oldValue: unknown,
  newValue: unknown,
  actor: string,
): Promise<void> {
  const oldMasked = maskValue(field, oldValue);
  const newMasked = maskValue(field, newValue);
  if (oldMasked === newMasked) {
    return;
  }
  await db('api_changes').insert({
    id: randomUUID(),
    apiId,
    field,
    oldValue: oldMasked,
    newValue: newMasked,
    actor,
    createdAt: new Date().toISOString(),
  });
}

export async function updateApi(
  id: string,
  publisherId: string,
  input: UpdateApiInput,
): Promise<OwnerApi | null> {
  const existing = await db<ApiRecord>('apis')
    .where({ id, publisherId })
    .first();
  if (!existing) {
    return null;
  }

  const updates: Partial<ApiRecord> = {};
  const changes: Array<{ field: string; oldValue: unknown; newValue: unknown }> =
    [];

  for (const field of AUDITED_FIELDS) {
    if (!(field in input)) {
      continue;
    }
    const newValue = input[field];
    const oldValue = existing[field as keyof ApiRecord];
    if (normalizeForCompare(oldValue) !== normalizeForCompare(newValue)) {
      updates[field as keyof ApiRecord] = newValue as never;
      changes.push({ field, oldValue, newValue });
    }
  }

  if (changes.length === 0) {
    return toOwnerApi(existing);
  }

  const now = new Date().toISOString();
  updates.updatedAt = now;

  // If the upstream URL changed, ownership must be re-verified.
  const upstreamChanged = changes.some((c) => c.field === 'upstreamUrl');
  if (upstreamChanged) {
    const verified = await verifyOwnership(
      (updates.upstreamUrl as string) ?? existing.upstreamUrl,
      existing.ownershipToken,
    );
    updates.ownershipVerified = verified;
    updates.listed = verified;
  }

  await db('apis').where({ id }).update(updates);

  for (const change of changes) {
    await recordChange(
      id,
      change.field,
      change.oldValue,
      change.newValue,
      publisherId,
    );
  }

  const updated = await db<ApiRecord>('apis').where({ id }).first();
  return updated ? toOwnerApi(updated) : null;
}

export async function listApiChanges(
  apiId: string,
): Promise<ApiChangeRecord[]> {
  const rows = await db<ApiChangeRecord>('api_changes')
    .where({ apiId })
    .orderBy('createdAt', 'desc');
  return rows;
}

export async function getApiChangesForOwner(
  apiId: string,
  publisherId: string,
): Promise<ApiChangeRecord[] | null> {
  const existing = await db<ApiRecord>('apis')
    .where({ id: apiId, publisherId })
    .first();
  if (!existing) {
    return null;
  }
  return listApiChanges(apiId);
}

export async function listApisForOwnershipRecheck(): Promise<ApiRecord[]> {
  return db<ApiRecord>('apis').where({ listed: true });
}

export async function reverifyOwnership(api: ApiRecord): Promise<boolean> {
  const verified = await verifyOwnership(api.upstreamUrl, api.ownershipToken);
  const now = new Date().toISOString();

  if (verified) {
    if (!api.ownershipVerified) {
      await db('apis')
        .where({ id: api.id })
        .update({ ownershipVerified: true, updatedAt: now });
    }
    return true;
  }

  // Token disappeared: unlist and notify.
  await db('apis')
    .where({ id: api.id })
    .update({ ownershipVerified: false, listed: false, updatedAt: now });

  logger.warn(
    { apiId: api.id, publisherId: api.publisherId },
    'Ownership token no longer verifiable; API unlisted',
  );

  try {
    await notificationService.notifyOwnershipLost({
      apiId: api.id,
      publisherId: api.publisherId,
      apiName: api.name,
      upstreamUrl: api.upstreamUrl,
    });
  } catch (err) {
    logger.error(
      { err, apiId: api.id },
      'Failed to send ownership-lost notification',
    );
  }

  return false;
}

export async function runOwnershipRecheck(): Promise<{
  checked: number;
  unlisted: number;
}> {
  const apis = await listApisForOwnershipRecheck();
  let unlisted = 0;
  for (const api of apis) {
    const ok = await reverifyOwnership(api);
    if (!ok) {
      unlisted += 1;
    }
  }
  return { checked: apis.length, unlisted };
}

let recheckTimer: NodeJS.Timeout | null = null;

export function startOwnershipRecheckSchedule(
  intervalMs: number,
): void {
  if (recheckTimer) {
    clearInterval(recheckTimer);
  }
  recheckTimer = setInterval(() => {
    runOwnershipRecheck().catch((err) => {
      logger.error({ err }, 'Ownership recheck run failed');
    });
  }, intervalMs);
  if (typeof recheckTimer.unref === 'function') {
    recheckTimer.unref();
  }
}

export function stopOwnershipRecheckSchedule(): void {
  if (recheckTimer) {
    clearInterval(recheckTimer);
    recheckTimer = null;
  }
}