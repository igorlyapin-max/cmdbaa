import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { enrichVsdxFile, inspectVsdxAggregates, inspectVsdxContractMetadata, inspectVsdxFile } from './enrich-vsdx.mjs';

const LISTEN_HOST = process.env.PROXY_HOST || '127.0.0.1';
const LISTEN_PORT = Number(process.env.PROXY_PORT || 8094);
const CMDBUILD_ORIGIN = process.env.CMDBUILD_ORIGIN || 'http://127.0.0.1:8090';
const UI_PREFIX = '/cmdbuild/baa/ui';
const API_PREFIX = '/cmdbuild/baa/api';
const DEFAULT_SCHEMA_ROOT = process.env.CMDBBAA_SCHEMA_ROOT || 'BAA';
const DEFAULT_SCHEMA_PARENT = process.env.CMDBBAA_SCHEMA_PARENT || 'AA';
const CSRF_SECRET = process.env.CMDBBAA_CSRF_SECRET || crypto.randomBytes(32).toString('hex');
const PROXY_COOKIE_SAMESITE = process.env.CMDBBAA_PROXY_COOKIE_SAMESITE || '';
const PROXY_COOKIE_SECURE = process.env.CMDBBAA_PROXY_COOKIE_SECURE || 'false';
const DEV_CACHE_BUSTER = String(Date.now());
const STARTED_AT = new Date();
const CONTRACT_STATUSES = new Set(['Draft', 'Active', 'Archived']);
const CONTRACT_VERSION_STATUSES = new Set(['Draft', 'Active', 'Archived']);
const clientLogs = [];

function getCookieValue(cookieHeader, name) {
  const cookies = String(cookieHeader || '').split(';');
  for (const cookie of cookies) {
    const index = cookie.indexOf('=');
    if (index === -1) continue;
    const key = cookie.slice(0, index).trim();
    const value = cookie.slice(index + 1).trim();
    if (key === name) return decodeURIComponent(value);
  }
  return '';
}

function htmlEscape(value) {
  return String(value === undefined || value === null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function sha256Hex(value) {
  return crypto.createHash('sha256').update(String(value || '')).digest('hex');
}

function getCsrfToken(authToken) {
  return crypto.createHmac('sha256', CSRF_SECRET).update(String(authToken || '')).digest('hex');
}

function sendJson(res, statusCode, payload) {
  const body = JSON.stringify(payload, null, 2);
  res.writeHead(statusCode, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'content-length': Buffer.byteLength(body)
  });
  res.end(body);
}

function sendBinary(res, statusCode, body, headers = {}) {
  res.writeHead(statusCode, {
    'cache-control': 'no-store',
    'content-length': body.length,
    ...headers
  });
  res.end(body);
}

function sendHtml(res, statusCode, body) {
  res.writeHead(statusCode, {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
    'content-length': Buffer.byteLength(body)
  });
  res.end(body);
}

function redirect(res, location) {
  res.writeHead(302, {
    location,
    'cache-control': 'no-store'
  });
  res.end();
}

function methodAllowed(req, res, allowed) {
  const list = Array.isArray(allowed) ? allowed : [allowed];
  if (list.includes(req.method)) return true;
  res.writeHead(405, {
    allow: list.join(', '),
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store'
  });
  res.end(JSON.stringify({ success: false, message: `Method ${req.method} is not allowed.` }));
  return false;
}

async function readRequestBuffer(req, maxBytes = 30 * 1024 * 1024) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > maxBytes) {
      const error = new Error(`Request body is too large. Limit is ${maxBytes} bytes.`);
      error.statusCode = 413;
      throw error;
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

async function readJsonBody(req) {
  const text = (await readRequestBuffer(req)).toString('utf8');
  return text ? JSON.parse(text) : {};
}

function withTempFile(prefix, suffix, buffer, fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  const filePath = path.join(dir, `input${suffix}`);
  try {
    fs.writeFileSync(filePath, buffer);
    return fn(filePath, dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function shapeClassMapFromAggregates(aggregates, aggregateClassMap) {
  const map = {};
  for (const aggregate of aggregates || []) {
    const aggregateTypeKey = String(aggregate.aggregateTypeKey || '');
    if (!aggregateTypeKey) continue;
    for (const role of aggregate.atomRoles || []) {
      const roleKey = String(role.roleKey || '');
      if (!roleKey) continue;
      const classValue = aggregateClassMap[`${aggregateTypeKey}::${roleKey}`];
      if (!classValue) continue;
      for (const instance of aggregate.instances || []) {
        for (const atom of instance.atoms || []) {
          if (atom.roleKey === roleKey && atom.page && atom.shapeId) {
            map[`${atom.page}:${atom.shapeId}`] = classValue;
          }
        }
      }
    }
  }
  return map;
}

function digestHex(algorithm, buffer) {
  return crypto.createHash(algorithm).update(buffer).digest('hex').toLowerCase();
}

function extractChecksumCandidates(text) {
  const candidates = [];
  const patterns = [
    { length: 64, algorithms: ['sha256', 'sha3-256'] },
    { length: 96, algorithms: ['sha384', 'sha3-384'] },
    { length: 128, algorithms: ['sha512', 'sha3-512'] }
  ];
  for (const pattern of patterns) {
    const regex = new RegExp(`\\b[a-fA-F0-9]{${pattern.length}}\\b`, 'g');
    for (const match of String(text || '').matchAll(regex)) {
      const before = String(text || '').slice(Math.max(0, match.index - 40), match.index).toLowerCase();
      let algorithms = pattern.algorithms;
      if (before.includes('sha3')) algorithms = pattern.algorithms.filter((item) => item.startsWith('sha3'));
      else if (before.includes('sha2') || before.includes('sha-2') || before.includes('sha256') || before.includes('sha384') || before.includes('sha512')) {
        algorithms = pattern.algorithms.filter((item) => !item.startsWith('sha3'));
      }
      candidates.push({
        value: match[0].toLowerCase(),
        algorithms
      });
    }
  }
  return candidates;
}

function verifyChecksum(buffer, checksumText) {
  const candidates = extractChecksumCandidates(checksumText);
  if (!candidates.length) {
    return {
      checked: false,
      ok: false,
      status: 'not_checked',
      message: 'Контрольная сумма не проверялась: файл суммы не содержит SHA-2/SHA-3 hex.'
    };
  }
  const algorithms = Array.from(new Set(candidates.flatMap((item) => item.algorithms)));
  const digests = Object.fromEntries(algorithms.map((algorithm) => [algorithm, digestHex(algorithm, buffer)]));
  for (const candidate of candidates) {
    for (const algorithm of candidate.algorithms) {
      if (digests[algorithm] === candidate.value) {
        return {
          checked: true,
          ok: true,
          status: 'ok',
          algorithm,
          expected: candidate.value,
          actual: digests[algorithm],
          message: `Контрольная сумма проверена успешно (${algorithm}).`
        };
      }
    }
  }
  return {
    checked: true,
    ok: false,
    status: 'mismatch',
    expected: candidates.map((item) => item.value),
    actual: digests,
    message: 'Контрольная сумма не совпала.'
  };
}

function parseContractRules(value) {
  if (!value) return {};
  if (typeof value === 'object' && !Array.isArray(value)) return value;
  try {
    const parsed = JSON.parse(String(value));
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function validateCmdbuildIdentifier(value, label) {
  const text = String(value || '').trim();
  if (!/^[A-Za-z][A-Za-z0-9_]*$/.test(text)) {
    throw new Error(`${label} must start with a letter and contain only letters, digits, and underscores.`);
  }
  return text;
}

function validateBusinessCode(value, label) {
  const text = String(value || '').trim();
  if (!/^[A-Za-z][A-Za-z0-9_-]*$/.test(text)) {
    throw new Error(`${label} must start with a letter and contain only letters, digits, underscores, or hyphens.`);
  }
  return text;
}

function validateContractStatus(value) {
  const status = String(value || 'Draft').trim() || 'Draft';
  if (!CONTRACT_STATUSES.has(status)) {
    throw new Error(`contract status must be one of: ${Array.from(CONTRACT_STATUSES).join(', ')}`);
  }
  return status;
}

function validateContractVersionStatus(value) {
  const status = String(value || 'Draft').trim() || 'Draft';
  if (!CONTRACT_VERSION_STATUSES.has(status)) {
    throw new Error(`contract version status must be one of: ${Array.from(CONTRACT_VERSION_STATUSES).join(', ')}`);
  }
  return status;
}

function baseClassPayload(definition) {
  const payload = {
    name: definition.name,
    description: definition.description,
    prototype: Boolean(definition.prototype),
    type: 'standard',
    active: true,
    defaultOrder: [],
    domainOrder: [],
    formTriggers: [],
    contextMenuItems: [],
    widgets: [],
    attributeGroups: [],
    dmsCategories: [],
    attachmentsInline: false,
    attachmentsInlineClosed: true,
    noteInline: false,
    noteInlineClosed: false,
    multitenantMode: 'never',
    uiRouting_mode: 'default',
    uiRouting_target: null,
    uiRouting_custom: {},
    barcodeSearchAttr: null,
    barcodeSearchRegex: null
  };
  if (definition.parent) payload.parent = definition.parent;
  return payload;
}

function baseAttributePayload(attribute, index) {
  const payload = {
    name: attribute.name,
    description: attribute.description,
    type: attribute.type,
    mode: 'write',
    active: true,
    mandatory: Boolean(attribute.mandatory),
    unique: Boolean(attribute.unique),
    showInGrid: attribute.showInGrid !== false,
    showInReducedGrid: false,
    hidden: false,
    writable: true,
    index,
    metadata: {}
  };
  if (attribute.type === 'string') {
    const maxLength = attribute.maxLength || 100;
    payload.maxLength = maxLength;
    payload.metadata.cm_length = String(maxLength);
    payload.metadata.cm_multiline = 'false';
    payload.password = false;
    payload.showPassword = 'always';
    payload.textContentSecurity = 'plaintext';
  }
  if (attribute.type === 'text') {
    payload.metadata.cm_multiline = 'true';
    payload.textContentSecurity = 'plaintext';
  }
  return payload;
}

function buildBaaSchema(input = {}) {
  const root = validateCmdbuildIdentifier(input.root || DEFAULT_SCHEMA_ROOT, 'schema root');
  const parentInput = input.parent === null || input.parent === false || input.parent === '__none__'
    ? ''
    : String(input.parent || input.rootParent || DEFAULT_SCHEMA_PARENT).trim();
  const parent = parentInput && parentInput !== root
    ? validateCmdbuildIdentifier(parentInput, 'schema parent')
    : '';
  const rootDescription = String(input.description || 'BAA technical superclass').trim() || 'BAA technical superclass';
  return {
    root,
    parent,
    description: rootDescription,
    classes: [
      {
        name: root,
        description: rootDescription,
        parent,
        prototype: true,
        attributes: []
      },
      {
        name: 'BAAConversionContract',
        description: 'BAA conversion contract',
        parent: root,
        prototype: false,
        attributes: [
          {
            name: 'ContractName',
            description: 'Contract name',
            type: 'string',
            mandatory: true,
            unique: false,
            showInGrid: true,
            maxLength: 250
          },
          {
            name: 'ContractStatus',
            description: 'Contract status',
            type: 'string',
            mandatory: true,
            unique: false,
            showInGrid: true,
            maxLength: 32
          }
        ]
      },
      {
        name: 'BAAConversionContractVersion',
        description: 'BAA conversion contract version',
        parent: root,
        prototype: false,
        attributes: [
          { name: 'ContractId', description: 'Contract object id', type: 'string', mandatory: true, unique: false, showInGrid: true, maxLength: 64 },
          { name: 'ContractCode', description: 'Contract code', type: 'string', mandatory: true, unique: false, showInGrid: true, maxLength: 100 },
          { name: 'VersionNumber', description: 'Version number', type: 'string', mandatory: true, unique: false, showInGrid: true, maxLength: 50 },
          { name: 'VersionStatus', description: 'Version status', type: 'string', mandatory: true, unique: false, showInGrid: true, maxLength: 32 },
          { name: 'RulesJson', description: 'Rules JSON', type: 'text', mandatory: true, unique: false, showInGrid: false },
          { name: 'RulesChecksum', description: 'Rules checksum', type: 'string', mandatory: true, unique: false, showInGrid: true, maxLength: 128 },
          { name: 'VersionActive', description: 'Version active flag', type: 'boolean', mandatory: false, unique: false, showInGrid: true },
          { name: 'CreatedBy', description: 'Created by', type: 'string', mandatory: false, unique: false, showInGrid: true, maxLength: 100 },
          { name: 'CreatedAt', description: 'Created at', type: 'string', mandatory: false, unique: false, showInGrid: true, maxLength: 40 }
        ]
      }
    ]
  };
}

function sanitizeClassForSchema(data) {
  if (!data || typeof data !== 'object') return null;
  return {
    name: data.name || '',
    description: data._description_translation || data.description || '',
    parent: data.parent || null,
    prototype: data.prototype === undefined ? null : Boolean(data.prototype),
    type: data.type || null,
    active: data.active === undefined ? null : Boolean(data.active)
  };
}

function sanitizeAttributeForSchema(data) {
  if (!data || typeof data !== 'object') return null;
  return {
    name: data.name || '',
    description: data._description_translation || data.description || '',
    type: data.type || null,
    active: data.active === undefined ? null : Boolean(data.active),
    mandatory: data.mandatory === undefined ? null : Boolean(data.mandatory),
    inherited: data.inherited === undefined ? null : Boolean(data.inherited)
  };
}

function sanitizeContractCard(data) {
  if (!data || typeof data !== 'object') return null;
  return {
    id: data._id || data.Id || data.id || null,
    code: data.Code || data.code || '',
    name: data.ContractName || data.contractName || '',
    description: data.Description || data.description || data._Description_description || '',
    status: data.ContractStatus || data.contractStatus || 'Draft',
    active: data.Active === undefined && data.active === undefined ? null : data.Active !== false && data.active !== false
  };
}

function sanitizeContractVersionCard(data) {
  if (!data || typeof data !== 'object') return null;
  return {
    id: data._id || data.Id || data.id || null,
    code: data.Code || data.code || '',
    description: data.Description || data.description || data._Description_description || '',
    contractId: data.ContractId || data.contractId || '',
    contractCode: data.ContractCode || data.contractCode || '',
    version: data.VersionNumber || data.versionNumber || '',
    status: data.VersionStatus || data.versionStatus || 'Draft',
    rulesJson: data.RulesJson || data.rulesJson || '',
    rulesChecksum: data.RulesChecksum || data.rulesChecksum || '',
    active: data.VersionActive === undefined && data.versionActive === undefined ? null : data.VersionActive !== false && data.versionActive !== false,
    createdBy: data.CreatedBy || data.createdBy || '',
    createdAt: data.CreatedAt || data.createdAt || ''
  };
}

function cmdbuildErrorMessage(response, fallback) {
  if (!response) return fallback;
  const messages = response.json && Array.isArray(response.json.messages) ? response.json.messages : [];
  const text = messages.map((item) => item && (item.message || item._message_translation)).filter(Boolean).join('; ');
  return response.error || text || response.text || fallback;
}

function requiredSystemAttributes() {
  return [
    { name: 'Code', description: 'Code', type: 'string', mandatory: true, system: true },
    { name: 'Description', description: 'Description', type: 'string', mandatory: true, system: true }
  ];
}

async function listConversionContracts(authToken) {
  const response = await cmdbuildRequest('/cmdbuild/services/rest/v3/classes/BAAConversionContract/cards?limit=200&detailed=true', authToken);
  return {
    success: response.ok,
    cmdbuildStatus: response.statusCode,
    data: Array.isArray(response.json && response.json.data)
      ? response.json.data.map(sanitizeContractCard).filter(Boolean)
      : [],
    message: response.ok ? '' : cmdbuildErrorMessage(response, 'CMDBuild contract list failed.')
  };
}

async function createConversionContract(authToken, input = {}) {
  const code = validateBusinessCode(input.code || input.Code, 'contract code');
  const name = String(input.name || input.ContractName || code).trim() || code;
  const description = String(input.description || input.Description || code).trim() || code;
  const status = validateContractStatus(input.status || input.ContractStatus || 'Draft');
  const existing = await listConversionContracts(authToken);
  if (existing.success) {
    const sameCode = existing.data.find((item) => item.code === code);
    if (sameCode) {
      return {
        success: true,
        cmdbuildStatus: 200,
        data: sameCode,
        message: 'Contract already exists.'
      };
    }
  }
  const response = await cmdbuildRequest('/cmdbuild/services/rest/v3/classes/BAAConversionContract/cards', authToken, {
    method: 'POST',
    body: {
      Code: code,
      Description: description,
      ContractName: name,
      ContractStatus: status
    }
  });
  return {
    success: response.ok,
    cmdbuildStatus: response.statusCode,
    data: sanitizeContractCard(response.json && response.json.data),
    message: response.ok ? '' : cmdbuildErrorMessage(response, 'CMDBuild contract create failed.')
  };
}

async function listConversionContractVersions(authToken) {
  const response = await cmdbuildRequest('/cmdbuild/services/rest/v3/classes/BAAConversionContractVersion/cards?limit=200&detailed=true', authToken);
  return {
    success: response.ok,
    cmdbuildStatus: response.statusCode,
    data: Array.isArray(response.json && response.json.data)
      ? response.json.data.map(sanitizeContractVersionCard).filter(Boolean)
      : [],
    message: response.ok ? '' : cmdbuildErrorMessage(response, 'CMDBuild contract version list failed.')
  };
}

async function createConversionContractVersion(authToken, input = {}) {
  const contractId = String(input.contractId || input.ContractId || '').trim();
  const contractCode = validateBusinessCode(input.contractCode || input.ContractCode, 'contract code');
  const version = String(input.version || input.VersionNumber || '1').trim() || '1';
  const code = validateBusinessCode(input.code || input.Code || `${contractCode}-v${version}`, 'contract version code');
  const description = String(input.description || input.Description || `${contractCode} version ${version}`).trim() || `${contractCode} version ${version}`;
  const status = validateContractVersionStatus(input.status || input.VersionStatus || 'Draft');
  const rulesText = String(input.rulesJson || input.RulesJson || '{}').trim() || '{}';
  let rulesObject;
  try {
    rulesObject = JSON.parse(rulesText);
  } catch {
    throw new Error('RulesJson must be valid JSON.');
  }
  const normalizedRulesJson = JSON.stringify(rulesObject, null, 2);
  const rulesChecksum = digestHex('sha256', Buffer.from(normalizedRulesJson, 'utf8'));
  const response = await cmdbuildRequest('/cmdbuild/services/rest/v3/classes/BAAConversionContractVersion/cards', authToken, {
    method: 'POST',
    body: {
      Code: code,
      Description: description,
      ContractId: contractId,
      ContractCode: contractCode,
      VersionNumber: version,
      VersionStatus: status,
      RulesJson: normalizedRulesJson,
      RulesChecksum: rulesChecksum,
      VersionActive: Boolean(input.active !== false && input.VersionActive !== false),
      CreatedBy: String(input.createdBy || input.CreatedBy || '').trim(),
      CreatedAt: new Date().toISOString()
    }
  });
  return {
    success: response.ok,
    cmdbuildStatus: response.statusCode,
    data: sanitizeContractVersionCard(response.json && response.json.data),
    rulesChecksum,
    message: response.ok ? '' : cmdbuildErrorMessage(response, 'CMDBuild contract version create failed.')
  };
}

function parseRulesJson(rulesJson) {
  try {
    return JSON.parse(String(rulesJson || '{}'));
  } catch {
    return {};
  }
}

function nextVersionNumber(versions) {
  const numbers = (versions || []).map((item) => Number.parseInt(String(item.version || '0'), 10)).filter(Number.isFinite);
  return String((numbers.length ? Math.max(...numbers) : 0) + 1);
}

function contractVersionsFor(versions, contract) {
  return (versions || []).filter((version) =>
    (contract.id && version.contractId === contract.id) ||
    (contract.code && version.contractCode === contract.code)
  );
}

function latestContractVersion(versions) {
  return [...(versions || [])].sort((a, b) =>
    Number.parseInt(String(b.version || '0'), 10) - Number.parseInt(String(a.version || '0'), 10)
  )[0] || null;
}

function typeSnapshot(types) {
  return (types || []).map((type) => ({
    typeKey: type.typeKey,
    label: type.label,
    kind: type.kind,
    eligibleForCmdb: type.eligibleForCmdb !== false
  })).filter((type) => type.typeKey);
}

function aggregateSnapshot(aggregates) {
  return (aggregates || []).map((aggregate) => ({
    aggregateTypeKey: aggregate.aggregateTypeKey,
    label: aggregate.label,
    kind: aggregate.kind,
    atomRoles: (aggregate.atomRoles || []).map((role) => ({
      roleKey: role.roleKey,
      label: role.label,
      kind: role.kind,
      typeKey: role.typeKey
    })).filter((role) => role.roleKey)
  })).filter((aggregate) => aggregate.aggregateTypeKey);
}

function mergeKnownTypes(previous, current) {
  const byKey = new Map();
  for (const item of previous || []) if (item && item.typeKey) byKey.set(item.typeKey, item);
  const added = [];
  for (const item of current || []) {
    if (!item || !item.typeKey) continue;
    if (!byKey.has(item.typeKey)) added.push(item);
    byKey.set(item.typeKey, { ...byKey.get(item.typeKey), ...item });
  }
  return {
    knownTypes: Array.from(byKey.values()).sort((a, b) => String(a.label || '').localeCompare(String(b.label || '')) || String(a.typeKey).localeCompare(String(b.typeKey))),
    addedTypes: added
  };
}

function mergeKnownAggregates(previous, current) {
  const byKey = new Map();
  for (const item of previous || []) if (item && item.aggregateTypeKey) byKey.set(item.aggregateTypeKey, item);
  const added = [];
  for (const item of current || []) {
    if (!item || !item.aggregateTypeKey) continue;
    if (!byKey.has(item.aggregateTypeKey)) {
      added.push(item);
      byKey.set(item.aggregateTypeKey, item);
      continue;
    }
    const existing = byKey.get(item.aggregateTypeKey);
    const roleByKey = new Map();
    for (const role of existing.atomRoles || []) if (role && role.roleKey) roleByKey.set(role.roleKey, role);
    let hasNewRole = false;
    for (const role of item.atomRoles || []) {
      if (!role || !role.roleKey) continue;
      if (!roleByKey.has(role.roleKey)) hasNewRole = true;
      roleByKey.set(role.roleKey, { ...roleByKey.get(role.roleKey), ...role });
    }
    const merged = {
      ...existing,
      ...item,
      atomRoles: Array.from(roleByKey.values()).sort((a, b) => String(a.label || '').localeCompare(String(b.label || '')) || String(a.roleKey).localeCompare(String(b.roleKey)))
    };
    if (hasNewRole) added.push(item);
    byKey.set(item.aggregateTypeKey, merged);
  }
  return {
    knownAggregates: Array.from(byKey.values()).sort((a, b) => String(a.label || '').localeCompare(String(b.label || '')) || String(a.aggregateTypeKey).localeCompare(String(b.aggregateTypeKey))),
    addedAggregates: added
  };
}

async function resolveContractVersionForEnrichment(authToken, input = {}) {
  const contract = input.contract || {};
  const currentTypes = typeSnapshot(input.types || []);
  const currentAggregates = aggregateSnapshot(input.aggregates || []);
  const typeRules = input.typeRules || {};
  const versionsResult = await listConversionContractVersions(authToken);
  const allVersions = versionsResult.success ? versionsResult.data : [];
  let resolvedContract = {
    id: String(contract.id || contract.contractId || ''),
    code: String(contract.code || contract.contractCode || '')
  };
  if ((!resolvedContract.id && !resolvedContract.code) && input.existingMetadata) {
    const existing = allVersions.find((version) =>
      version.id === input.existingMetadata.contractVersionId ||
      version.code === input.existingMetadata.contractVersionCode
    );
    if (existing) {
      resolvedContract = {
        id: existing.contractId,
        code: existing.contractCode
      };
    }
  }
  if (!resolvedContract.id && !resolvedContract.code) {
    throw new Error('Contract is required for new template enrichment.');
  }
  const contractVersions = contractVersionsFor(allVersions, resolvedContract);
  const latest = latestContractVersion(contractVersions);
  const latestRules = parseRulesJson(latest && latest.rulesJson);
  const merged = mergeKnownTypes(Array.isArray(latestRules.knownTypes) ? latestRules.knownTypes : [], currentTypes);
  const mergedAggregates = mergeKnownAggregates(Array.isArray(latestRules.knownAggregates) ? latestRules.knownAggregates : [], currentAggregates);
  if (latest && merged.addedTypes.length === 0 && mergedAggregates.addedAggregates.length === 0) {
    return {
      version: latest,
      action: 'reused',
      addedTypes: [],
      knownTypes: merged.knownTypes,
      addedAggregates: [],
      knownAggregates: mergedAggregates.knownAggregates
    };
  }
  const versionNumber = nextVersionNumber(contractVersions);
  const rulesObject = {
    ...typeRules,
    knownTypes: merged.knownTypes,
    knownAggregates: mergedAggregates.knownAggregates
  };
  const created = await createConversionContractVersion(authToken, {
    contractId: resolvedContract.id,
    contractCode: resolvedContract.code,
    code: `${resolvedContract.code || 'contract'}-v${versionNumber}`,
    version: versionNumber,
    status: 'Active',
    rulesJson: JSON.stringify(rulesObject, null, 2),
    createdBy: input.preparedBy || ''
  });
  if (!created.success) {
    throw new Error(created.message || 'Failed to create contract version.');
  }
  return {
    version: created.data,
    action: latest ? 'created_extended' : 'created_initial',
    addedTypes: latest ? merged.addedTypes : currentTypes,
    knownTypes: merged.knownTypes,
    addedAggregates: latest ? mergedAggregates.addedAggregates : currentAggregates,
    knownAggregates: mergedAggregates.knownAggregates
  };
}

async function checkOrCreateBaaSchema(authToken, input = {}, createMissing = false) {
  const schema = buildBaaSchema(input);
  const actions = [];
  const missing = [];
  const conflicts = [];
  const errors = [];
  const classResults = [];

  if (schema.parent) {
    const parentResponse = await cmdbuildRequest(`/cmdbuild/services/rest/v3/classes/${encodeURIComponent(schema.parent)}`, authToken);
    if (!parentResponse.ok) {
      errors.push({
        type: 'parent',
        name: schema.parent,
        cmdbuildStatus: parentResponse.statusCode,
        message: parentResponse.statusCode === 404
          ? `Parent superclass "${schema.parent}" was not found. Select an existing parent or "Без родителя".`
          : cmdbuildErrorMessage(parentResponse, 'CMDBuild parent class check failed.')
      });
    }
  }

  for (const classDefinition of schema.classes) {
    const response = await cmdbuildRequest(`/cmdbuild/services/rest/v3/classes/${encodeURIComponent(classDefinition.name)}`, authToken);
    let exists = response.ok;
    let created = false;
    let existing = response.ok ? sanitizeClassForSchema(response.json && response.json.data) : null;
    const classMissing = [];
    const classErrors = [];

    if (exists) {
      if (existing && classDefinition.parent && String(existing.parent || '') !== String(classDefinition.parent || '')) {
        conflicts.push({
          type: 'class',
          name: classDefinition.name,
          field: 'parent',
          expected: classDefinition.parent,
          actual: existing.parent
        });
      }
      if (existing && existing.prototype !== null && existing.prototype !== classDefinition.prototype) {
        conflicts.push({
          type: 'class',
          name: classDefinition.name,
          field: 'prototype',
          expected: classDefinition.prototype,
          actual: existing.prototype
        });
      }
    } else if (response.statusCode === 404) {
      const item = {
        type: 'class',
        name: classDefinition.name,
        parent: classDefinition.parent
      };
      classMissing.push(item);
      missing.push(item);
      actions.push({
        type: 'class',
        name: classDefinition.name,
        action: 'create',
        parent: classDefinition.parent
      });
    } else {
      const error = {
        type: 'class',
        name: classDefinition.name,
        cmdbuildStatus: response.statusCode,
        message: response.error || response.text || 'CMDBuild class check failed.'
      };
      classErrors.push(error);
      errors.push(error);
    }

    if (createMissing && classMissing.length && !conflicts.length && !errors.length && !classErrors.length) {
      const createResponse = await cmdbuildRequest('/cmdbuild/services/rest/v3/classes/', authToken, {
        method: 'POST',
        body: baseClassPayload(classDefinition)
      });
      actions.push({
        type: 'class',
        name: classDefinition.name,
        action: createResponse.ok ? 'created' : 'create_failed',
        cmdbuildStatus: createResponse.statusCode
      });
      exists = createResponse.ok;
      created = createResponse.ok;
      existing = createResponse.ok ? sanitizeClassForSchema(createResponse.json && createResponse.json.data) : null;
      if (createResponse.ok) {
        for (const item of classMissing) {
          const index = missing.indexOf(item);
          if (index !== -1) missing.splice(index, 1);
        }
      } else {
        errors.push({
          type: 'class',
          name: classDefinition.name,
          cmdbuildStatus: createResponse.statusCode,
          message: cmdbuildErrorMessage(createResponse, 'CMDBuild class create failed.')
        });
      }
    }

    classResults.push({
      ...classDefinition,
      exists,
      created,
      existing,
      cmdbuildStatus: response.statusCode,
      attributes: []
    });
    const classStatus = classResults[classResults.length - 1];
    if (!classDefinition.prototype) {
      for (const systemAttribute of requiredSystemAttributes()) {
        classStatus.attributes.push({
          ...systemAttribute,
          exists: exists,
          created: false,
          existing: exists ? systemAttribute : null,
          cmdbuildStatus: exists ? 200 : response.statusCode
        });
      }
    }
    if (exists && Array.isArray(classDefinition.attributes)) {
      let index = 10;
      for (const attribute of classDefinition.attributes) {
        const attrResponse = await cmdbuildRequest(`/cmdbuild/services/rest/v3/classes/${encodeURIComponent(classDefinition.name)}/attributes/${encodeURIComponent(attribute.name)}`, authToken);
        let attrExists = attrResponse.ok;
        let attrCreated = false;
        let existingAttribute = attrExists ? sanitizeAttributeForSchema(attrResponse.json && attrResponse.json.data) : null;
        if (attrExists && existingAttribute && existingAttribute.type && existingAttribute.type !== attribute.type) {
          conflicts.push({
            type: 'attribute',
            className: classDefinition.name,
            name: attribute.name,
            field: 'type',
            expected: attribute.type,
            actual: existingAttribute.type
          });
        } else if (!attrExists && attrResponse.statusCode === 404) {
          missing.push({
            type: 'attribute',
            className: classDefinition.name,
            name: attribute.name
          });
          actions.push({
            type: 'attribute',
            className: classDefinition.name,
            name: attribute.name,
            action: 'create'
          });
          if (createMissing && !conflicts.length) {
            const createAttrResponse = await cmdbuildRequest(`/cmdbuild/services/rest/v3/classes/${encodeURIComponent(classDefinition.name)}/attributes`, authToken, {
              method: 'POST',
              body: baseAttributePayload(attribute, index)
            });
            actions.push({
              type: 'attribute',
              className: classDefinition.name,
              name: attribute.name,
              action: createAttrResponse.ok ? 'created' : 'create_failed',
              cmdbuildStatus: createAttrResponse.statusCode
            });
            attrExists = createAttrResponse.ok;
            attrCreated = createAttrResponse.ok;
            existingAttribute = attrExists ? sanitizeAttributeForSchema(createAttrResponse.json && createAttrResponse.json.data) : null;
            if (createAttrResponse.ok) {
              const missingIndex = missing.findIndex((item) => item.type === 'attribute' && item.className === classDefinition.name && item.name === attribute.name);
              if (missingIndex !== -1) missing.splice(missingIndex, 1);
            } else {
              errors.push({
                type: 'attribute',
                className: classDefinition.name,
                name: attribute.name,
                cmdbuildStatus: createAttrResponse.statusCode,
                message: createAttrResponse.error || createAttrResponse.text || 'CMDBuild attribute create failed.'
              });
            }
          }
        } else if (!attrExists) {
          errors.push({
            type: 'attribute',
            className: classDefinition.name,
            name: attribute.name,
            cmdbuildStatus: attrResponse.statusCode,
            message: attrResponse.error || attrResponse.text || 'CMDBuild attribute check failed.'
          });
        }
        classStatus.attributes.push({
          ...attribute,
          exists: attrExists,
          created: attrCreated,
          existing: existingAttribute,
          cmdbuildStatus: attrResponse.statusCode
        });
        index += 10;
      }
    }
  }

  const ready = classResults.every((item) => item.exists) && !conflicts.length && !errors.length && !missing.length;

  return {
    root: schema.root,
    parent: schema.parent,
    description: schema.description,
    ready,
    status: ready
      ? 'ready'
      : conflicts.length
        ? 'conflict'
        : missing.length
          ? 'missing'
          : 'error',
    createMissing,
    classes: classResults,
    missing,
    conflicts,
    errors,
    actions,
    summary: {
      classCount: schema.classes.length,
      attributeCount: schema.classes.reduce((count, item) => count + (Array.isArray(item.attributes) ? item.attributes.length : 0), 0),
      plannedCreates: actions.filter((item) => item.action === 'create' || item.action === 'created').length,
      conflicts: conflicts.length,
      errors: errors.length
    }
  };
}

function isHealthPath(pathname) {
  return pathname === '/health/live' ||
    pathname === '/health/ready' ||
    pathname === `${API_PREFIX}/health/live` ||
    pathname === `${API_PREFIX}/health/ready`;
}

function baseHealthPayload() {
  return {
    service: 'cmdbaa',
    timestamp: new Date().toISOString(),
    startedAt: STARTED_AT.toISOString(),
    uptimeSec: Math.floor(process.uptime()),
    pid: process.pid
  };
}

async function cmdbuildRequest(path, authToken, options = {}) {
  const target = new URL(path, CMDBUILD_ORIGIN);
  const body = options.body === undefined ? null : JSON.stringify(options.body);
  return await new Promise((resolve) => {
    const headers = {
      accept: 'application/json',
      'CMDBuild-Authorization': authToken,
      ...(options.headers || {})
    };
    if (body !== null) {
      headers['content-type'] = 'application/json';
      headers['content-length'] = Buffer.byteLength(body);
    }
    const request = http.request({
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port,
      method: options.method || 'GET',
      path: `${target.pathname}${target.search}`,
      headers
    }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try {
          json = text ? JSON.parse(text) : null;
        } catch {
          json = null;
        }
        const statusCode = response.statusCode || 0;
        resolve({
          ok: statusCode >= 200 && statusCode < 300,
          statusCode,
          json,
          text
        });
      });
    });
    request.on('error', (error) => {
      resolve({
        ok: false,
        statusCode: 0,
        json: null,
        text: '',
        error: error && error.message ? error.message : String(error)
      });
    });
    request.setTimeout(10000, () => {
      request.destroy(new Error('CMDBuild request timed out.'));
    });
    if (body !== null) request.write(body);
    request.end();
  });
}

function sanitizeSession(data) {
  if (!data || typeof data !== 'object') return {};
  return {
    username: data.username || data.user || '',
    role: data.role || data.roleName || '',
    sessionIdHash: data._id ? sha256Hex(data._id).slice(0, 16) : ''
  };
}

async function getSessionData(authToken) {
  const response = await cmdbuildRequest('/cmdbuild/services/rest/v3/sessions/current', authToken);
  return {
    response,
    data: response.json && response.json.data ? response.json.data : null
  };
}

async function handleHealth(req, res, requestUrl) {
  if (!methodAllowed(req, res, 'GET')) return;
  if (requestUrl.pathname.endsWith('/live')) {
    sendJson(res, 200, {
      ...baseHealthPayload(),
      status: 'live',
      live: true
    });
    return;
  }
  const target = new URL('/cmdbuild/services/rest/v3/sessions/current', CMDBUILD_ORIGIN);
  const probe = await new Promise((resolve) => {
    const started = Date.now();
    const request = http.request({
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port,
      method: 'GET',
      path: target.pathname,
      headers: { accept: 'application/json' }
    }, (response) => {
      response.resume();
      response.on('end', () => {
        const statusCode = response.statusCode || 0;
        resolve({
          ok: statusCode >= 200 && statusCode < 500,
          statusCode,
          latencyMs: Date.now() - started
        });
      });
    });
    request.on('error', (error) => {
      resolve({
        ok: false,
        statusCode: 0,
        latencyMs: Date.now() - started,
        error: error && error.message ? error.message : String(error)
      });
    });
    request.setTimeout(3000, () => request.destroy(new Error('CMDBuild health probe timed out.')));
    request.end();
  });
  const ready = Boolean(probe.ok);
  sendJson(res, ready ? 200 : 503, {
    ...baseHealthPayload(),
    status: ready ? 'ready' : 'not_ready',
    ready,
    checks: {
      process: { ok: true, status: 'ok' },
      cmdbuild: {
        required: true,
        status: ready ? 'ok' : 'unavailable',
        url: `${target.origin}${target.pathname}`,
        ...probe
      }
    }
  });
}

function normalizeSection(value) {
  const section = String(value || '').trim().toLowerCase();
  if (section === 'schema' || section === 'cmdb-schema') return 'schema';
  if (section === 'contracts' || section === 'contract' || section === 'conversion-contracts') return 'contracts';
  if (section === 'settings' || section === 'config' || section === 'configuration') return 'settings';
  if (section === 'types' || section === 'type-settings' || section === 'visio-types') return 'types';
  if (section === 'verify' || section === 'verification') return 'verify';
  if (section === 'create-objects' || section === 'create' || section === 'objects') return 'create-objects';
  return 'prepare-template';
}

function sectionFromPath(pathname) {
  const suffix = pathname === UI_PREFIX ? '' : pathname.slice(`${UI_PREFIX}/`.length);
  return normalizeSection(suffix.split('/')[0]);
}

function renderBaaShell({ session, section }) {
  const boot = JSON.stringify({
    section,
    session,
    apiPrefix: API_PREFIX,
    uiPrefix: UI_PREFIX
  });
  return `<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CMDB BAA</title>
  <style>
    :root{color-scheme:light;--bg:#f5f7fa;--panel:#fff;--line:#d8dee6;--text:#1f2933;--muted:#66788a;--accent:#0b6b6f;--accent-soft:#e6f4f1;--danger:#b42318;--ok:#257a45}
    *{box-sizing:border-box}
    body{margin:0;background:var(--bg);color:var(--text);font:13px/1.4 Arial,sans-serif}
    header{min-height:48px;display:flex;align-items:flex-start;justify-content:space-between;gap:12px;padding:8px 16px;border-bottom:1px solid var(--line);background:#fff}
    .brand{display:grid;gap:6px;min-width:0}
    h1{font-size:18px;margin:0} h2{font-size:16px;margin:0 0 10px} h3{font-size:13px;margin:0 0 8px;color:#334e68}
    .session{color:var(--muted);font-size:12px}
    .layout{display:grid;grid-template-columns:260px minmax(0,1fr);gap:14px;padding:14px 16px}
    nav{border:1px solid var(--line);background:#fff;padding:10px;height:calc(100vh - 76px);position:sticky;top:62px}
    .nav-group{margin-bottom:12px}.nav-group.bottom{margin-top:20px}
    .nav-title{font-size:11px;font-weight:bold;color:#52606d;text-transform:uppercase;letter-spacing:.03em;margin:2px 0 6px}
    nav a{display:block;border:1px solid var(--line);background:#f8fafc;color:var(--text);padding:8px 9px;border-radius:4px;text-decoration:none;margin-bottom:7px}
    nav a.child{margin-left:10px}
    nav a.active{background:var(--accent-soft);border-color:#86b7b3;color:#07575b;font-weight:bold}
    main{min-width:0}
    .section{border:1px solid var(--line);background:var(--panel);padding:12px;margin-bottom:12px}
    .toolbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:12px}
    button,a.button{border:1px solid #9fb3c8;background:#fff;color:var(--text);padding:6px 10px;border-radius:4px;cursor:pointer;text-decoration:none;display:inline-block}
    button.primary{background:var(--accent);border-color:var(--accent);color:#fff}
    label{display:grid;gap:4px;color:var(--muted);font-size:12px}
    input,textarea,select{max-width:100%;border:1px solid #bcccdc;border-radius:4px;padding:6px;font:13px Arial,sans-serif;color:var(--text);background:#fff}
    textarea{min-height:160px;font-family:ui-monospace,SFMono-Regular,Consolas,monospace}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px}
    .notice{padding:8px 10px;border:1px solid var(--line);background:#f8fafc;margin:8px 0}.notice.error{border-color:#f0b8b0;color:var(--danger);background:#fff7f5}.notice.ok{border-color:#a7d8b5;color:var(--ok);background:#f4fbf6}
    .muted{color:var(--muted)}
    .table-wrap{overflow:auto;border:1px solid var(--line);background:#fff}.type-table{width:100%;border-collapse:collapse}.type-table th,.type-table td{border-bottom:1px solid var(--line);padding:7px 8px;text-align:left;vertical-align:top}.type-table th{background:#f0f4f8;color:#334e68}.type-key{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:11px;color:var(--muted);overflow-wrap:anywhere}.shape-data{display:flex;gap:5px;flex-wrap:wrap}.sd-pill{border:1px solid var(--line);background:#f8fafc;border-radius:4px;padding:2px 5px;font-size:11px}.file-input{display:none}.file-name{color:var(--muted);font-size:12px}.file-status{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.checksum-status{padding:5px 7px;border:1px solid var(--line);background:#f8fafc;font-size:12px}.checksum-status.ok{border-color:#a7d8b5;color:var(--ok);background:#f4fbf6}.checksum-status.error{border-color:#f0b8b0;color:var(--danger);background:#fff7f5}.checksum-ext{width:110px}.check-label{display:flex;align-items:center;gap:7px;color:var(--text);font-size:13px}.check-label input{width:auto}.column-toggles{display:flex;gap:12px;flex-wrap:wrap;padding:7px 8px;border-bottom:1px solid var(--line);background:#f8fafc}.object-editor{display:grid;grid-template-columns:minmax(220px,320px) minmax(0,1fr);gap:10px;padding:10px;border-bottom:1px solid var(--line);background:#fff}.object-editor select{width:100%;min-height:140px}.object-row{border:1px solid var(--line);background:#f8fafc;margin-bottom:7px}.object-row summary{cursor:pointer;padding:7px 8px}.object-row-body{display:grid;grid-template-columns:minmax(220px,360px) minmax(0,1fr);gap:8px;padding:8px;border-top:1px solid var(--line);background:#fff}.tabs{display:inline-flex;border:1px solid var(--line);background:#fff}.tabs button{border:0;border-right:1px solid var(--line);border-radius:0}.tabs button:last-child{border-right:0}.tabs button.active{background:var(--accent-soft);color:#07575b;font-weight:bold}.right-actions{display:flex;justify-content:flex-end;gap:8px;flex-wrap:wrap;margin-top:10px}
    pre{white-space:pre-wrap;background:#f8fafc;border:1px solid var(--line);padding:8px;overflow:auto}
    @media(max-width:840px){header{align-items:flex-start;flex-direction:column}.layout{grid-template-columns:1fr;padding:10px}nav{position:static;height:auto}.nav-group{margin-bottom:8px}.nav-group.bottom{margin-top:8px}nav a{display:inline-block;margin-right:6px}nav a.child{margin-left:0}}
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <h1>CMDB BAA</h1>
      <div class="file-status" aria-label="Статус файла">
        <span id="checksum-status" class="checksum-status error">Контрольная сумма не проверялась</span>
        <span id="contract-version-status" class="file-name">Версия не выбрана</span>
        <input id="checksum-file" class="file-input" type="file" multiple>
      </div>
    </div>
    <div class="session">${htmlEscape(session.username || '')} / ${htmlEscape(session.role || '')}</div>
  </header>
  <div class="layout">
    <nav aria-label="BAA sections">
      <div class="nav-group">
        <div class="nav-title">Работа с шаблонами</div>
        <a class="child" href="${UI_PREFIX}/contracts" data-section="contracts">Контракты</a>
        <a class="child" href="${UI_PREFIX}/prepare-template" data-section="prepare-template">Подготовить шаблон</a>
      </div>
      <a href="${UI_PREFIX}/verify" data-section="verify">Верифицировать</a>
      <a href="${UI_PREFIX}/create-objects" data-section="create-objects">Создать объекты</a>
      <div class="nav-group bottom">
        <div class="nav-title">Настройки</div>
        <a class="child" href="${UI_PREFIX}/settings" data-section="settings">Общие</a>
        <a class="child" href="${UI_PREFIX}/types" data-section="types">Типы</a>
        <a class="child" href="${UI_PREFIX}/schema" data-section="schema">Схема</a>
      </div>
    </nav>
    <main id="app"><div class="notice">Загрузка...</div></main>
  </div>
  <script>window.CMDBBAA_BOOT=${boot};</script>
  <script>${clientScript()}</script>
</body>
</html>`;
}

function clientScript() {
  return `
(function () {
  'use strict';
  var boot = window.CMDBBAA_BOOT || {};
  var app = document.getElementById('app');
  var labels = {
    schema: 'Схема',
    contracts: 'Контракты',
    settings: 'Общие',
    types: 'Типы',
    'prepare-template': 'Подготовить шаблон',
    verify: 'Верифицировать',
    'create-objects': 'Создать объекты'
  };
  var defaultSettings = {
    checksumExtension: 'sha256',
    verifyChecksumOnPrepare: true
  };
  var defaultSchemaSettings = {
    root: 'BAA',
    parent: '',
    description: 'BAA technical superclass'
  };
  var defaultTypeRules = {
    typeDetection: {
      useVisibleTextAsTypeFactor: true,
      treatGroupsAsTypes: true,
      groupNameDifferentiatesType: true,
      groupCompositionDifferentiatesType: true,
      treatContainersAsTypes: true,
      containerIncludesContent: true
    },
    presentation: {
      keepDecorativeShapesUnchanged: true
    }
  };
  var contractsState = {
    contracts: [],
    versions: []
  };
  function readSettings() {
    var settings = Object.assign({}, defaultSettings);
    try {
      var raw = window.localStorage && window.localStorage.getItem('cmdbaa.settings');
      if (raw) settings = Object.assign(settings, JSON.parse(raw));
    } catch (error) {}
    settings.checksumExtension = String(settings.checksumExtension || 'sha256').trim().replace(/^\\.+/, '') || 'sha256';
    settings.verifyChecksumOnPrepare = settings.verifyChecksumOnPrepare !== false;
    return settings;
  }
  function writeSettings(settings) {
    var next = Object.assign({}, defaultSettings, settings || {});
    next.checksumExtension = String(next.checksumExtension || 'sha256').trim().replace(/^\\.+/, '') || 'sha256';
    next.verifyChecksumOnPrepare = next.verifyChecksumOnPrepare !== false;
    try {
      if (window.localStorage) window.localStorage.setItem('cmdbaa.settings', JSON.stringify(next));
    } catch (error) {}
    return next;
  }
  function normalizeSchemaSettings(settings) {
    var next = Object.assign({}, defaultSchemaSettings, settings || {});
    next.root = String(next.root || 'BAA').trim() || 'BAA';
    next.parent = String(next.parent || '').trim();
    if (next.parent === next.root) next.parent = '';
    next.description = String(next.description || 'BAA technical superclass').trim() || 'BAA technical superclass';
    return next;
  }
  function readSchemaSettings() {
    var settings = Object.assign({}, defaultSchemaSettings);
    try {
      var raw = window.localStorage && window.localStorage.getItem('cmdbaa.schemaSettings');
      if (raw) settings = Object.assign(settings, JSON.parse(raw));
    } catch (error) {}
    return normalizeSchemaSettings(settings);
  }
  function writeSchemaSettings(settings) {
    var next = normalizeSchemaSettings(settings);
    try {
      if (window.localStorage) window.localStorage.setItem('cmdbaa.schemaSettings', JSON.stringify(next));
    } catch (error) {}
    return next;
  }
  function readTypeRules() {
    var rules = JSON.parse(JSON.stringify(defaultTypeRules));
    try {
      var raw = window.localStorage && window.localStorage.getItem('cmdbaa.typeRules');
      if (raw) rules = Object.assign(rules, JSON.parse(raw));
    } catch (error) {}
    rules.typeDetection = Object.assign({}, defaultTypeRules.typeDetection, rules.typeDetection || {});
    rules.presentation = Object.assign({}, defaultTypeRules.presentation, rules.presentation || {});
    return rules;
  }
  function writeTypeRules(rules) {
    var next = {
      typeDetection: Object.assign({}, defaultTypeRules.typeDetection, rules && rules.typeDetection || {}),
      presentation: Object.assign({}, defaultTypeRules.presentation, rules && rules.presentation || {})
    };
    try {
      if (window.localStorage) window.localStorage.setItem('cmdbaa.typeRules', JSON.stringify(next));
    } catch (error) {}
    return next;
  }
  function setActive(section) {
    Array.prototype.forEach.call(document.querySelectorAll('nav a[data-section]'), function (link) {
      link.className = link.getAttribute('data-section') === section ? 'active' : '';
    });
  }
  function api(path, options) {
    return fetch(boot.apiPrefix + path, Object.assign({ credentials: 'include', headers: { Accept: 'application/json' } }, options || {}))
      .then(function (response) { return response.json().then(function (json) { return { response: response, json: json }; }); });
  }
  function renderSchema() {
    var schemaSettings = readSchemaSettings();
    app.innerHTML = [
      '<div class="toolbar"><button class="primary" type="button" data-action="schema-preview">Проверить</button><button type="button" data-action="schema-bootstrap">Создать схему</button><button type="button" data-action="check-session">Проверить сессию</button></div>',
      '<section class="section"><h2>Схема CMDBuild</h2><div class="grid">',
      '<label>Суперкласс проекта<input id="schema-root" value="' + escapeHtml(schemaSettings.root) + '"></label>',
      '<label>Родительский суперкласс<select id="schema-parent"><option value="">Без родителя</option><option value="AA">AA</option></select></label>',
      '<label>Описание<input id="schema-description" value="' + escapeHtml(schemaSettings.description) + '"></label>',
      '</div><p class="muted">Будут проверены и созданы классы BAA, BAAConversionContract и BAAConversionContractVersion.</p></section>',
      '<section class="section"><h3>Результат</h3><pre id="status">Схема еще не проверялась.</pre></section>'
    ].join('');
    var parentSelect = document.getElementById('schema-parent');
    if (parentSelect) parentSelect.value = schemaSettings.parent;
    loadSchemaParents();
  }
  function loadSchemaParents() {
    var select = document.getElementById('schema-parent');
    if (!select) return;
    var selected = select.value || readSchemaSettings().parent || '';
    api('/cmdb/classes').then(function (result) {
      if (!result.response.ok) return;
      var options = ['<option value="">Без родителя</option>'];
      (result.json.data || []).filter(function (item) {
        return item.active !== false && item.prototype && item.name !== (document.getElementById('schema-root') && document.getElementById('schema-root').value || 'BAA');
      }).sort(function (left, right) {
        return String(left.name).localeCompare(String(right.name));
      }).forEach(function (item) {
        options.push('<option value="' + escapeHtml(item.name) + '">' + escapeHtml(item.name + (item.description ? ' - ' + item.description : '')) + '</option>');
      });
      select.innerHTML = options.join('');
      select.value = options.some(function (html) { return html.indexOf('value="' + escapeHtml(selected) + '"') !== -1; }) ? selected : '';
    }).catch(function () {});
  }
  function renderSettings() {
    var settings = readSettings();
    app.innerHTML = [
      '<div class="toolbar"><button class="primary" type="button" data-action="save-settings">Сохранить</button></div>',
      '<section class="section"><h2>Общие настройки</h2><div class="grid">',
      '<label>Расширение файла суммы<input id="settings-checksum-extension" class="checksum-ext" value="' + escapeHtml(settings.checksumExtension) + '"></label>',
      '<label class="check-label"><input id="settings-verify-checksum" type="checkbox"' + (settings.verifyChecksumOnPrepare ? ' checked' : '') + '>Проверять контрольную сумму при подготовке шаблона</label>',
      '</div></section>',
      '<section class="section"><h3>Результат</h3><pre id="status">Настройки загружены.</pre></section>'
    ].join('');
  }
  function renderTypesSettings() {
    var rules = readTypeRules();
    app.innerHTML = [
      '<div class="toolbar"><button class="primary" type="button" data-action="save-type-rules">Сохранить</button></div>',
      '<section class="section"><h2>Распознавание Visio-типов</h2><div class="grid">',
      '<label class="check-label"><input id="rule-use-visible-text" type="checkbox"' + (rules.typeDetection.useVisibleTextAsTypeFactor ? ' checked' : '') + ' data-rule-control="1">Учитывать видимое имя как фактор типа</label>',
      '<label class="check-label"><input id="rule-treat-groups" type="checkbox"' + (rules.typeDetection.treatGroupsAsTypes ? ' checked' : '') + ' data-rule-control="1">Показывать группы как Visio-типы</label>',
      '<label class="check-label"><input id="rule-group-name" type="checkbox"' + (rules.typeDetection.groupNameDifferentiatesType ? ' checked' : '') + ' data-rule-control="1">Различать группы по имени</label>',
      '<label class="check-label"><input id="rule-group-composition" type="checkbox"' + (rules.typeDetection.groupCompositionDifferentiatesType ? ' checked' : '') + ' data-rule-control="1">Различать группы по составу</label>',
      '<label class="check-label"><input id="rule-treat-containers" type="checkbox"' + (rules.typeDetection.treatContainersAsTypes ? ' checked' : '') + ' data-rule-control="1">Считать контейнер отдельным Visio-типом</label>',
      '<label class="check-label"><input id="rule-container-content" type="checkbox"' + (rules.typeDetection.containerIncludesContent ? ' checked' : '') + ' data-rule-control="1">Включать содержимое контейнера в Visio-тип</label>',
      '<label class="check-label"><input id="rule-keep-decorative" type="checkbox"' + (rules.presentation.keepDecorativeShapesUnchanged ? ' checked' : '') + ' data-rule-control="1">Служебное оформление не менять</label>',
      '</div><p class="muted">Эти правила описывают только способ распознавания одинаковых Visio-фигур. Состав CMDB-данных остается частью версии контракта.</p></section>',
      '<section class="section"><h3>Результат</h3><pre id="status">Настройки типов загружены.</pre></section>'
    ].join('');
  }
  function contractsTableHtml(contracts) {
    if (!contracts || !contracts.length) return '<div class="notice">Контракты еще не созданы.</div>';
    return '<div class="table-wrap"><table class="type-table"><thead><tr><th>Код</th><th>Название</th><th>Описание</th><th>Статус</th><th>ID</th><th>Активен</th></tr></thead><tbody>' +
      contracts.map(function (contract) {
        return '<tr><td><strong>' + escapeHtml(contract.code) + '</strong></td><td>' + escapeHtml(contract.name) + '</td><td>' + escapeHtml(contract.description) + '</td><td>' + escapeHtml(contract.status) + '</td><td>' + escapeHtml(contract.id || '') + '</td><td>' + escapeHtml(contract.active === false ? 'нет' : 'да') + '</td></tr>';
      }).join('') +
      '</tbody></table></div>';
  }
  function contractOptionsHtml(contracts) {
    if (!contracts || !contracts.length) return '<option value="">Нет контрактов</option>';
    return contracts.map(function (contract) {
      return '<option value="' + escapeHtml(contract.id || '') + '" data-code="' + escapeHtml(contract.code) + '">' + escapeHtml(contract.code + (contract.name ? ' / ' + contract.name : '')) + '</option>';
    }).join('');
  }
  function versionsTableHtml(versions) {
    if (!versions || !versions.length) return '<div class="notice">Версии контрактов еще не созданы.</div>';
    return '<div class="table-wrap"><table class="type-table"><thead><tr><th>Код</th><th>Контракт</th><th>Версия</th><th>Статус</th><th>Rules checksum</th><th>ID</th></tr></thead><tbody>' +
      versions.map(function (version) {
        return '<tr><td><strong>' + escapeHtml(version.code) + '</strong></td><td>' + escapeHtml(version.contractCode) + '</td><td>' + escapeHtml(version.version) + '</td><td>' + escapeHtml(version.status) + '</td><td class="type-key">' + escapeHtml(version.rulesChecksum) + '</td><td>' + escapeHtml(version.id || '') + '</td></tr>';
      }).join('') +
      '</tbody></table></div>';
  }
  function contractVersionOptionsHtml(versions) {
    if (!versions || !versions.length) return '<option value="">Нет версий</option>';
    return versions.map(function (version) {
      var label = version.contractCode + ' / ' + version.version + ' / ' + version.status;
      return '<option value="' + escapeHtml(version.id || '') + '"' +
        ' data-code="' + escapeHtml(version.code || '') + '"' +
        ' data-contract-id="' + escapeHtml(version.contractId || '') + '"' +
        ' data-contract-code="' + escapeHtml(version.contractCode || '') + '"' +
        ' data-version="' + escapeHtml(version.version || '') + '"' +
        ' data-status="' + escapeHtml(version.status || '') + '"' +
        ' data-checksum="' + escapeHtml(version.rulesChecksum || '') + '"' +
        ' data-rules-json="' + escapeHtml(version.rulesJson || '') + '">' +
        escapeHtml(label) +
        '</option>';
    }).join('');
  }
  function rulesFromControls() {
    if (!document.getElementById('rule-use-visible-text')) return readTypeRules();
    return {
      typeDetection: {
        useVisibleTextAsTypeFactor: Boolean(document.getElementById('rule-use-visible-text') && document.getElementById('rule-use-visible-text').checked),
        treatGroupsAsTypes: Boolean(document.getElementById('rule-treat-groups') && document.getElementById('rule-treat-groups').checked),
        groupNameDifferentiatesType: Boolean(document.getElementById('rule-group-name') && document.getElementById('rule-group-name').checked),
        groupCompositionDifferentiatesType: Boolean(document.getElementById('rule-group-composition') && document.getElementById('rule-group-composition').checked),
        treatContainersAsTypes: Boolean(document.getElementById('rule-treat-containers') && document.getElementById('rule-treat-containers').checked),
        containerIncludesContent: Boolean(document.getElementById('rule-container-content') && document.getElementById('rule-container-content').checked)
      },
      presentation: {
        keepDecorativeShapesUnchanged: Boolean(document.getElementById('rule-keep-decorative') && document.getElementById('rule-keep-decorative').checked)
      }
    };
  }
  function updateContractSelect() {
    updatePrepareContractVersionSelect();
  }
  function updatePrepareContractVersionSelect() {
    var select = document.getElementById('prepare-contract-version');
    if (select) select.innerHTML = contractVersionOptionsHtml(contractsState.versions);
    var versions = (contractsState.versions || []).filter(function (version) {
      return (prepareState.contractVersionId && version.id === prepareState.contractVersionId) ||
        (prepareState.contractMetadata && prepareState.contractMetadata.contractVersionCode && version.code === prepareState.contractMetadata.contractVersionCode);
    }).sort(function (left, right) {
      return Number(right.version || 0) - Number(left.version || 0);
    });
    if (versions.length) {
      prepareState.contractVersionId = versions[0].id || '';
    }
    updatePrepareContractVersionSummary();
  }
  function updatePrepareContractVersionSummary() {
    var target = document.getElementById('contract-version-status');
    if (!target) return;
    var version = selectedPrepareContractVersion();
    if (version) {
      target.textContent = 'Версия: ' + version.contractCode + ' / ' + version.version + ' / ' + version.code;
      return;
    }
    if (prepareState.contractMetadata && (prepareState.contractMetadata.contractVersionCode || prepareState.contractMetadata.contractVersionId)) {
      target.textContent = 'Версия: ' + (prepareState.contractMetadata.contractVersionCode || prepareState.contractMetadata.contractVersionId);
      return;
    }
    target.textContent = 'Версия не выбрана';
  }
  function selectedPrepareContractVersion() {
    var select = document.getElementById('prepare-contract-version');
    if (!select) {
      var selected = (contractsState.versions || []).filter(function (version) {
        return version.id === prepareState.contractVersionId;
      })[0];
      if (!selected) return null;
      return {
        id: selected.id || '',
        code: selected.code || '',
        contractId: selected.contractId || '',
        contractCode: selected.contractCode || '',
        version: selected.version || '',
        status: selected.status || '',
        rulesChecksum: selected.rulesChecksum || '',
        rulesJson: selected.rulesJson || '',
        preparedBy: boot.session && boot.session.username || ''
      };
    }
    if (!select.value) return null;
    prepareState.contractVersionId = select.value;
    var option = select.options[select.selectedIndex];
    if (!option) return null;
    return {
      id: select.value,
      code: option.getAttribute('data-code') || '',
      contractId: option.getAttribute('data-contract-id') || '',
      contractCode: option.getAttribute('data-contract-code') || '',
      version: option.getAttribute('data-version') || '',
      status: option.getAttribute('data-status') || '',
        rulesChecksum: option.getAttribute('data-checksum') || '',
      rulesJson: option.getAttribute('data-rules-json') || '',
      preparedBy: boot.session && boot.session.username || ''
    };
  }
  function selectedPrepareContract() {
    return null;
  }
  function loadContractVersions() {
    var target = document.getElementById('versions-list');
    if (target) target.innerHTML = '<div class="notice">Загружаю версии...</div>';
    return api('/contract-versions').then(function (result) {
      contractsState.versions = result.response.ok ? (result.json.data || []) : [];
      if (target) target.innerHTML = result.response.ok ? versionsTableHtml(contractsState.versions) : '<div class="notice error">' + escapeHtml(result.json.message || 'Не удалось загрузить версии.') + '</div>';
      updatePrepareContractVersionSelect();
    }).catch(function (error) {
      if (target) target.innerHTML = '<div class="notice error">' + escapeHtml(error && error.message ? error.message : String(error)) + '</div>';
    });
  }
  function loadContracts() {
    var target = document.getElementById('contracts-list');
    if (target) target.innerHTML = '<div class="notice">Загружаю контракты...</div>';
    return api('/contracts').then(function (result) {
      contractsState.contracts = result.response.ok ? (result.json.data || []) : [];
      if (target) target.innerHTML = result.response.ok ? contractsTableHtml(result.json.data || []) : '<div class="notice error">' + escapeHtml(result.json.message || 'Не удалось загрузить контракты.') + '</div>';
      updateContractSelect();
    }).catch(function (error) {
      if (target) target.innerHTML = '<div class="notice error">' + escapeHtml(error && error.message ? error.message : String(error)) + '</div>';
    });
  }
  function renderContracts() {
    app.innerHTML = [
      '<div class="toolbar"><button class="primary" type="button" data-action="create-contract">Создать контракт</button><button type="button" data-action="reload-contracts">Обновить</button></div>',
      '<section class="section"><h2>Контракты конвертации</h2><div class="grid">',
      '<label>Код контракта<input id="contract-code" value="default-contract"></label>',
      '<label>Название<input id="contract-name" value="Default contract"></label>',
      '<label>Описание<input id="contract-description" value="Default conversion contract"></label>',
      '<label>Статус<select id="contract-status"><option value="Draft">Draft</option><option value="Active">Active</option><option value="Archived">Archived</option></select></label>',
      '</div><p class="muted">Здесь создается объект BAAConversionContract: код, название, описание и статус. Версии создаются автоматически при обогащении шаблона.</p></section>',
      '<section class="section"><h3>Список</h3><div id="contracts-list" class="notice">Контракты еще не загружались.</div></section>',
      '<section class="section"><div class="toolbar"><h3>Версии</h3><button type="button" data-action="reload-contract-versions">Обновить версии</button></div><p class="muted">Версии создаются автоматически при обогащении шаблона, если расширился набор Visio-типов.</p><div id="versions-list" class="notice">Версии еще не загружались.</div></section>'
    ].join('');
    loadContracts().then(loadContractVersions);
  }
  function renderPrepare() {
    function tabButton(tab, label) {
      return '<button' + (prepareState.activeTab === tab ? ' class="active"' : '') + ' type="button" data-action="prepare-tab" data-tab="' + tab + '">' + label + '</button>';
    }
    app.innerHTML = [
      '<div class="toolbar"><button class="primary" type="button" data-action="choose-vsdx">Загрузить и разобрать vhdx</button><button type="button" data-action="choose-checksum">Загрузить файл контрольной суммы</button><input id="vsdx-file" class="file-input" type="file" multiple></div>',
      '<section class="section"><div class="toolbar"><div class="tabs">' + tabButton('types', 'Типы') + tabButton('shapes', 'Фигуры') + tabButton('enrich', 'Обогатить') + '</div></div><div id="prepare-view" class="notice">Загрузите .vsdx для извлечения типов фигур.</div></section>'
    ].join('');
    updatePrepareContractVersionSummary();
    loadContractVersions();
    loadCmdbClassesForPrepare();
    renderChecksumStatus(prepareState.checksum);
    renderPrepareData();
  }
  function renderVerify() {
    app.innerHTML = [
      '<div class="toolbar"><button class="primary" type="button" data-action="verify">Запустить проверку</button><button type="button" data-action="check-session">Проверить сессию</button></div>',
      '<section class="section"><h2>Верифицировать</h2><label>Данные для проверки<textarea id="verify-json">{\\n  "templateCode": "",\\n  "contractVersion": {\\n    "id": "",\\n    "code": "",\\n    "rulesChecksum": ""\\n  },\\n  "input": {}\\n}</textarea></label></section>',
      '<section class="section"><h3>Результат</h3><pre id="status">Проверка еще не запускалась.</pre></section>'
    ].join('');
  }
  function renderCreate() {
    app.innerHTML = [
      '<div class="toolbar"><button class="primary" type="button" data-action="create-objects">Создать объекты</button><button type="button" data-action="check-session">Проверить сессию</button></div>',
      '<section class="section"><h2>Создать объекты</h2><label>Пакет создания<textarea id="create-json">{\\n  "templateCode": "",\\n  "contractVersion": {\\n    "id": "",\\n    "code": "",\\n    "rulesChecksum": ""\\n  },\\n  "objects": []\\n}</textarea></label></section>',
      '<section class="section"><h3>Результат</h3><pre id="status">Создание еще не запускалось.</pre></section>'
    ].join('');
  }
  function showStatus(value, ok) {
    var target = document.getElementById('status');
    if (!target) return;
    target.className = ok === false ? 'notice error' : ok === true ? 'notice ok' : 'notice';
    target.textContent = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  }
  var prepareState = {
    file: null,
    fileName: '',
    fileBase64: '',
    checksumFile: null,
    checksumFileName: '',
    checksumText: '',
    contractVersionId: '',
    contractMetadata: null,
    types: [],
    aggregates: [],
    selectedTypeKey: '',
    cmdbClasses: [],
    classAssignments: {},
    activeTab: 'types',
    columns: {
      kind: false,
      cmdb: false,
      page: false,
      shapeId: false,
      count: false,
      pages: false,
      connection: true,
      shapeData: true
    },
    checksum: {
      checked: false,
      ok: false,
      message: 'Контрольная сумма не проверялась'
    }
  };
  function persistPrepareState() {
    try {
      if (!window.sessionStorage) return;
      window.sessionStorage.setItem('cmdbaa.prepareState', JSON.stringify({
        fileName: prepareState.fileName,
        fileBase64: prepareState.fileBase64,
        checksumFileName: prepareState.checksumFileName,
        checksumText: prepareState.checksumText,
        contractVersionId: prepareState.contractVersionId,
        contractMetadata: prepareState.contractMetadata,
        types: prepareState.types,
        aggregates: prepareState.aggregates,
        selectedTypeKey: prepareState.selectedTypeKey,
        classAssignments: prepareState.classAssignments,
        activeTab: prepareState.activeTab,
        columns: prepareState.columns,
        checksum: prepareState.checksum
      }));
    } catch (error) {}
  }
  function hydratePrepareState() {
    try {
      var raw = window.sessionStorage && window.sessionStorage.getItem('cmdbaa.prepareState');
      if (!raw) return;
      var stored = JSON.parse(raw);
      prepareState.fileName = stored.fileName || '';
      prepareState.fileBase64 = stored.fileBase64 || '';
      prepareState.checksumFileName = stored.checksumFileName || '';
      prepareState.checksumText = stored.checksumText || '';
      prepareState.contractVersionId = stored.contractVersionId || '';
      prepareState.contractMetadata = stored.contractMetadata || null;
      prepareState.types = Array.isArray(stored.types) ? stored.types : [];
      prepareState.aggregates = Array.isArray(stored.aggregates) ? stored.aggregates : [];
      prepareState.selectedTypeKey = stored.selectedTypeKey || '';
      prepareState.classAssignments = stored.classAssignments || {};
      prepareState.activeTab = stored.activeTab || 'types';
      prepareState.columns = Object.assign({}, prepareState.columns, stored.columns || {});
      prepareState.checksum = Object.assign({}, prepareState.checksum, stored.checksum || {});
    } catch (error) {}
  }
  function escapeHtml(value) {
    return String(value === undefined || value === null ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }
  function shapeDataHtml(rows) {
    if (!rows || !rows.length) return '<span class="muted">нет</span>';
    return '<div class="shape-data">' + rows.map(function (row) {
      var title = row.label && row.label !== row.name ? row.name + ' / ' + row.label : row.name;
      var suffix = row.value ? ': ' + row.value : '';
      return '<span class="sd-pill">' + escapeHtml(title + suffix) + '</span>';
    }).join('') + '</div>';
  }
  function connectionHtml(connection) {
    if (!connection) return '<span class="muted">нет</span>';
    return '<div class="shape-data">' +
      '<span class="sd-pill">status: ' + escapeHtml(connection.status || '') + '</span>' +
      '<span class="sd-pill">source: ' + escapeHtml(connection.sourceShapeId || '') + (connection.sourceKind ? ' / ' + escapeHtml(connection.sourceKind) : '') + '</span>' +
      '<span class="sd-pill">destination: ' + escapeHtml(connection.destinationShapeId || '') + (connection.destinationKind ? ' / ' + escapeHtml(connection.destinationKind) : '') + '</span>' +
      (connection.issue ? '<span class="sd-pill">issue: ' + escapeHtml(connection.issue) + '</span>' : '') +
      '</div>';
  }
  function shapeInstanceKey(shape) {
    return String(shape && shape.page || '') + ':' + String(shape && shape.shapeId || '');
  }
  function contextPathText(shape) {
    var path = shape && shape.contextPath || [];
    if (!path.length) return 'без группы/контейнера';
    return path.map(function (item) {
      return (item.kind === 'container' ? 'Контейнер' : 'Группа') + ' ' + (item.label || item.shapeId || '');
    }).join(' / ');
  }
  function classDatalistHtml() {
    return '<datalist id="cmdb-class-list">' + (prepareState.cmdbClasses || []).map(function (item) {
      return '<option value="' + escapeHtml(item.name) + '">' + escapeHtml(item.description || item.name) + '</option>';
    }).join('') + '</datalist>';
  }
  function prepareObjectEditorHtml(types) {
    var candidates = (prepareState.aggregates || []).filter(function (aggregate) {
      return aggregate.atomRoles && aggregate.atomRoles.length && aggregate.instances && aggregate.instances.length;
    });
    if (!candidates.length) return '<div class="notice">Нет агрегированных типов для назначения CMDB-классов.</div>';
    if (!prepareState.selectedTypeKey || !candidates.some(function (aggregate) { return aggregate.aggregateTypeKey === prepareState.selectedTypeKey; })) {
      prepareState.selectedTypeKey = candidates[0].aggregateTypeKey;
    }
    var selected = candidates.filter(function (aggregate) { return aggregate.aggregateTypeKey === prepareState.selectedTypeKey; })[0] || candidates[0];
    var left = '<select id="prepare-type-selector" size="' + Math.min(Math.max(candidates.length, 4), 12) + '">' + candidates.map(function (aggregate) {
      return '<option value="' + escapeHtml(aggregate.aggregateTypeKey) + '"' + (aggregate.aggregateTypeKey === selected.aggregateTypeKey ? ' selected' : '') + '>' + escapeHtml(aggregate.label + ' (' + aggregate.instances.length + ')') + '</option>';
    }).join('') + '</select>';
    var roles = (selected.atomRoles || []).map(function (role) {
      var key = selected.aggregateTypeKey + '::' + role.roleKey;
      var value = prepareState.classAssignments[key] || '';
      var instances = (selected.instances || []).map(function (instance) {
        var atom = (instance.atoms || []).filter(function (item) { return item.roleKey === role.roleKey; })[0];
        if (!atom) return '';
        return '<details class="object-row"><summary><strong>' + escapeHtml(atom.label) + '</strong><span class="muted"> ' + escapeHtml(atom.page + ' / Shape ' + atom.shapeId) + '</span></summary>' +
          '<div class="object-row-body"><div>' + shapeDataHtml(atom.shapeData) + '</div></div></details>';
      }).join('');
      return '<details class="object-row" open><summary><strong>' + escapeHtml(role.label) + '</strong><span class="muted"> / роль атомарной фигуры</span></summary>' +
        '<div class="object-row-body"><label>CMDB-классы<input data-object-class="' + escapeHtml(key) + '" list="cmdb-class-list" value="' + escapeHtml(value) + '" placeholder="Server, Application"></label>' +
        '<div>' + instances + '</div></div></details>';
    }).join('');
    return '<div class="object-editor"><div class="object-editor-left"><h3>Агрегированные типы</h3>' + left + '</div><div class="object-editor-right"><h3>Атомарные фигуры</h3>' + classDatalistHtml() + roles + '</div></div>';
  }
  function prepareColumnToggleHtml() {
    var columns = prepareState.columns || {};
    var options = prepareState.activeTab === 'shapes'
      ? [
        ['kind', 'Вид'],
        ['cmdb', 'CMDB'],
        ['page', 'Страница'],
        ['shapeId', 'Shape ID'],
        ['connection', 'Связь'],
        ['shapeData', 'Shape Data']
      ]
      : [
        ['count', 'Фигур'],
        ['pages', 'Страницы'],
        ['shapeData', 'Shape Data']
      ];
    return '<div class="column-toggles">' + options.map(function (item) {
      return '<label class="check-label"><input type="checkbox" data-prepare-column="' + escapeHtml(item[0]) + '"' + (columns[item[0]] ? ' checked' : '') + '>' + escapeHtml(item[1]) + '</label>';
    }).join('') + '</div>';
  }
  function renderPrepareData() {
    var target = document.getElementById('prepare-view');
    if (!target) return;
    var types = prepareState.types || [];
    var hasContract = Boolean(prepareState.contractVersionId || prepareState.contractMetadata && (prepareState.contractMetadata.contractVersionId || prepareState.contractMetadata.contractVersionCode));
    var contractWarning = hasContract ? '' : '<div class="notice">Контракт не выбран. Для нового шаблона привяжите контракт к конкретному объекту в редакторе; для уже версионированного VSDX контракт читается из файла.</div>';
    if (!types.length) {
      target.className = 'notice';
      target.textContent = 'Загрузите .vsdx для извлечения типов фигур.';
      return;
    }
    target.className = 'table-wrap';
    if (prepareState.activeTab === 'enrich') {
      target.innerHTML = contractWarning + checksumWarningHtml() + prepareObjectEditorHtml(types) + '<div class="right-actions"><button class="primary" type="button" data-action="enrich-vsdx">ОК</button></div>';
      return;
    }
    if (prepareState.activeTab === 'shapes') {
      var rows = [];
      types.forEach(function (type) {
        (type.examples || []).forEach(function (shape) {
          var kind = shape.kind || type.kind || '';
          var eligible = shape.eligibleForCmdb === false || type.eligibleForCmdb === false ? 'нет' : 'да';
          var cells = ['<td><strong>' + escapeHtml(type.label) + '</strong><div class="type-key">' + escapeHtml(type.typeKey) + '</div></td>'];
          if (prepareState.columns.kind) cells.push('<td>' + escapeHtml(kind) + '</td>');
          if (prepareState.columns.cmdb) cells.push('<td>' + escapeHtml(eligible) + '</td>');
          if (prepareState.columns.page) cells.push('<td>' + escapeHtml(shape.page) + '</td>');
          if (prepareState.columns.shapeId) cells.push('<td>' + escapeHtml(shape.shapeId) + '</td>');
          if (prepareState.columns.connection) cells.push('<td>' + connectionHtml(shape.connection) + '</td>');
          if (prepareState.columns.shapeData) cells.push('<td>' + shapeDataHtml(shape.shapeData) + '</td>');
          rows.push('<tr>' + cells.join('') + '</tr>');
        });
      });
      var headers = ['<th>Тип</th>'];
      if (prepareState.columns.kind) headers.push('<th>Вид</th>');
      if (prepareState.columns.cmdb) headers.push('<th>CMDB</th>');
      if (prepareState.columns.page) headers.push('<th>Страница</th>');
      if (prepareState.columns.shapeId) headers.push('<th>Shape ID</th>');
      if (prepareState.columns.connection) headers.push('<th>Связь</th>');
      if (prepareState.columns.shapeData) headers.push('<th>Shape Data</th>');
      target.innerHTML = contractWarning + checksumWarningHtml() + prepareColumnToggleHtml() + '<table class="type-table"><thead><tr>' + headers.join('') + '</tr></thead><tbody>' + rows.join('') + '</tbody></table>';
      return;
    }
    var typeHeaders = ['<th>Тип</th>'];
    if (prepareState.columns.count) typeHeaders.push('<th>Фигур</th>');
    if (prepareState.columns.pages) typeHeaders.push('<th>Страницы</th>');
    if (prepareState.columns.shapeData) typeHeaders.push('<th>Shape Data</th>');
    target.innerHTML = [
      contractWarning,
      checksumWarningHtml(),
      prepareColumnToggleHtml(),
      '<table class="type-table"><thead><tr>' + typeHeaders.join('') + '</tr></thead><tbody>',
      types.map(function (type) {
        var eligible = type.eligibleForCmdb === false ? ' / CMDB: нет' : ' / CMDB: да';
        var cells = ['<td><strong>' + escapeHtml(type.label) + '</strong><div class="muted">' + escapeHtml(type.kind) + escapeHtml(eligible) + (type.masterName ? ' / ' + escapeHtml(type.masterName) : '') + '</div><div class="type-key">' + escapeHtml(type.typeKey) + '</div></td>'];
        if (prepareState.columns.count) cells.push('<td>' + escapeHtml(type.count) + '</td>');
        if (prepareState.columns.pages) cells.push('<td>' + escapeHtml((type.pages || []).join(', ')) + '</td>');
        if (prepareState.columns.shapeData) cells.push('<td>' + shapeDataHtml(type.shapeData) + '</td>');
        return '<tr data-type-key="' + escapeHtml(type.typeKey) + '">' + cells.join('') + '</tr>';
      }).join(''),
      '</tbody></table>'
    ].join('');
  }
  function selectedFile() {
    return prepareState.file;
  }
  function fileToBase64(file) {
    return file.arrayBuffer().then(function (buffer) {
      var bytes = new Uint8Array(buffer);
      var binary = '';
      for (var index = 0; index < bytes.length; index += 1) binary += String.fromCharCode(bytes[index]);
      return btoa(binary);
    });
  }
  function expectedChecksumName() {
    var file = selectedFile();
    var ext = readSettings().checksumExtension;
    return prepareState.fileName ? (prepareState.fileName + '.' + ext) : file ? (file.name + '.' + ext) : '';
  }
  function selectedChecksumFile() {
    return prepareState.checksumFile;
  }
  function isVsdxFile(file) {
    var name = file && file.name ? String(file.name).toLowerCase() : '';
    var type = file && file.type ? String(file.type).toLowerCase() : '';
    return /\\.vsdx$/.test(name) || type.indexOf('visio') !== -1;
  }
  function syncFileStatus() {
  }
  function acceptProvidedFiles(fileList) {
    var files = Array.prototype.slice.call(fileList || []);
    if (!files.length) return;
    Promise.all(files.map(function (file) {
      if (isVsdxFile(file)) {
        prepareState.file = file;
        prepareState.fileName = file.name || 'template.vsdx';
        return fileToBase64(file).then(function (base64) {
          prepareState.fileBase64 = base64;
        });
      }
      prepareState.checksumFile = file;
      prepareState.checksumFileName = file.name || '';
      return file.text().then(function (text) {
        prepareState.checksumText = text;
      });
    })).then(function () {
      syncFileStatus();
      persistPrepareState();
      if (prepareState.fileBase64) {
        inspectVsdx();
        return;
      }
      renderChecksumStatus({
        checked: false,
        ok: false,
        status: 'waiting_vsdx',
        message: prepareState.checksumText ? 'Контрольная сумма не проверялась: ожидается VSDX файл.' : 'Контрольная сумма не проверялась'
      });
    }).catch(function (error) {
      renderChecksumStatus({
        checked: false,
        ok: false,
        status: 'read_failed',
        message: error && error.message ? error.message : String(error)
      });
    });
  }
  function renderChecksumStatus(result) {
    prepareState.checksum = result || prepareState.checksum;
    persistPrepareState();
    var target = document.getElementById('checksum-status');
    if (!target) return;
    target.className = 'checksum-status ' + (prepareState.checksum && prepareState.checksum.ok ? 'ok' : 'error');
    target.textContent = prepareState.checksum && prepareState.checksum.message || 'Контрольная сумма не проверялась';
  }
  function checksumWarningHtml() {
    return '';
  }
  function mappingFromTable() {
    return Object.assign({}, prepareState.classAssignments || {});
  }
  function loadCmdbClassesForPrepare() {
    return api('/cmdb/classes').then(function (result) {
      prepareState.cmdbClasses = result.response.ok ? (result.json.data || []).filter(function (item) { return item.active !== false && !item.prototype; }) : [];
      renderPrepareData();
    }).catch(function () {});
  }
  function payloadHasContractVersion(payload) {
    var version = payload && payload.contractVersion;
    return Boolean(version && version.id && version.code && version.rulesChecksum);
  }
  function inspectVsdx() {
    var file = selectedFile();
    if (!file && !prepareState.fileBase64) {
      renderNotice('Выберите .vsdx файл.', false);
      return;
    }
    if (file) prepareState.fileName = file.name || prepareState.fileName || 'template.vsdx';
    var settings = readSettings();
    syncFileStatus();
    if (!settings.verifyChecksumOnPrepare) {
      renderChecksumStatus({
        checked: false,
        ok: false,
        status: 'disabled',
        message: 'Контрольная сумма не проверялась: проверка отключена в настройках.'
      });
    }
    renderNotice('Разбираю VSDX...', null);
    (prepareState.fileBase64 ? Promise.resolve(prepareState.fileBase64) : fileToBase64(file).then(function (base64) {
      prepareState.fileBase64 = base64;
      return base64;
    })).then(function (base64) {
      return api('/vsdx/inspect', {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'content-type': 'application/json'
        },
        body: JSON.stringify({
          filename: prepareState.fileName || file && file.name || 'template.vsdx',
          fileBase64: base64,
          checksumFilename: settings.verifyChecksumOnPrepare ? (prepareState.checksumFileName || expectedChecksumName()) : '',
          checksumExtension: settings.verifyChecksumOnPrepare ? settings.checksumExtension : '',
          checksumText: settings.verifyChecksumOnPrepare ? prepareState.checksumText : '',
          schema: readSchemaSettings(),
          typeRules: readTypeRules()
        })
      });
    }).then(function (result) {
      prepareState.types = result.json.types || [];
      prepareState.aggregates = result.json.aggregates || [];
      prepareState.contractMetadata = result.json.contractMetadata || null;
      prepareState.contractVersionId = prepareState.contractMetadata && prepareState.contractMetadata.contractVersionId || '';
      if (!prepareState.selectedTypeKey && prepareState.aggregates.length) prepareState.selectedTypeKey = prepareState.aggregates[0].aggregateTypeKey || '';
      updatePrepareContractVersionSummary();
      renderChecksumStatus(settings.verifyChecksumOnPrepare ? (result.json.checksum || {
        checked: false,
        ok: false,
        message: 'Контрольная сумма не проверялась'
      }) : {
        checked: false,
        ok: false,
        status: 'disabled',
        message: 'Контрольная сумма не проверялась: проверка отключена в настройках.'
      });
      persistPrepareState();
      renderPrepareData();
      if (!result.response.ok) renderNotice(result.json, false);
    }).catch(function (error) {
      renderNotice(error && error.message ? error.message : String(error), false);
    });
  }
  function renderNotice(message, ok) {
    var target = document.getElementById('prepare-view');
    if (!target) return;
    target.className = ok === false ? 'notice error' : ok === true ? 'notice ok' : 'notice';
    target.textContent = typeof message === 'string' ? message : JSON.stringify(message, null, 2);
  }
  function enrichVsdx() {
    var file = selectedFile();
    if (!file && !prepareState.fileBase64) {
      renderNotice('Выберите .vsdx файл.', false);
      return;
    }
    renderNotice('Обогащаю VSDX...', null);
    (prepareState.fileBase64 ? Promise.resolve(prepareState.fileBase64) : fileToBase64(file).then(function (base64) {
      prepareState.fileBase64 = base64;
      return base64;
    })).then(function (base64) {
      return api('/vsdx/enrich', {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'content-type': 'application/json'
        },
        body: JSON.stringify({
          filename: prepareState.fileName || file && file.name || 'template.vsdx',
          fileBase64: base64,
          aggregateClassMap: mappingFromTable(),
          schema: readSchemaSettings(),
          typeRules: readTypeRules(),
          preparedBy: boot.session && boot.session.username || ''
        })
      });
    }).then(function (result) {
      if (!result.response.ok) {
        renderNotice(result.json, false);
        return;
      }
      var binary = atob(result.json.fileBase64 || '');
      var bytes = new Uint8Array(binary.length);
      for (var index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
      var blob = new Blob([bytes], { type: 'application/vnd.ms-visio.drawing' });
      var url = URL.createObjectURL(blob);
      var link = document.createElement('a');
      link.href = url;
      link.download = result.json.filename || 'enriched.vsdx';
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
      prepareState.contractVersionId = result.json.contractVersion && result.json.contractVersion.id || prepareState.contractVersionId;
      loadContractVersions();
      persistPrepareState();
      renderNotice('Файл обогащен и загружен. Версия: ' + (result.json.contractVersion && result.json.contractVersion.code || ''), true);
    }).catch(function (error) {
      renderNotice(error && error.message ? error.message : String(error), false);
    });
  }
  function render(section) {
    setActive(section);
    if (section === 'schema') renderSchema();
    else if (section === 'contracts') renderContracts();
    else if (section === 'settings') renderSettings();
    else if (section === 'types') renderTypesSettings();
    else if (section === 'verify') renderVerify();
    else if (section === 'create-objects') renderCreate();
    else renderPrepare();
    if (section !== 'contracts' && section !== 'prepare-template') loadContractVersions();
  }
  document.addEventListener('click', function (event) {
    var button = event.target.closest('button[data-action]');
    if (!button) return;
    var action = button.getAttribute('data-action');
    if (action === 'check-session') {
      api('/session').then(function (result) { showStatus(result.json, result.response.ok); });
      return;
    }
    if (action === 'schema-preview' || action === 'schema-bootstrap') {
      var parentSelect = document.getElementById('schema-parent');
      var rootValue = document.getElementById('schema-root') && document.getElementById('schema-root').value || 'BAA';
      var parentValue = parentSelect ? parentSelect.value : '';
      if (parentValue === rootValue) parentValue = '';
      var payload = {
        root: rootValue,
        parent: parentValue,
        description: document.getElementById('schema-description') && document.getElementById('schema-description').value || 'BAA technical superclass'
      };
      payload = writeSchemaSettings(payload);
      api(action === 'schema-bootstrap' ? '/schema/bootstrap' : '/schema/preview', {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'content-type': 'application/json'
        },
        body: JSON.stringify(payload)
      }).then(function (result) { showStatus(result.json, result.response.ok); })
        .catch(function (error) { showStatus(error && error.message ? error.message : String(error), false); });
      return;
    }
    if (action === 'save-settings') {
      var settings = writeSettings({
        checksumExtension: document.getElementById('settings-checksum-extension') && document.getElementById('settings-checksum-extension').value || 'sha256',
        verifyChecksumOnPrepare: Boolean(document.getElementById('settings-verify-checksum') && document.getElementById('settings-verify-checksum').checked)
      });
      showStatus({
        success: true,
        checksumExtension: settings.checksumExtension,
        verifyChecksumOnPrepare: settings.verifyChecksumOnPrepare
      }, true);
      return;
    }
    if (action === 'save-type-rules') {
      var rules = writeTypeRules(rulesFromControls());
      showStatus({
        success: true,
        rules: rules
      }, true);
      return;
    }
    if (action === 'reload-contracts') {
      loadContracts().then(loadContractVersions);
      return;
    }
    if (action === 'reload-contract-versions') {
      loadContractVersions();
      return;
    }
    if (action === 'create-contract') {
      var payload = {
        code: document.getElementById('contract-code') && document.getElementById('contract-code').value || '',
        name: document.getElementById('contract-name') && document.getElementById('contract-name').value || '',
        description: document.getElementById('contract-description') && document.getElementById('contract-description').value || '',
        status: document.getElementById('contract-status') && document.getElementById('contract-status').value || 'Draft',
        schema: readSchemaSettings()
      };
      api('/contracts', {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'content-type': 'application/json'
        },
        body: JSON.stringify(payload)
      }).then(function (result) {
        if (!result.response.ok) {
          var target = document.getElementById('contracts-list');
          if (target) target.innerHTML = '<div class="notice error">' + escapeHtml(result.json.message || 'Не удалось создать контракт.') + '</div>';
          return;
        }
        loadContracts().then(loadContractVersions);
      }).catch(function (error) {
        var target = document.getElementById('contracts-list');
        if (target) target.innerHTML = '<div class="notice error">' + escapeHtml(error && error.message ? error.message : String(error)) + '</div>';
      });
      return;
    }
    if (action === 'verify') {
      try {
        var verifyPayload = JSON.parse(document.getElementById('verify-json') && document.getElementById('verify-json').value || '{}');
        if (!payloadHasContractVersion(verifyPayload)) {
          showStatus('Валидация невозможна: payload должен содержать contractVersion.id, contractVersion.code и contractVersion.rulesChecksum.', false);
          return;
        }
        showStatus('Валидация по контракту будет реализована следующим шагом.', true);
      } catch (error) {
        showStatus(error && error.message ? error.message : String(error), false);
      }
      return;
    }
    if (action === 'create-objects') {
      try {
        var createPayload = JSON.parse(document.getElementById('create-json') && document.getElementById('create-json').value || '{}');
        if (!payloadHasContractVersion(createPayload)) {
          showStatus('Создание объектов невозможно: payload должен содержать contractVersion.id, contractVersion.code и contractVersion.rulesChecksum.', false);
          return;
        }
        showStatus('Создание объектов по контракту будет реализовано следующим шагом.', true);
      } catch (error) {
        showStatus(error && error.message ? error.message : String(error), false);
      }
      return;
    }
    if (action === 'inspect-vsdx') {
      inspectVsdx();
      return;
    }
    if (action === 'choose-vsdx') {
      var input = document.getElementById('vsdx-file');
      if (input) input.click();
      return;
    }
    if (action === 'choose-checksum') {
      var checksumInput = document.getElementById('checksum-file');
      if (checksumInput) checksumInput.click();
      return;
    }
    if (action === 'prepare-tab') {
      prepareState.activeTab = button.getAttribute('data-tab') || 'types';
      persistPrepareState();
      Array.prototype.forEach.call(document.querySelectorAll('button[data-action="prepare-tab"]'), function (item) {
        item.className = item === button ? 'active' : '';
      });
      renderPrepareData();
      return;
    }
    if (action === 'enrich-vsdx') {
      enrichVsdx();
      return;
    }
    showStatus('Backend action "' + action + '" is reserved for the next implementation step.', true);
  });
  document.addEventListener('change', function (event) {
    if (event.target && (event.target.id === 'vsdx-file' || event.target.id === 'checksum-file')) {
      acceptProvidedFiles(event.target.files);
      event.target.value = '';
      return;
    }
    if (event.target && (event.target.id === 'settings-checksum-extension' || event.target.id === 'settings-verify-checksum')) {
      writeSettings({
        checksumExtension: document.getElementById('settings-checksum-extension') && document.getElementById('settings-checksum-extension').value || 'sha256',
        verifyChecksumOnPrepare: Boolean(document.getElementById('settings-verify-checksum') && document.getElementById('settings-verify-checksum').checked)
      });
    }
    if (event.target && event.target.id === 'schema-root') {
      loadSchemaParents();
    }
    if (event.target && (event.target.id === 'schema-root' || event.target.id === 'schema-parent' || event.target.id === 'schema-description')) {
      var schemaRoot = document.getElementById('schema-root') && document.getElementById('schema-root').value || 'BAA';
      var schemaParent = document.getElementById('schema-parent') && document.getElementById('schema-parent').value || '';
      if (schemaParent === schemaRoot) schemaParent = '';
      writeSchemaSettings({
        root: schemaRoot,
        parent: schemaParent,
        description: document.getElementById('schema-description') && document.getElementById('schema-description').value || 'BAA technical superclass'
      });
    }
    if (event.target && event.target.getAttribute('data-prepare-column')) {
      prepareState.columns[event.target.getAttribute('data-prepare-column')] = Boolean(event.target.checked);
      persistPrepareState();
      renderPrepareData();
    }
    if (event.target && event.target.id === 'prepare-type-selector') {
      prepareState.selectedTypeKey = event.target.value || '';
      persistPrepareState();
      renderPrepareData();
    }
    if (event.target && event.target.getAttribute('data-object-class')) {
      prepareState.classAssignments[event.target.getAttribute('data-object-class')] = event.target.value || '';
      persistPrepareState();
    }
  });
  hydratePrepareState();
  renderChecksumStatus(prepareState.checksum);
  updatePrepareContractVersionSummary();
  render(boot.section || 'prepare-template');
}());
`;
}

async function handleUi(req, res, requestUrl) {
  if (!methodAllowed(req, res, 'GET')) return;
  const pathname = requestUrl.pathname.replace(/\/+$/, '') || UI_PREFIX;
  if (pathname === UI_PREFIX) {
    redirect(res, `${UI_PREFIX}/prepare-template`);
    return;
  }
  const authToken = getCookieValue(req.headers.cookie, 'CMDBuild-Authorization');
  if (!authToken) {
    sendHtml(res, 401, `<!doctype html><html lang="ru"><head><meta charset="utf-8"><title>CMDB BAA</title></head><body style="font-family:Arial,sans-serif;padding:24px"><h1>CMDB BAA</h1><p>CMDBuild session cookie was not sent. Open CMDBuild through the proxy and log in first.</p><p><a href="/cmdbuild/ui/?baSection=prepare-template#custompages/CmdbBaa">Open CMDBuild custom page</a></p></body></html>`);
    return;
  }
  const session = await getSessionData(authToken);
  if (!session.response.ok || !session.data) {
    sendHtml(res, 401, `<!doctype html><html lang="ru"><head><meta charset="utf-8"><title>CMDB BAA</title></head><body style="font-family:Arial,sans-serif;padding:24px"><h1>CMDB BAA</h1><p>CMDBuild session is not valid.</p><p><a href="/cmdbuild/ui/?baSection=prepare-template#custompages/CmdbBaa">Open CMDBuild custom page</a></p></body></html>`);
    return;
  }
  sendHtml(res, 200, renderBaaShell({
    session: sanitizeSession(session.data),
    section: sectionFromPath(pathname)
  }));
}

async function handleApi(req, res, requestUrl) {
  const authToken = getCookieValue(req.headers.cookie, 'CMDBuild-Authorization');
  if (isHealthPath(requestUrl.pathname)) {
    await handleHealth(req, res, requestUrl);
    return;
  }
  if (!authToken) {
    sendJson(res, 401, {
      success: false,
      receivedCmdbuildCookie: false,
      message: 'CMDBuild-Authorization cookie was not sent to backend route.'
    });
    return;
  }
  if (requestUrl.pathname === `${API_PREFIX}/client-log`) {
    if (!methodAllowed(req, res, 'GET')) return;
    const stage = requestUrl.searchParams.get('stage') || '';
    if (stage) {
      clientLogs.push({
        time: new Date().toISOString(),
        stage: stage.slice(0, 120),
        href: (requestUrl.searchParams.get('href') || '').slice(0, 500),
        message: (requestUrl.searchParams.get('message') || '').slice(0, 500)
      });
      while (clientLogs.length > 100) clientLogs.shift();
    }
    sendJson(res, 200, { success: true, data: clientLogs });
    return;
  }
  if (requestUrl.pathname === `${API_PREFIX}/cmdb/classes`) {
    if (!methodAllowed(req, res, 'GET')) return;
    const classes = await cmdbuildRequest('/cmdbuild/services/rest/v3/classes?limit=500&detailed=true', authToken);
    sendJson(res, classes.ok ? 200 : 502, {
      success: classes.ok,
      cmdbuildStatus: classes.statusCode,
      data: Array.isArray(classes.json && classes.json.data)
        ? classes.json.data.map((item) => ({
          name: item.name || '',
          description: item.description || item._description_translation || '',
          parent: item.parent || '',
          prototype: Boolean(item.prototype),
          active: item.active !== false
        })).filter((item) => item.name)
        : []
    });
    return;
  }
  if (requestUrl.pathname === `${API_PREFIX}/contracts`) {
    if (req.method === 'GET') {
      const result = await listConversionContracts(authToken);
      sendJson(res, result.success ? 200 : 502, result);
      return;
    }
    if (req.method === 'POST') {
      try {
        const body = await readJsonBody(req);
        const schema = await checkOrCreateBaaSchema(authToken, body.schema || {}, false);
        if (!schema.ready) {
          sendJson(res, 502, {
            success: false,
            message: 'BAA schema is not ready. Open Settings / Schema and run bootstrap explicitly.',
            schema
          });
          return;
        }
        const result = await createConversionContract(authToken, body);
        sendJson(res, result.success ? 200 : 502, result);
      } catch (error) {
        sendJson(res, 400, {
          success: false,
          message: error && error.message ? error.message : String(error)
        });
      }
      return;
    }
    methodAllowed(req, res, 'GET', 'POST');
    return;
  }
  if (requestUrl.pathname === `${API_PREFIX}/contract-versions`) {
    if (req.method === 'GET') {
      const result = await listConversionContractVersions(authToken);
      sendJson(res, result.success ? 200 : 502, result);
      return;
    }
    methodAllowed(req, res, 'GET');
    return;
  }
  if (requestUrl.pathname === `${API_PREFIX}/schema/preview`) {
    if (!methodAllowed(req, res, 'POST')) return;
    let body;
    try {
      body = await readJsonBody(req);
      const schema = await checkOrCreateBaaSchema(authToken, body, false);
      sendJson(res, 200, {
        success: true,
        schema
      });
    } catch (error) {
      sendJson(res, 400, {
        success: false,
        message: error && error.message ? error.message : String(error)
      });
    }
    return;
  }
  if (requestUrl.pathname === `${API_PREFIX}/schema/bootstrap`) {
    if (!methodAllowed(req, res, 'POST')) return;
    let body;
    try {
      body = await readJsonBody(req);
      const schema = await checkOrCreateBaaSchema(authToken, body, true);
      sendJson(res, schema.ready ? 200 : 502, {
        success: schema.ready,
        schema
      });
    } catch (error) {
      sendJson(res, 400, {
        success: false,
        message: error && error.message ? error.message : String(error)
      });
    }
    return;
  }
  if (requestUrl.pathname === `${API_PREFIX}/vsdx/inspect`) {
    if (!methodAllowed(req, res, 'POST')) return;
    const contentType = String(req.headers['content-type'] || '').toLowerCase();
    let buffer;
    let checksum = {
      checked: false,
      ok: false,
      status: 'not_checked',
      message: 'Контрольная сумма не проверялась'
    };
    let contractRules = {};
    if (contentType.includes('application/json')) {
      const body = await readJsonBody(req);
      buffer = Buffer.from(String(body.fileBase64 || ''), 'base64');
      contractRules = parseContractRules(body.typeRules || body.contractVersion && body.contractVersion.rulesJson);
      if (body.checksumText) {
        checksum = verifyChecksum(buffer, body.checksumText);
        checksum.filename = body.checksumFilename || '';
        checksum.extension = body.checksumExtension || '';
      }
    } else {
      buffer = await readRequestBuffer(req);
    }
    if (!buffer || !buffer.length) {
      sendJson(res, 400, {
        success: false,
        message: 'VSDX file body is required.',
        checksum
      });
      return;
    }
    const inspected = withTempFile('cmdbaa-inspect-', '.vsdx', buffer, (filePath) => ({
      types: inspectVsdxFile(filePath, {
        rules: contractRules
      }),
      aggregates: inspectVsdxAggregates(filePath, {
        rules: contractRules
      }),
      contractMetadata: inspectVsdxContractMetadata(filePath)
    }));
    sendJson(res, 200, {
      success: true,
      checksum,
      types: inspected.types,
      aggregates: inspected.aggregates,
      contractMetadata: inspected.contractMetadata
    });
    return;
  }
  if (requestUrl.pathname === `${API_PREFIX}/vsdx/enrich`) {
    if (!methodAllowed(req, res, 'POST')) return;
    const body = await readJsonBody(req);
    const inputBuffer = Buffer.from(String(body.fileBase64 || ''), 'base64');
    if (!inputBuffer.length) {
      sendJson(res, 400, {
        success: false,
        message: 'fileBase64 is required.'
      });
      return;
    }
    const contract = body.contract && typeof body.contract === 'object' && !Array.isArray(body.contract)
      ? body.contract
      : {};
    const typeClassMap = body.typeClassMap && typeof body.typeClassMap === 'object' && !Array.isArray(body.typeClassMap)
      ? body.typeClassMap
      : {};
    const aggregateClassMap = body.aggregateClassMap && typeof body.aggregateClassMap === 'object' && !Array.isArray(body.aggregateClassMap)
      ? body.aggregateClassMap
      : {};
    const preparedAt = new Date().toISOString();
    const preparedBy = String(body.preparedBy || '').trim();
    const result = withTempFile('cmdbaa-enrich-', '.vsdx', inputBuffer, (filePath, dir) => {
      const outputPath = path.join(dir, 'enriched.vsdx');
      const typeRules = parseContractRules(body.typeRules || {});
      const types = inspectVsdxFile(filePath, { rules: typeRules });
      const aggregates = inspectVsdxAggregates(filePath, { rules: typeRules });
      const existingMetadata = inspectVsdxContractMetadata(filePath);
      return {
        outputPath,
        typeRules,
        types,
        aggregates,
        existingMetadata
      };
    });
    let versionResolution;
    try {
      const schema = await checkOrCreateBaaSchema(authToken, body.schema || {}, false);
      if (!schema.ready) {
        sendJson(res, 502, {
          success: false,
          message: 'BAA schema is not ready. Open Settings / Schema and run bootstrap explicitly.',
          schema
        });
        return;
      }
      versionResolution = await resolveContractVersionForEnrichment(authToken, {
        contract,
        existingMetadata: result.existingMetadata,
        types: result.types,
        aggregates: result.aggregates,
        typeRules: result.typeRules,
        preparedBy
      });
    } catch (error) {
      sendJson(res, 400, {
        success: false,
        message: error && error.message ? error.message : String(error)
      });
      return;
    }
    const fixedContractVersion = {
      id: String(versionResolution.version.id || ''),
      code: String(versionResolution.version.code || ''),
      contractId: String(versionResolution.version.contractId || ''),
      contractCode: String(versionResolution.version.contractCode || ''),
      version: String(versionResolution.version.version || ''),
      status: String(versionResolution.version.status || ''),
      rulesChecksum: String(versionResolution.version.rulesChecksum || '')
    };
    const contractRules = parseContractRules(versionResolution.version.rulesJson || result.typeRules);
    const classByPageShapeId = shapeClassMapFromAggregates(result.aggregates, aggregateClassMap);
    const enriched = withTempFile('cmdbaa-enrich-', '.vsdx', inputBuffer, (filePath, dir) => {
      const outputPath = path.join(dir, 'enriched.vsdx');
      const pages = enrichVsdxFile(filePath, outputPath, {
        classByTypeKey: typeClassMap,
        classByPageShapeId,
        rules: contractRules,
        contractVersion: fixedContractVersion,
        preparedAt,
        preparedBy
      });
      return {
        pages,
        buffer: fs.readFileSync(outputPath)
      };
    });
    const filename = String(body.filename || 'template.vsdx').replace(/\.vsdx$/i, '') + '.enriched.vsdx';
    sendJson(res, 200, {
      success: true,
      filename,
      fileBase64: enriched.buffer.toString('base64'),
      summary: {
        pages: enriched.pages,
        mappedTypes: Object.keys(typeClassMap).length,
        mappedAggregateRoles: Object.keys(aggregateClassMap).length,
        mappedShapes: Object.keys(classByPageShapeId).length,
        versionAction: versionResolution.action,
        addedTypes: versionResolution.addedTypes.length,
        knownTypes: versionResolution.knownTypes.length,
        addedAggregates: versionResolution.addedAggregates.length,
        knownAggregates: versionResolution.knownAggregates.length
      },
      contractVersion: fixedContractVersion,
      versionAction: versionResolution.action,
      addedTypes: versionResolution.addedTypes,
      addedAggregates: versionResolution.addedAggregates,
      fixedMetadata: {
        templatePrepared: true,
        contractVersionId: fixedContractVersion.id,
        contractVersionCode: fixedContractVersion.code,
        contractVersionChecksum: fixedContractVersion.rulesChecksum,
        preparedAt,
        preparedBy
      }
    });
    return;
  }
  if (requestUrl.pathname === `${API_PREFIX}/session`) {
    if (!methodAllowed(req, res, 'GET')) return;
    const session = await getSessionData(authToken);
    sendJson(res, session.response.ok ? 200 : 502, {
      success: session.response.ok,
      receivedCmdbuildCookie: true,
      forwardedAs: 'CMDBuild-Authorization header',
      cmdbuildStatus: session.response.statusCode,
      session: sanitizeSession(session.data)
    });
    return;
  }
  if (requestUrl.pathname === `${API_PREFIX}/csrf`) {
    if (!methodAllowed(req, res, 'GET')) return;
    sendJson(res, 200, {
      success: true,
      token: getCsrfToken(authToken)
    });
    return;
  }
  sendJson(res, 404, {
    success: false,
    message: `Unknown backend route: ${requestUrl.pathname}`
  });
}

function isCmdbBaaScript(pathname) {
  return pathname.endsWith('/view/custompages/CmdbBaa/CmdbBaa.js');
}

function isCmdbuildUiEntry(pathname) {
  return pathname === '/cmdbuild/ui' || pathname === '/cmdbuild/ui/';
}

function isCmdbuildUiManifest(pathname) {
  return pathname === '/cmdbuild/ui/cmdbuild.json' || pathname === '/cmdbuild/ui/hda.json';
}

function isCmdbuildUiCacheSensitive(pathname) {
  return isCmdbuildUiEntry(pathname) ||
    isCmdbuildUiManifest(pathname) ||
    pathname === '/cmdbuild/ui/config.js' ||
    pathname === '/cmdbuild/ui/cmdbuild/app.js' ||
    pathname === '/cmdbuild/ui/hda/app.js' ||
    isCmdbBaaScript(pathname);
}

function normalizeSameSiteValue(value) {
  const text = String(value || '').trim().toLowerCase();
  if (text === 'lax') return 'Lax';
  if (text === 'strict') return 'Strict';
  if (text === 'none') return 'None';
  return '';
}

function shouldMarkProxyCookieSecure() {
  const value = String(PROXY_COOKIE_SECURE || '').trim().toLowerCase();
  return value !== 'false' && value !== '0' && value !== 'no';
}

function rewriteProxySetCookieHeader(header) {
  if (!header) return header;
  const sameSite = normalizeSameSiteValue(PROXY_COOKIE_SAMESITE);
  const secure = shouldMarkProxyCookieSecure();
  function rewriteOne(cookie) {
    const parts = String(cookie || '').split(';').map((part) => part.trim()).filter(Boolean);
    if (!parts.length) return cookie;
    const rewritten = [parts[0]];
    let hasSecure = false;
    for (const part of parts.slice(1)) {
      if (/^samesite=/i.test(part)) continue;
      if (/^secure$/i.test(part)) {
        hasSecure = true;
        rewritten.push('Secure');
        continue;
      }
      rewritten.push(part);
    }
    if (sameSite) rewritten.push(`SameSite=${sameSite}`);
    if (secure && !hasSecure) rewritten.push('Secure');
    return rewritten.join('; ');
  }
  return Array.isArray(header) ? header.map(rewriteOne) : rewriteOne(header);
}

function rewriteProxyResponseHeaders(headers) {
  const responseHeaders = { ...headers };
  if (responseHeaders['set-cookie']) {
    responseHeaders['set-cookie'] = rewriteProxySetCookieHeader(responseHeaders['set-cookie']);
  }
  return responseHeaders;
}

function withNoStoreHeaders(headers) {
  const responseHeaders = { ...headers };
  responseHeaders['cache-control'] = 'no-store, no-cache, must-revalidate, proxy-revalidate';
  responseHeaders.pragma = 'no-cache';
  responseHeaders.expires = '0';
  delete responseHeaders.etag;
  delete responseHeaders['content-length'];
  delete responseHeaders['transfer-encoding'];
  return responseHeaders;
}

function rewriteCmdbuildUiHtml(body) {
  const injection = [
    '<script type="text/javascript">',
    '(function(){try{',
    'var pendingKey="cmdbaa.pendingTarget";',
    'function parseQuery(q){var r={};String(q||"").replace(/^\\?/,"").split("&").forEach(function(part){if(!part)return;var i=part.indexOf("=");var k=i===-1?part:part.slice(0,i);var v=i===-1?"":part.slice(i+1);k=decodeURIComponent(k.replace(/\\+/g," "));if(k)r[k]=decodeURIComponent(v.replace(/\\+/g," "));});return r;}',
    'function normalize(v){v=String(v||"").toLowerCase();if(v==="schema"||v==="cmdb-schema")return"schema";if(v==="contracts"||v==="contract"||v==="conversion-contracts")return"contracts";if(v==="settings"||v==="config"||v==="configuration")return"settings";if(v==="types"||v==="type-settings"||v==="visio-types")return"types";if(v==="verify"||v==="verification")return"verify";if(v==="create-objects"||v==="create"||v==="objects")return"create-objects";return"prepare-template";}',
    'function readHash(){var h=window.location.hash||"";var marker="custompages/CmdbBaa";var at=h.indexOf(marker);if(at===-1)return"";return h.slice(at+marker.length).replace(/^\\/+/, "").split(/[/?#]/)[0]||"";}',
    'var query=parseQuery(window.location.search||"");',
    'var shouldOpen=(window.location.hash||"").indexOf("custompages/CmdbBaa")!==-1||query.baSection||query.section;',
    'var target=shouldOpen?"/cmdbuild/baa/ui/"+encodeURIComponent(normalize(query.baSection||query.section||readHash())):"";',
    'if(target&&window.sessionStorage){window.sessionStorage.setItem(pendingKey,target);}',
    'var pending=window.sessionStorage&&window.sessionStorage.getItem(pendingKey)||"";',
    'function clearPending(){try{if(window.sessionStorage)window.sessionStorage.removeItem(pendingKey);}catch(e){}}',
    'function showPendingLink(){if(!pending||document.getElementById("cmdbaa-login-fallback-link")||!document.body)return;var a=document.createElement("a");a.id="cmdbaa-login-fallback-link";a.href=pending;a.textContent="Open CMDB BAA";a.style.cssText="position:fixed;right:14px;bottom:14px;z-index:2147483647;background:#236c91;color:#fff;padding:9px 12px;border-radius:4px;text-decoration:none;font:600 13px Arial,sans-serif;box-shadow:0 6px 16px rgba(15,23,42,.18)";document.body.appendChild(a);}',
    'if(pending){if(document.readyState==="loading"){document.addEventListener("DOMContentLoaded",showPendingLink);}else{showPendingLink();}fetch("/cmdbuild/baa/api/session",{credentials:"include",headers:{Accept:"application/json"}}).then(function(r){if(r.ok){clearPending();window.location.replace(pending);}}).catch(function(){});}',
    '}catch(e){}})();',
    '</script>'
  ].join('');
  if (body.indexOf('cmdbaa-dev-cache-reset') !== -1) return body;
  return body.replace('<head>', '<head>\n<meta name="cmdbaa-dev-cache-reset" content="' + DEV_CACHE_BUSTER + '">\n' + injection);
}

function rewriteCmdbuildManifest(body) {
  try {
    const manifest = JSON.parse(body);
    manifest.cache = manifest.cache || {};
    manifest.cache.enable = false;
    manifest.appCacheEnabled = false;
    manifest.loader = manifest.loader || {};
    manifest.loader.cache = DEV_CACHE_BUSTER;
    manifest.hash = `${manifest.hash || 'dev'}-${DEV_CACHE_BUSTER}`;
    return JSON.stringify(manifest);
  } catch {
    return body;
  }
}

function proxyToCmdbuild(req, res, requestUrl) {
  const target = new URL(req.url || '/', CMDBUILD_ORIGIN);
  const headers = { ...req.headers };
  headers.host = req.headers.host || `${LISTEN_HOST}:${LISTEN_PORT}`;
  if (isCmdbuildUiCacheSensitive(requestUrl.pathname)) {
    headers['accept-encoding'] = 'identity';
  }
  const proxyReq = http.request({
    protocol: target.protocol,
    hostname: target.hostname,
    port: target.port,
    method: req.method,
    path: `${target.pathname}${target.search}`,
    headers
  }, (proxyRes) => {
    const shouldRewriteHtml = isCmdbuildUiEntry(requestUrl.pathname);
    const shouldRewriteManifest = isCmdbuildUiManifest(requestUrl.pathname);
    const shouldBuffer = shouldRewriteHtml || shouldRewriteManifest || isCmdbuildUiCacheSensitive(requestUrl.pathname);
    if (!shouldBuffer) {
      res.writeHead(proxyRes.statusCode || 502, rewriteProxyResponseHeaders(proxyRes.headers));
      proxyRes.pipe(res);
      return;
    }
    const chunks = [];
    proxyRes.on('data', (chunk) => chunks.push(chunk));
    proxyRes.on('end', () => {
      let body = Buffer.concat(chunks).toString('utf8');
      if (shouldRewriteHtml) body = rewriteCmdbuildUiHtml(body);
      else if (shouldRewriteManifest) body = rewriteCmdbuildManifest(body);
      const responseHeaders = withNoStoreHeaders(rewriteProxyResponseHeaders(proxyRes.headers));
      responseHeaders['content-length'] = Buffer.byteLength(body);
      res.writeHead(proxyRes.statusCode || 502, responseHeaders);
      res.end(body);
    });
  });
  proxyReq.on('error', (error) => {
    sendJson(res, 502, {
      success: false,
      message: `Proxy error: ${error.message}`
    });
  });
  req.pipe(proxyReq);
}

const server = http.createServer((req, res) => {
  const requestUrl = new URL(req.url || '/', `http://${req.headers.host || `${LISTEN_HOST}:${LISTEN_PORT}`}`);
  if (isHealthPath(requestUrl.pathname)) {
    handleHealth(req, res, requestUrl).catch((error) => {
      sendJson(res, 503, {
        ...baseHealthPayload(),
        status: 'not_ready',
        ready: false,
        error: error && error.message ? error.message : String(error)
      });
    });
    return;
  }
  if (requestUrl.pathname === UI_PREFIX || requestUrl.pathname.startsWith(`${UI_PREFIX}/`)) {
    handleUi(req, res, requestUrl).catch((error) => {
      sendHtml(res, 500, `<!doctype html><html lang="ru"><head><meta charset="utf-8"><title>CMDB BAA</title></head><body style="font-family:Arial,sans-serif;padding:24px"><h1>CMDB BAA error</h1><pre>${htmlEscape(error && error.stack ? error.stack : error)}</pre></body></html>`);
    });
    return;
  }
  if (requestUrl.pathname.startsWith(`${API_PREFIX}/`)) {
    handleApi(req, res, requestUrl).catch((error) => {
      sendJson(res, 500, {
        success: false,
        message: error && error.message ? error.message : String(error)
      });
    });
    return;
  }
  proxyToCmdbuild(req, res, requestUrl);
});

server.on('error', (error) => {
  process.stderr.write(JSON.stringify({
    time: new Date().toISOString(),
    level: 'error',
    service: 'cmdbaa',
    event: 'app.listen_failed',
    listen: `http://${LISTEN_HOST}:${LISTEN_PORT}`,
    error: error && error.message ? error.message : String(error)
  }) + '\n');
  process.exitCode = 1;
});

const isMainModule = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isMainModule) {
  server.listen(LISTEN_PORT, LISTEN_HOST, () => {
    process.stdout.write(JSON.stringify({
      time: new Date().toISOString(),
      level: 'info',
      service: 'cmdbaa',
      event: 'app.started',
      listen: `http://${LISTEN_HOST}:${LISTEN_PORT}`,
      cmdbuildOrigin: CMDBUILD_ORIGIN,
      uiPrefix: UI_PREFIX,
      apiPrefix: API_PREFIX
    }) + '\n');
  });
}

export {
  getCookieValue,
  getCsrfToken,
  normalizeSection,
  renderBaaShell,
  rewriteProxySetCookieHeader,
  sanitizeSession
};
