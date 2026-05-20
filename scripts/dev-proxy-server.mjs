import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { enrichVsdxFile, extractBaaObjectsFromVsdx, inspectVsdxAggregates, inspectVsdxContractMetadata, inspectVsdxFile } from './enrich-vsdx.mjs';

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

function normalizeClassValue(value) {
  if (Array.isArray(value)) return value.map((item) => String(item || '').trim()).filter(Boolean).join(', ');
  return String(value || '').split(',').map((item) => item.trim()).filter(Boolean).join(', ');
}

function addShapeMapping(target, atom, classValue, metadata = {}) {
  const normalizedClassValue = normalizeClassValue(classValue);
  if (!atom || !atom.page || !atom.shapeId || !normalizedClassValue) return false;
  const key = `${atom.page}:${atom.shapeId}`;
  target.classByPageShapeId[key] = target.classByPageShapeId[key]
    ? normalizeClassValue(`${target.classByPageShapeId[key]}, ${normalizedClassValue}`)
    : normalizedClassValue;
  const existingMetadata = target.metadataByPageShapeId[key] || {};
  target.metadataByPageShapeId[key] = {
    ...existingMetadata,
    ...metadata,
    cmdbClasses: Array.from(new Set([...(existingMetadata.cmdbClasses || []), ...(metadata.cmdbClasses || [])])),
    cmdbAttributeFields: mergeCmdbAttributeFields(existingMetadata.cmdbAttributeFields, metadata.cmdbAttributeFields)
  };
  target.mapped.push({
    pageShapeKey: key,
    classValue: normalizedClassValue,
    metadata
  });
  return true;
}

function mergeCmdbAttributeFields(left = [], right = []) {
  const byKey = new Map();
  for (const item of [...left, ...right]) {
    if (!item || !item.rowName) continue;
    byKey.set(item.rowName, { ...byKey.get(item.rowName), ...item });
  }
  return Array.from(byKey.values()).sort((a, b) => String(a.rowName).localeCompare(String(b.rowName)));
}

function cmdbShapeDataRowName(className, attrName) {
  const safe = String(`${className}_${attrName}`)
    .replace(/[^A-Za-z0-9_]/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+/, '');
  return `template_${safe || 'Attribute'}`.slice(0, 120);
}

function legacyCmdbShapeDataRowName(className, attrName) {
  const safe = String(`${className}_${attrName}`)
    .replace(/[^A-Za-z0-9_]/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+/, '');
  return `CMDB_${safe || 'Attribute'}`.slice(0, 120);
}

const ATTRIBUTE_SOURCE_ROLES = new Set(['self', 'source', 'destination', 'manual', 'constant', 'default', 'override']);
const SHAPE_DATA_NAMESPACES = {
  technicalPrefix: '_baa_',
  templatePrefix: 'template_'
};

function normalizeAttributeSourceRule(rule = {}, targetClass = '', targetAttribute = '') {
  const sourceRole = ATTRIBUTE_SOURCE_ROLES.has(String(rule.sourceRole || '').trim())
    ? String(rule.sourceRole).trim()
    : 'self';
  const mode = String(rule.mode || (sourceRole === 'constant' ? 'constant' : sourceRole === 'default' ? 'default' : sourceRole === 'manual' ? 'manual' : sourceRole === 'override' ? 'override' : 'copy')).trim();
  const sourceAttribute = String(rule.sourceAttribute || rule.attribute || targetAttribute || '').trim();
  return {
    targetClass: String(rule.targetClass || targetClass || '').trim(),
    targetAttribute: String(rule.targetAttribute || targetAttribute || '').trim(),
    sourceRole,
    sourceAttribute,
    mode,
    constantValue: String(rule.constantValue || ''),
    defaultValue: String(rule.defaultValue || ''),
    overrideAttribute: String(rule.overrideAttribute || '')
  };
}

function attributeSourceRuleFor(attributeSourceRules = {}, key, className, attrName) {
  return normalizeAttributeSourceRule(
    attributeSourceRules[`${key}::${className}::${attrName}`] || {},
    className,
    attrName
  );
}

function selectedAttributeFields(roleMapKey, classValue, aggregateAttributeMap = {}, attributeCatalog = {}, attributeListModes = {}, attributeSourceRules = {}) {
  const classes = normalizeClassValue(classValue).split(',').map((item) => item.trim()).filter(Boolean);
  const fields = [];
  for (const className of classes) {
    const selectedNames = Array.isArray(aggregateAttributeMap[`${roleMapKey}::${className}`])
      ? aggregateAttributeMap[`${roleMapKey}::${className}`].map((item) => String(item || '').trim()).filter(Boolean)
      : [];
    const catalog = Array.isArray(attributeCatalog[className]) ? attributeCatalog[className] : [];
    const byName = new Map(catalog.map((attr) => [attr && attr.name, attr]).filter((item) => item[0]));
    for (const attrName of selectedNames) {
      const attr = byName.get(attrName) || { name: attrName };
      const sourceRule = attributeSourceRuleFor(attributeSourceRules, roleMapKey, className, attrName);
      fields.push({
        className,
        attrName,
        rowName: cmdbShapeDataRowName(className, attrName),
        label: attr.description || attr.name || attrName,
        type: attr.type || '',
        mandatory: Boolean(attr.mandatory),
        listMode: attr.resolvedListMode || attributeListModes[`${roleMapKey}::${className}::${attrName}`] || 'none',
        listValues: Array.isArray(attr.resolvedListValues) ? attr.resolvedListValues : [],
        listSource: attr.resolvedListSource || attr.lookupType || attr.targetClass || attr.domain || '',
        listWarning: attr.resolvedListWarning || '',
        sourceRule
      });
    }
  }
  return {
    cmdbClasses: classes,
    cmdbAttributeFields: mergeCmdbAttributeFields([], fields)
  };
}

function shapeMappingsFromAggregates(aggregates, aggregateClassMap, options = {}) {
  const result = {
    classByPageShapeId: {},
    metadataByPageShapeId: {},
    mapped: [],
    skipped: []
  };
  const decomposeAggregates = Boolean(options.decomposeAggregates);
  const aggregateAttributeMap = options.aggregateAttributeMap || {};
  const attributeListModes = options.attributeListModes || {};
  const attributeSourceRules = options.attributeSourceRules || {};
  const attributeCatalog = options.attributeCatalog || {};
  const contractAnchorKey = String(options.contractAnchorKey || '');
  for (const aggregate of aggregates || []) {
    const aggregateTypeKey = String(aggregate.aggregateTypeKey || '');
    if (!aggregateTypeKey) continue;
    const isAggregateObject = aggregate.kind === 'group' || aggregate.kind === 'container';
    const isConnector = aggregate.kind === 'connector';
    const wholeVisualObjectKey = `${aggregateTypeKey}::__visual_object__`;
    const wholeVisualObjectClassValue = normalizeClassValue(aggregateClassMap[wholeVisualObjectKey]);
    if (!decomposeAggregates && wholeVisualObjectClassValue && isAggregateObject) {
      const assignmentFields = selectedAttributeFields(wholeVisualObjectKey, wholeVisualObjectClassValue, aggregateAttributeMap, attributeCatalog, attributeListModes, attributeSourceRules);
      for (const instance of aggregate.instances || []) {
        const anchor = instance.anchor || null;
        const anchorKey = anchor && anchor.page && anchor.shapeId ? `${anchor.page}:${anchor.shapeId}` : '';
        if (anchorKey && anchorKey === contractAnchorKey) {
          result.skipped.push({ key: wholeVisualObjectKey, reason: 'contract_anchor', aggregateTypeKey, pageShapeKey: anchorKey });
          continue;
        }
        const ok = addShapeMapping(result, anchor, wholeVisualObjectClassValue, {
          visualObjectId: [instance.page || '', instance.aggregateShapeId || ''].filter(Boolean).join(':'),
          anchorShapeId: anchor && anchor.shapeId || '',
          aggregationKind: aggregate.kind || '',
          decomposed: 'false',
          roleKey: '__visual_object__',
          mappingKey: wholeVisualObjectKey,
          cmdbEntitySlot: String(wholeVisualObjectClassValue).split(',').map((_, index) => String(index + 1)).join(','),
          ...assignmentFields
        });
        if (!ok) result.skipped.push({ key: wholeVisualObjectKey, reason: 'missing_anchor', aggregateTypeKey });
      }
    }
    if (decomposeAggregates && wholeVisualObjectClassValue && isAggregateObject) {
      result.skipped.push({ key: wholeVisualObjectKey, reason: 'visual_object_disabled_by_decomposition', aggregateTypeKey });
    }
    for (const role of aggregate.atomRoles || []) {
      const roleKey = String(role.roleKey || '');
      if (!roleKey) continue;
      const roleMapKey = `${aggregateTypeKey}::${roleKey}`;
      const classValue = normalizeClassValue(aggregateClassMap[roleMapKey]);
      if (!classValue) continue;
      const assignmentFields = selectedAttributeFields(roleMapKey, classValue, aggregateAttributeMap, attributeCatalog, attributeListModes, attributeSourceRules);
      if (!decomposeAggregates && isAggregateObject) {
        result.skipped.push({ key: roleMapKey, reason: 'atom_role_disabled_without_decomposition', aggregateTypeKey, roleKey });
        continue;
      }
      if (!classValue) continue;
      for (const instance of aggregate.instances || []) {
        let roleMapped = false;
        for (const atom of instance.atoms || []) {
          if (atom.roleKey === roleKey && atom.page && atom.shapeId) {
            const atomKey = `${atom.page}:${atom.shapeId}`;
            if (atomKey === contractAnchorKey) {
              result.skipped.push({ key: roleMapKey, reason: 'contract_anchor', aggregateTypeKey, roleKey, pageShapeKey: atomKey });
              roleMapped = true;
              continue;
            }
            roleMapped = addShapeMapping(result, atom, classValue, {
              visualObjectId: [instance.page || '', instance.aggregateShapeId || ''].filter(Boolean).join(':'),
              anchorShapeId: atom.shapeId || '',
              aggregationKind: aggregate.kind || '',
              decomposed: aggregate.kind === 'group' || aggregate.kind === 'container' ? 'true' : '',
              roleKey,
              mappingKey: roleMapKey,
              cmdbEntitySlot: String(classValue).split(',').map((_, index) => String(index + 1)).join(','),
              relationType: isConnector ? classValue : '',
              ...assignmentFields
            }) || roleMapped;
          }
        }
        if (!roleMapped) result.skipped.push({ key: roleMapKey, reason: 'role_atom_not_found', aggregateTypeKey, roleKey });
      }
    }
  }
  return result;
}

function aggregatePageShapeKeys(aggregates) {
  const keys = new Set();
  for (const aggregate of aggregates || []) {
    for (const instance of aggregate.instances || []) {
      const anchor = instance.anchor || null;
      if (anchor && anchor.page && anchor.shapeId) keys.add(`${anchor.page}:${anchor.shapeId}`);
      for (const atom of instance.atoms || []) {
        if (atom && atom.page && atom.shapeId) keys.add(`${atom.page}:${atom.shapeId}`);
      }
    }
  }
  return keys;
}

function digestHex(algorithm, buffer) {
  return crypto.createHash(algorithm).update(buffer).digest('hex').toLowerCase();
}

function checksumAlgorithmFromExtension(extension) {
  const normalized = String(extension || '').trim().replace(/^\.+/, '').toLowerCase();
  if (normalized === 'sha2' || normalized === 'sha-2') return 'sha256';
  if (normalized === 'sha3') return 'sha3-256';
  if (['sha256', 'sha384', 'sha512', 'sha3-256', 'sha3-384', 'sha3-512'].includes(normalized)) return normalized;
  return 'sha256';
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

function listModeForAttribute(type, requested) {
  const normalized = String(requested || '').trim();
  if (normalized === 'fixed' || normalized === 'variable' || normalized === 'none') return normalized;
  if (String(type || '').toLowerCase() === 'lookup') return 'fixed';
  if (String(type || '').toLowerCase() === 'reference') return 'fixed';
  return 'none';
}

function lookupValueLabel(item, byId, seen = new Set()) {
  const own = item.description || item._description_translation || item.text || item.Code || item.code || item.value || item.id || '';
  const parentId = item.parent || item.Parent || item.parent_id || item._parent_id || '';
  if (!parentId || !byId.has(parentId) || seen.has(parentId)) return String(own || '');
  seen.add(parentId);
  const parent = lookupValueLabel(byId.get(parentId), byId, seen);
  return [parent, own].filter(Boolean).join(' / ');
}

async function lookupListValues(authToken, lookupType) {
  const type = String(lookupType || '').trim();
  if (!type) return { values: [], source: '', warning: 'lookup type is empty' };
  const response = await cmdbuildRequest(`/cmdbuild/services/rest/v3/lookup_types/${encodeURIComponent(type)}/values?limit=10000&detailed=true`, authToken);
  if (!response.ok || !Array.isArray(response.json && response.json.data)) {
    return { values: [], source: type, warning: cmdbuildErrorMessage(response, 'Lookup values unavailable.') };
  }
  const byId = new Map(response.json.data.map((item) => [String(item._id || item.Id || item.id || item.Code || item.code || ''), item]).filter((entry) => entry[0]));
  return {
    values: response.json.data.map((item) => lookupValueLabel(item, byId)).filter(Boolean).sort((a, b) => a.localeCompare(b)),
    source: type,
    warning: ''
  };
}

async function referenceListValues(authToken, className, limit) {
  const target = String(className || '').trim();
  if (!target) return { values: [], source: '', warning: 'reference target class is empty', forcedMode: '' };
  const safeLimit = Math.max(1, Number.parseInt(String(limit || '50'), 10) || 50);
  const response = await cmdbuildRequest(`/cmdbuild/services/rest/v3/classes/${encodeURIComponent(target)}/cards?limit=${safeLimit + 1}&detailed=true`, authToken);
  if (!response.ok || !Array.isArray(response.json && response.json.data)) {
    return { values: [], source: target, warning: cmdbuildErrorMessage(response, 'Reference values unavailable.'), forcedMode: '' };
  }
  const tooMany = response.json.data.length > safeLimit;
  const values = response.json.data.slice(0, safeLimit).map((item) =>
    item.Description || item.description || item.Code || item.code || item._Description_description || item._id || item.Id || item.id || ''
  ).filter(Boolean).sort((a, b) => String(a).localeCompare(String(b)));
  return {
    values,
    source: target,
    warning: tooMany ? `Reference ${target}: объектов больше ${safeLimit}, постоянный список заменен на переменный.` : '',
    forcedMode: tooMany ? 'variable' : ''
  };
}

async function resolveAttributeListValues(authToken, attributeCatalog = {}, attributeListModes = {}, settings = {}) {
  const referenceLimit = Math.max(1, Number.parseInt(String(settings.referenceFixedListLimit || '50'), 10) || 50);
  const warnings = [];
  const nextCatalog = {};
  for (const [className, attrs] of Object.entries(attributeCatalog || {})) {
    nextCatalog[className] = Array.isArray(attrs) ? attrs.map((attr) => ({ ...attr })) : attrs;
    if (!Array.isArray(nextCatalog[className])) continue;
    for (const attr of nextCatalog[className]) {
      const type = String(attr && attr.type || '').toLowerCase();
      if (type !== 'lookup' && type !== 'reference') continue;
      const matchingMode = Object.entries(attributeListModes || {}).find(([key]) => key.endsWith(`::${className}::${attr.name}`));
      const requestedMode = listModeForAttribute(type, matchingMode && matchingMode[1]);
      if (requestedMode === 'none') {
        attr.resolvedListMode = 'none';
        continue;
      }
      if (type === 'lookup') {
        const source = attr.lookupType || attr.lookupName || attr.lookup || attr.rawSource && attr.rawSource.lookupType || '';
        const result = await lookupListValues(authToken, source);
        attr.resolvedListMode = requestedMode;
        attr.resolvedListValues = result.values;
        attr.resolvedListSource = result.source;
        attr.resolvedListWarning = result.warning;
        if (result.warning) warnings.push(result.warning);
      }
      if (type === 'reference') {
        const source = attr.targetClass || attr.target || attr.referenceClass || attr.rawSource && attr.rawSource.targetClass || '';
        const result = await referenceListValues(authToken, source, referenceLimit);
        attr.resolvedListMode = result.forcedMode || requestedMode;
        attr.resolvedListValues = result.values;
        attr.resolvedListSource = result.source;
        attr.resolvedListWarning = result.warning;
        if (result.warning) warnings.push(result.warning);
      }
    }
  }
  return { attributeCatalog: nextCatalog, warnings };
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

function classesFromValue(value) {
  return normalizeClassValue(value).split(',').map((item) => item.trim()).filter(Boolean);
}

function mappingByKeyFromRules(rules = {}) {
  const result = new Map();
  for (const item of Array.isArray(rules.knownMappings) ? rules.knownMappings : []) {
    if (item && item.key) result.set(item.key, item);
  }
  return result;
}

function normalizeContractParam(param = {}) {
  const name = String(param.name || param.Name || '').trim();
  if (!name) return null;
  const values = Array.isArray(param.values || param.Values)
    ? (param.values || param.Values).map((item) => String(item || '').trim()).filter(Boolean)
    : [];
  const listMode = ['none', 'fixed', 'variable'].includes(String(param.listMode || param.ListMode || 'none'))
    ? String(param.listMode || param.ListMode || 'none')
    : values.length ? 'fixed' : 'none';
  return {
    name,
    description: String(param.description || param.Description || name).trim() || name,
    type: String(param.type || param.Type || 'string').trim() || 'string',
    required: Boolean(param.required || param.Required || param.mandatory || param.Mandatory),
    defaultValue: String(param.defaultValue || param.DefaultValue || ''),
    listMode,
    values,
    help: String(param.help || param.Help || '').trim()
  };
}

function normalizeContractParams(params = []) {
  const byName = new Map();
  for (const item of Array.isArray(params) ? params : []) {
    const param = normalizeContractParam(item);
    if (!param) continue;
    byName.set(param.name, { ...byName.get(param.name), ...param });
  }
  return Array.from(byName.values()).sort((a, b) => String(a.name).localeCompare(String(b.name)));
}

function contractParamSignature(param) {
  return JSON.stringify(normalizeContractParam(param) || {});
}

function mergeContractParams(previous = [], current = []) {
  const byName = new Map();
  let changed = false;
  for (const param of normalizeContractParams(previous)) byName.set(param.name, param);
  for (const param of normalizeContractParams(current)) {
    const existing = byName.get(param.name);
    if (!existing || contractParamSignature(existing) !== contractParamSignature(param)) changed = true;
    byName.set(param.name, { ...existing, ...param });
  }
  return {
    contractParams: Array.from(byName.values()).sort((a, b) => String(a.name).localeCompare(String(b.name))),
    changed
  };
}

function publicContractVersion(version) {
  if (!version) return null;
  return {
    id: version.id || '',
    code: version.code || '',
    contractCode: version.contractCode || '',
    version: version.version || '',
    rulesChecksum: version.rulesChecksum || ''
  };
}

function valueByRowName(object) {
  const result = {};
  for (const row of object && object.values || []) result[row.name] = row.value;
  return result;
}

function objectsByPageShapeKey(objects = []) {
  const result = new Map();
  for (const object of objects) {
    if (object && object.pageShapeKey) result.set(object.pageShapeKey, object);
  }
  return result;
}

function objectForEndpoint(shapeByKey, object, shapeId) {
  if (!shapeId) return null;
  return shapeByKey.get(`${object.page}:${shapeId}`) || null;
}

function attributeDefinitionMap(mapping, className) {
  const result = new Map();
  const attrs = mapping && mapping.attributesByClass && Array.isArray(mapping.attributesByClass[className])
    ? mapping.attributesByClass[className]
    : [];
  for (const attr of attrs) {
    if (attr && attr.name) result.set(attr.name, attr);
  }
  return result;
}

function mappingAttributeRules(mapping, className) {
  const attrs = mapping && mapping.attributesByClass && Array.isArray(mapping.attributesByClass[className])
    ? mapping.attributesByClass[className]
    : [];
  const byAttribute = new Map();
  for (const attr of attrs) {
    if (!attr || !attr.name) continue;
    byAttribute.set(attr.name, normalizeAttributeSourceRule(attr.sourceRule || {}, className, attr.name));
  }
  for (const rule of mapping && mapping.attributeRules || []) {
    const normalized = normalizeAttributeSourceRule(rule, rule && rule.targetClass, rule && rule.targetAttribute);
    if (normalized.targetClass === className && normalized.targetAttribute) byAttribute.set(normalized.targetAttribute, normalized);
  }
  return Array.from(byAttribute.values());
}

function sourceAttributeRef(rule, fallbackClass = '') {
  const text = String(rule && rule.sourceAttribute || '').trim();
  if (!text) return { className: fallbackClass, attrName: '' };
  const delimiter = text.indexOf('.');
  if (delimiter === -1) return { className: fallbackClass, attrName: text };
  return {
    className: text.slice(0, delimiter).trim() || fallbackClass,
    attrName: text.slice(delimiter + 1).trim()
  };
}

function sourceAttributeRefFromRelationMapping(object, rule, endpointObject, relationEndpointMappings) {
  const sourceRole = rule && rule.sourceRole || 'self';
  if (!['source', 'destination'].includes(sourceRole)) {
    return sourceAttributeRef(rule, endpointObject && endpointObject.cmdbClasses && endpointObject.cmdbClasses[0] || '');
  }
  const relationKey = relationEndpointMappingKeyForObject(object);
  const relationMapping = relationEndpointMappings && relationEndpointMappings[relationKey] || {};
  const attributeMappings = Array.isArray(relationMapping.attributes) ? relationMapping.attributes : [];
  const endpointClasses = new Set(endpointObject && endpointObject.cmdbClasses || []);
  const mapped = attributeMappings.find((row) =>
    row.relationClassName === rule.targetClass &&
    row.relationAttributeName === rule.targetAttribute &&
    endpointClasses.has(row.className)
  ) || attributeMappings.find((row) =>
    row.relationAttributeName === rule.targetAttribute &&
    endpointClasses.has(row.className)
  );
  if (mapped) return { className: mapped.className, attrName: mapped.attributeName };
  return sourceAttributeRef(rule, endpointObject && endpointObject.cmdbClasses && endpointObject.cmdbClasses[0] || '');
}

function hasFilledValue(object, rowName) {
  const values = valueByRowName(object);
  return Object.prototype.hasOwnProperty.call(values, rowName) && String(values[rowName] || '').trim();
}

function hasFilledClassAttribute(object, className, attrName) {
  const values = valueByRowName(object);
  const rowNames = [cmdbShapeDataRowName(className, attrName), legacyCmdbShapeDataRowName(className, attrName)];
  return rowNames.some((rowName) => Object.prototype.hasOwnProperty.call(values, rowName) && String(values[rowName] || '').trim());
}

function endpointKindFor(object, sourceRole) {
  return sourceRole === 'source' ? object.sourceKind || '' : object.destinationKind || '';
}

function endpointTextFor(object, sourceRole) {
  return sourceRole === 'source'
    ? object.sourceText || object.sourceObjectType || ''
    : object.destinationText || object.destinationObjectType || '';
}

function relationEndpointMappingKeyForObject(object = {}) {
  const mappingKey = String(object.mappingKey || '');
  const roleKey = String(object.roleKey || '');
  const suffix = roleKey ? `::${roleKey}` : '';
  if (mappingKey && suffix && mappingKey.endsWith(suffix)) return mappingKey.slice(0, -suffix.length);
  return String(object.typeKey || mappingKey || '');
}

function addRelationEndpointMappingIssue({ object, className, attr, rule, relationEndpointMappings, issues }) {
  const sourceRole = rule.sourceRole || 'self';
  if (!['source', 'destination'].includes(sourceRole)) return;
  const relationKey = relationEndpointMappingKeyForObject(object);
  const relationMapping = relationEndpointMappings && relationEndpointMappings[relationKey] || {};
  const attributeMappings = Array.isArray(relationMapping.attributes) ? relationMapping.attributes : [];
  const rowsForAttribute = attributeMappings.filter((row) =>
    row.relationClassName === className &&
    row.relationAttributeName === attr.name
  );
  if (!rowsForAttribute.length) {
    issues.push({ level: 'warning', code: 'relation_endpoint_mapping_missing', pageShapeKey: object.pageShapeKey, mappingKey: object.mappingKey, relationKey, className, attribute: attr.name, sourceRole, message: 'Для атрибута связи не настроен внешний endpoint-источник в блоке "Отразить на связь".' });
    return;
  }
}

function connectorLabelFor(object) {
  return object.objectType || object.relationType || object.pageShapeKey || 'Связь';
}

function addRelationBindingIssues(object, issues) {
  if (!object.sourceShapeId && !object.destinationShapeId && !object.relationBindingStatus) return;
  const base = {
    pageShapeKey: object.pageShapeKey,
    mappingKey: object.mappingKey,
    relation: connectorLabelFor(object),
    sourceShapeId: object.sourceShapeId || '',
    sourceKind: object.sourceKind || '',
    sourceText: object.sourceText || '',
    destinationShapeId: object.destinationShapeId || '',
    destinationKind: object.destinationKind || '',
    destinationText: object.destinationText || '',
    relationBindingStatus: object.relationBindingStatus || ''
  };
  if (object.relationBindingStatus === 'unbound') {
    issues.push({ level: 'warning', code: 'relation_unbound', ...base, message: `Связь "${base.relation}" не привязана ни к source, ни к destination.` });
  } else if (object.relationBindingStatus === 'partial') {
    issues.push({ level: 'warning', code: 'relation_partial', ...base, missingSide: object.sourceShapeId ? 'destination' : 'source', message: `Связь "${base.relation}" привязана только с одной стороны.` });
  } else if (object.relationBindingStatus === 'invalid_endpoint') {
    issues.push({ level: 'error', code: 'relation_invalid_endpoint', ...base, bindingIssue: object.relationBindingIssue || '', message: `Связь "${base.relation}" привязана к endpoint, которого нет в индексе фигур.` });
  }
  if (object.sourceKind === 'group') {
    issues.push({ level: 'warning', code: 'relation_group_endpoint', ...base, endpointSide: 'source', endpointShapeId: object.sourceShapeId || '', endpointText: object.sourceText || object.sourceObjectType || '', message: `Связь "${base.relation}" привязана к группе на стороне source; группа допустима, назначение будет разрешаться при сборке.` });
  }
  if (object.destinationKind === 'group') {
    issues.push({ level: 'warning', code: 'relation_group_endpoint', ...base, endpointSide: 'destination', endpointShapeId: object.destinationShapeId || '', endpointText: object.destinationText || object.destinationObjectType || '', message: `Связь "${base.relation}" привязана к группе на стороне destination; группа допустима, назначение будет разрешаться при сборке.` });
  }
}

function verifyObjectAttributeRule({ object, className, attr, rule, shapeByKey, relationEndpointMappings, contractParams, issues }) {
  const sourceRole = rule.sourceRole || 'self';
  const rowName = cmdbShapeDataRowName(className, attr.name);
  if (attr.mandatory && hasExpression(rule.sourceAttribute)) {
    const expressionValue = evaluateExpression(rule.sourceAttribute, { object, className, attr, rule, shapeByKey, contractParams });
    if (typeof expressionValue === 'undefined' || !String(expressionValue || '').trim()) {
      issues.push({ level: 'error', code: 'expression_value_empty', pageShapeKey: object.pageShapeKey, mappingKey: object.mappingKey, className, attribute: attr.name, expression: rule.sourceAttribute, message: 'Обязательный атрибут вычисляется выражением, но значение не найдено.' });
    }
    return;
  }
  if (['self', 'manual', 'override'].includes(sourceRole) && attr.mandatory && !hasFilledClassAttribute(object, className, attr.name)) {
    issues.push({ level: 'error', code: 'mandatory_attribute_empty', pageShapeKey: object.pageShapeKey, mappingKey: object.mappingKey, className, attribute: attr.name, sourceRole, message: 'Обязательный атрибут не заполнен.' });
  }
  if (sourceRole === 'constant' && attr.mandatory && !String(hasExpression(rule.constantValue) ? evaluateExpression(rule.constantValue, { object, className, attr, rule, shapeByKey, contractParams }) : rule.constantValue || '').trim()) {
    issues.push({ level: 'error', code: 'constant_value_empty', pageShapeKey: object.pageShapeKey, mappingKey: object.mappingKey, className, attribute: attr.name, message: 'Для обязательного атрибута выбран источник constant, но значение не задано.' });
  }
  if (!['source', 'destination'].includes(sourceRole)) return;
  addRelationEndpointMappingIssue({ object, className, attr, rule, relationEndpointMappings, issues });

  const endpointShapeId = sourceRole === 'source' ? object.sourceShapeId : object.destinationShapeId;
  const endpointKind = endpointKindFor(object, sourceRole);
  if (!endpointShapeId) {
    issues.push({ level: 'error', code: 'connection_endpoint_missing', pageShapeKey: object.pageShapeKey, mappingKey: object.mappingKey, className, attribute: attr.name, sourceRole, message: sourceRole === 'source' ? 'Для связи не определен source-объект.' : 'Для связи не определен destination-объект.' });
    return;
  }
  const endpointObject = objectForEndpoint(shapeByKey, object, endpointShapeId);
  if (!endpointObject) {
    if (endpointKind === 'group') {
      issues.push({ level: 'warning', code: 'endpoint_group_unresolved', pageShapeKey: object.pageShapeKey, endpointShapeId, endpointKind, endpointText: endpointTextFor(object, sourceRole), className, attribute: attr.name, sourceRole, message: 'Конец связи привязан к группе; группа не инвалидирует связь, но атрибут источника будет разрешаться на этапе сборки.' });
      return;
    }
    issues.push({ level: 'error', code: 'endpoint_object_not_found', pageShapeKey: object.pageShapeKey, endpointShapeId, className, attribute: attr.name, sourceRole, message: 'Конечная фигура связи не найдена среди CMDB-назначений шаблона.' });
    return;
  }
  if (!endpointObject.mappingKey || !(endpointObject.cmdbClasses || []).length) {
    if (endpointKind === 'group') {
      issues.push({ level: 'warning', code: 'endpoint_group_not_mapped', pageShapeKey: object.pageShapeKey, endpointPageShapeKey: endpointObject.pageShapeKey, endpointKind, endpointText: endpointTextFor(object, sourceRole), className, attribute: attr.name, sourceRole, message: 'Конец связи привязан к группе без прямого CMDB-назначения; группа допустима, назначение будет разрешаться на этапе сборки.' });
      return;
    }
    issues.push({ level: 'error', code: 'endpoint_not_cmdb_mapped', pageShapeKey: object.pageShapeKey, endpointPageShapeKey: endpointObject.pageShapeKey, className, attribute: attr.name, sourceRole, message: 'На конечной фигуре связи нет CMDB-назначения.' });
    return;
  }
}

function safeBusinessCode(value) {
  const text = String(value || '')
    .trim()
    .replace(/[^A-Za-z0-9_-]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-+/, '')
    .slice(0, 80);
  return /^[A-Za-z]/.test(text) ? text : `baa-${text || Date.now()}`;
}

function valueForClassAttribute(object, className, attrName) {
  const values = valueByRowName(object);
  const rowName = cmdbShapeDataRowName(className, attrName);
  if (Object.prototype.hasOwnProperty.call(values, rowName)) return values[rowName];
  const legacyRowName = legacyCmdbShapeDataRowName(className, attrName);
  return Object.prototype.hasOwnProperty.call(values, legacyRowName) ? values[legacyRowName] : undefined;
}

function hasExpression(value) {
  return /\$\{[^}]+\}/.test(String(value || ''));
}

function contractParamValue(contractParams = [], name = '') {
  const paramName = String(name || '').trim();
  if (!paramName) return undefined;
  const found = normalizeContractParams(contractParams).find((param) => param.name === paramName);
  return found ? found.defaultValue : undefined;
}

function visioParamValue(object, name) {
  const paramName = String(name || '').trim();
  if (!object || !paramName) return undefined;
  const values = valueByRowName(object);
  const candidates = [paramName, `template_${paramName}`];
  for (const candidate of candidates) {
    if (Object.prototype.hasOwnProperty.call(values, candidate)) return values[candidate];
  }
  const suffix = `_${paramName}`;
  const matchingKeys = Object.keys(values).filter((key) => key.endsWith(suffix));
  if (matchingKeys.length === 1) return values[matchingKeys[0]];
  return undefined;
}

function endpointObjectForRole(context, role) {
  const object = context.object || {};
  const shapeByKey = context.shapeByKey || new Map();
  if (role === 'relation') return object;
  if (role !== 'source' && role !== 'destination') return null;
  const shapeId = role === 'source' ? object.sourceShapeId : object.destinationShapeId;
  return objectForEndpoint(shapeByKey, object, shapeId);
}

function expressionTokenValue(token, context) {
  const text = String(token || '').trim();
  if (text.startsWith('contractparam.')) return contractParamValue(context.contractParams || [], text.slice('contractparam.'.length));
  if (text.startsWith('visioparam.')) return visioParamValue(context.object, text.slice('visioparam.'.length));
  for (const role of ['source', 'destination', 'relation']) {
    const prefix = `${role}.visioparam.`;
    if (text.startsWith(prefix)) return visioParamValue(endpointObjectForRole(context, role), text.slice(prefix.length));
  }
  return undefined;
}

function evaluateExpression(value, context = {}) {
  const text = String(value || '');
  const exact = text.match(/^\$\{([^}]+)\}$/);
  if (exact) return expressionTokenValue(exact[1], context);
  if (!hasExpression(text)) return text;
  return text.replace(/\$\{([^}]+)\}/g, (_match, token) => {
    const resolved = expressionTokenValue(token, context);
    return typeof resolved === 'undefined' || resolved === null ? '' : String(resolved);
  });
}

function payloadValueFromRule(object, className, attr, rule, shapeByKey, relationEndpointMappings, contractParams = []) {
  const sourceRole = rule.sourceRole || 'self';
  const expressionContext = { object, className, attr, rule, shapeByKey, contractParams };
  if (hasExpression(rule.sourceAttribute)) return evaluateExpression(rule.sourceAttribute, expressionContext);
  if (sourceRole === 'constant') return hasExpression(rule.constantValue) ? evaluateExpression(rule.constantValue, expressionContext) : rule.constantValue;
  if (sourceRole === 'default') {
    const ownValue = valueForClassAttribute(object, className, attr.name);
    return String(ownValue || '').trim() ? ownValue : hasExpression(rule.defaultValue) ? evaluateExpression(rule.defaultValue, expressionContext) : rule.defaultValue;
  }
  if (sourceRole === 'source' || sourceRole === 'destination') {
    const endpointShapeId = sourceRole === 'source' ? object.sourceShapeId : object.destinationShapeId;
    const endpointObject = objectForEndpoint(shapeByKey, object, endpointShapeId);
    const ref = sourceAttributeRefFromRelationMapping(object, rule, endpointObject, relationEndpointMappings);
    if (!endpointObject || !ref.className || !ref.attrName) return undefined;
    return valueForClassAttribute(endpointObject, ref.className, ref.attrName);
  }
  if (sourceRole === 'override') {
    const overrideAttr = String(rule.overrideAttribute || rule.targetAttribute || attr.name || '').trim();
    const overrideValue = valueForClassAttribute(object, className, overrideAttr);
    if (String(overrideValue || '').trim()) return overrideValue;
    const ownValue = valueForClassAttribute(object, className, attr.name);
    if (String(ownValue || '').trim()) return ownValue;
    return undefined;
  }
  return valueForClassAttribute(object, className, attr.name);
}

function endpointSummaryFor(object, shapeByKey, sourceRole) {
  const endpointShapeId = sourceRole === 'source' ? object.sourceShapeId : object.destinationShapeId;
  const endpointObject = objectForEndpoint(shapeByKey, object, endpointShapeId);
  return {
    role: sourceRole,
    shapeId: endpointShapeId || '',
    pageShapeKey: endpointObject && endpointObject.pageShapeKey || '',
    mappingKey: endpointObject && endpointObject.mappingKey || '',
    classes: endpointObject && endpointObject.cmdbClasses || []
  };
}

function attributeSourceTrace(object, className, attr, rule, shapeByKey, value, relationEndpointMappings) {
  const sourceRole = rule.sourceRole || 'self';
  const trace = {
    targetClass: className,
    targetAttribute: attr.name,
    mandatory: Boolean(attr.mandatory),
    description: attr.description || '',
    sourceRole,
    sourceAttribute: rule.sourceAttribute || attr.name || '',
    expression: hasExpression(rule.sourceAttribute) ? rule.sourceAttribute : '',
    sourcePageShapeKey: object.pageShapeKey,
    valuePresent: typeof value !== 'undefined' && String(value || '').trim() !== ''
  };
  if (sourceRole === 'source' || sourceRole === 'destination') {
    const endpoint = endpointSummaryFor(object, shapeByKey, sourceRole);
    const endpointObject = endpoint.pageShapeKey ? shapeByKey.get(endpoint.pageShapeKey) : null;
    const ref = sourceAttributeRefFromRelationMapping(object, rule, endpointObject, relationEndpointMappings);
    return {
      ...trace,
      endpoint,
      sourcePageShapeKey: endpoint.pageShapeKey,
      sourceClass: ref.className,
      sourceAttribute: ref.attrName
    };
  }
  if (sourceRole === 'constant') return { ...trace, sourceAttribute: '' };
  if (sourceRole === 'override') return { ...trace, overrideAttribute: rule.overrideAttribute || rule.targetAttribute || attr.name || '' };
  return trace;
}

function objectPayloadForClass(object, className, mapping, shapeByKey, relationEndpointMappings, contractParams = []) {
  const values = valueByRowName(object);
  const payload = {};
  const attributeSources = [];
  const attrByName = attributeDefinitionMap(mapping, className);
  for (const rule of mappingAttributeRules(mapping, className)) {
    const attr = attrByName.get(rule.targetAttribute) || { name: rule.targetAttribute };
    if (!attr.name) continue;
    const value = payloadValueFromRule(object, className, attr, rule, shapeByKey, relationEndpointMappings, contractParams);
    if (typeof value !== 'undefined') payload[attr.name] = value;
    attributeSources.push(attributeSourceTrace(object, className, attr, rule, shapeByKey, value, relationEndpointMappings));
  }
  const name = values.template_Name || values.CMDB_Name || object.objectType || `${className} ${object.pageShapeKey}`;
  if (!payload.Code) payload.Code = safeBusinessCode(`${className}-${object.page}-${object.shapeId}`);
  if (!payload.Description) payload.Description = String(name || payload.Code).slice(0, 250);
  return { payload, attributeSources };
}

function normalizeCreateValueOverrides(value) {
  if (!value || typeof value !== 'object') return new Map();
  const result = new Map();
  if (Array.isArray(value)) {
    for (const item of value) {
      if (!item || typeof item !== 'object') continue;
      const planIndex = Number.isFinite(Number(item.planIndex)) ? String(Number(item.planIndex)) : '';
      const pageShapeKey = String(item.pageShapeKey || '').trim();
      const className = String(item.className || '').trim();
      const attribute = String(item.attribute || item.targetAttribute || '').trim();
      const overrideValue = item.value;
      if (attribute && planIndex) result.set(`${planIndex}::${attribute}`, overrideValue);
      if (pageShapeKey && className && attribute) result.set(`${pageShapeKey}::${className}::${attribute}`, overrideValue);
    }
    return result;
  }
  for (const [key, overrideValue] of Object.entries(value)) {
    if (String(key || '').trim()) result.set(String(key), overrideValue);
  }
  return result;
}

function createOverrideValue(overrides, planIndex, object, className, attrName) {
  const keys = [
    `${planIndex}::${attrName}`,
    `${object.pageShapeKey}::${className}::${attrName}`
  ];
  for (const key of keys) {
    if (!overrides.has(key)) continue;
    const value = overrides.get(key);
    if (typeof value !== 'undefined' && String(value || '').trim()) return value;
  }
  return undefined;
}

function applyCreateOverrides(payloadPlan, overrides, planIndex, object, className) {
  if (!overrides || !overrides.size) return payloadPlan;
  const payload = { ...payloadPlan.payload };
  const attributeSources = payloadPlan.attributeSources.map((source) => {
    const attrName = source.targetAttribute || '';
    const overrideValue = createOverrideValue(overrides, planIndex, object, className, attrName);
    if (typeof overrideValue === 'undefined') return source;
    payload[attrName] = overrideValue;
    return {
      ...source,
      sourceRole: 'ui_override',
      sourceAttribute: attrName,
      sourcePageShapeKey: object.pageShapeKey,
      valuePresent: true
    };
  });
  return { payload, attributeSources };
}

function buildCreationPlan(verification, valueOverrides = new Map()) {
  const rules = parseRulesJson(verification.contractVersion && verification.contractVersion.rulesJson);
  const relationEndpointMappings = normalizeRelationEndpointMappings(rules.relationEndpointMappings || {});
  const contractParams = normalizeContractParams(rules.contractParams || []);
  const mappings = mappingByKeyFromRules(rules);
  const shapeByKey = objectsByPageShapeKey(verification.objects || []);
  const objects = [];
  const skipped = [];
  for (const object of verification.objects || []) {
    if (object.action === 'skip') {
      skipped.push({ pageShapeKey: object.pageShapeKey, reason: 'action_skip' });
      continue;
    }
    const mapping = mappings.get(object.mappingKey);
    if (!mapping) {
      skipped.push({ pageShapeKey: object.pageShapeKey, reason: 'mapping_not_found', mappingKey: object.mappingKey });
      continue;
    }
    for (const className of object.cmdbClasses || []) {
      const planIndex = objects.length;
      const rawPayloadPlan = objectPayloadForClass(object, className, mapping, shapeByKey, relationEndpointMappings, contractParams);
      const payloadPlan = applyCreateOverrides(rawPayloadPlan, valueOverrides, planIndex, object, className);
      const missingAttributes = payloadPlan.attributeSources.filter((source) => source.mandatory && !source.valuePresent).map((source) => ({
        className: source.targetClass,
        attribute: source.targetAttribute,
        description: source.description || '',
        sourceRole: source.sourceRole || '',
        sourceAttribute: source.sourceAttribute || '',
        expression: source.expression || '',
        pageShapeKey: source.sourcePageShapeKey || object.pageShapeKey
      }));
      objects.push({
        pageShapeKey: object.pageShapeKey,
        mappingKey: object.mappingKey,
        className,
        kind: object.relationType || object.sourceShapeId || object.destinationShapeId ? 'context' : 'object',
        relationBindingStatus: object.relationBindingStatus || '',
        endpoints: object.sourceShapeId || object.destinationShapeId ? {
          source: endpointSummaryFor(object, shapeByKey, 'source'),
          destination: endpointSummaryFor(object, shapeByKey, 'destination')
        } : null,
        payload: payloadPlan.payload,
        attributeSources: payloadPlan.attributeSources,
        missingAttributes
      });
    }
  }
  return {
    objects,
    skipped,
    missingAttributes: objects.flatMap((item, index) => (item.missingAttributes || []).map((missing) => ({
      ...missing,
      planIndex: index
    })))
  };
}

async function verifyBaaTemplate(authToken, input = {}) {
  const buffer = Buffer.from(String(input.fileBase64 || ''), 'base64');
  if (!buffer.length) throw new Error('fileBase64 is required.');
  const extracted = withTempFile('cmdbaa-verify-', '.vsdx', buffer, (filePath) => extractBaaObjectsFromVsdx(filePath));
  const metadata = extracted.contractMetadata || {};
  const issues = [];
  if (!metadata.contractVersionId && !metadata.contractVersionCode) {
    issues.push({ level: 'error', code: 'missing_contract_version', message: 'В файле нет версии контракта.' });
  }
  if (!metadata.contractPageShapeKey || String(metadata.contractObject || '').toLowerCase() !== 'true') {
    issues.push({ level: 'error', code: 'missing_contract_object', message: 'В файле не выбран объект контракта. Привяжите контракт к объекту на схеме и заново сохраните шаблон.' });
  }
  const versionsResult = await listConversionContractVersions(authToken);
  if (!versionsResult.success) {
    issues.push({ level: 'error', code: 'contract_versions_unavailable', message: versionsResult.message || 'Не удалось загрузить версии контрактов.' });
  }
  const version = (versionsResult.data || []).find((item) =>
    (metadata.contractVersionId && item.id === metadata.contractVersionId) ||
    (metadata.contractVersionCode && item.code === metadata.contractVersionCode)
  ) || null;
  if (!version && (metadata.contractVersionId || metadata.contractVersionCode)) {
    issues.push({ level: 'error', code: 'contract_version_not_found', message: 'Версия контракта из VSDX не найдена в CMDBuild.' });
  }
  if (version && metadata.contractVersionChecksum && version.rulesChecksum && metadata.contractVersionChecksum !== version.rulesChecksum) {
    issues.push({ level: 'error', code: 'contract_checksum_mismatch', message: 'Контрольная сумма правил версии контракта не совпадает.' });
  }
  const rules = parseRulesJson(version && version.rulesJson);
  const relationEndpointMappings = normalizeRelationEndpointMappings(rules.relationEndpointMappings || {});
  const contractParams = normalizeContractParams(rules.contractParams || []);
  const mappings = mappingByKeyFromRules(rules);
  const shapeByKey = objectsByPageShapeKey(extracted.objects);
  if (!extracted.objects.length) {
    issues.push({ level: 'error', code: 'no_cmdb_objects', message: 'В файле не найдены фигуры с CMDB-назначениями.' });
  }
  for (const object of extracted.objects) {
    addRelationBindingIssues(object, issues);
    for (const item of object.attributeRules || []) {
      if (item && item.parseError) {
        issues.push({ level: 'error', code: 'attribute_rule_invalid_json', pageShapeKey: object.pageShapeKey, rowName: item.rowName, message: 'Техническое правило атрибута в VSDX повреждено.' });
      }
    }
    if (!object.mappingKey) {
      issues.push({ level: 'error', code: 'missing_mapping_key', pageShapeKey: object.pageShapeKey, message: 'У фигуры нет _baa_MappingKey.' });
      continue;
    }
    const mapping = mappings.get(object.mappingKey);
    if (!mapping) {
      issues.push({ level: 'error', code: 'mapping_not_in_contract', pageShapeKey: object.pageShapeKey, mappingKey: object.mappingKey, message: 'Назначение фигуры отсутствует в версии контракта.' });
      continue;
    }
    const allowedClasses = new Set(mapping.classes || []);
    const actualClasses = object.cmdbClasses || [];
    for (const className of actualClasses) {
      if (!allowedClasses.has(className)) {
        issues.push({ level: 'error', code: 'class_not_in_contract', pageShapeKey: object.pageShapeKey, mappingKey: object.mappingKey, className, message: 'Класс фигуры отсутствует в назначении контракта.' });
      }
      const attrByName = attributeDefinitionMap(mapping, className);
      const attrRules = mappingAttributeRules(mapping, className);
      const needsConnectionEndpoints = attrRules.some((rule) => ['source', 'destination'].includes(rule.sourceRole));
      if (needsConnectionEndpoints && object.relationBindingStatus && object.relationBindingStatus !== 'bound' && object.relationBindingStatus !== 'invalid_endpoint') {
        issues.push({ level: 'error', code: 'connection_binding_invalid', pageShapeKey: object.pageShapeKey, mappingKey: object.mappingKey, className, relationBindingStatus: object.relationBindingStatus, message: 'Связь не привязана к двум допустимым CMDB-объектам.' });
      }
      for (const rule of attrRules) {
        const attr = attrByName.get(rule.targetAttribute) || { name: rule.targetAttribute, mandatory: false };
        verifyObjectAttributeRule({ object, className, attr, rule, shapeByKey, relationEndpointMappings, contractParams, issues });
      }
    }
  }
  return {
    success: !issues.some((issue) => issue.level === 'error'),
    metadata,
    contractVersion: version ? {
      ...publicContractVersion(version),
      rulesJson: version.rulesJson
    } : null,
    summary: {
      objects: extracted.objects.length,
      mappings: mappings.size,
      errors: issues.filter((issue) => issue.level === 'error').length,
      warnings: issues.filter((issue) => issue.level === 'warning').length
    },
    issues,
    objects: extracted.objects
  };
}

async function checkBaaTemplateTechnical(authToken, input = {}) {
  const buffer = Buffer.from(String(input.fileBase64 || ''), 'base64');
  if (!buffer.length) throw new Error('fileBase64 is required.');
  const extracted = withTempFile('cmdbaa-check-template-', '.vsdx', buffer, (filePath) => extractBaaObjectsFromVsdx(filePath));
  const metadata = extracted.contractMetadata || {};
  const issues = [];
  if (!metadata.contractVersionId && !metadata.contractVersionCode) {
    issues.push({ level: 'error', code: 'missing_contract_version', message: 'В файле нет технической версии контракта.' });
  }
  if (!metadata.contractPageShapeKey || String(metadata.contractObject || '').toLowerCase() !== 'true') {
    issues.push({ level: 'error', code: 'missing_contract_object', message: 'В файле не найден объект, к которому привязан контракт.' });
  }
  const versionsResult = await listConversionContractVersions(authToken);
  if (!versionsResult.success) {
    issues.push({ level: 'error', code: 'contract_versions_unavailable', message: versionsResult.message || 'Не удалось загрузить версии контрактов.' });
  }
  const version = (versionsResult.data || []).find((item) =>
    (metadata.contractVersionId && item.id === metadata.contractVersionId) ||
    (metadata.contractVersionCode && item.code === metadata.contractVersionCode)
  ) || null;
  if (!version && (metadata.contractVersionId || metadata.contractVersionCode)) {
    issues.push({ level: 'error', code: 'contract_version_not_found', message: 'Версия контракта из VSDX не найдена в CMDBuild.' });
  }
  if (version && metadata.contractVersionChecksum && version.rulesChecksum && metadata.contractVersionChecksum !== version.rulesChecksum) {
    issues.push({ level: 'error', code: 'contract_checksum_mismatch', message: 'Контрольная сумма правил версии контракта не совпадает.' });
  }
  const rules = parseRulesJson(version && version.rulesJson);
  const mappings = mappingByKeyFromRules(rules);
  if (!extracted.objects.length) {
    issues.push({ level: 'error', code: 'no_cmdb_objects', message: 'В файле не найдены фигуры с CMDB-назначениями.' });
  }
  for (const object of extracted.objects) {
    if (Array.isArray(object.unexpectedTechnicalRows) && object.unexpectedTechnicalRows.length) {
      for (const row of object.unexpectedTechnicalRows) {
        issues.push({ level: 'error', code: 'visible_lowercase_baa_field', pageShapeKey: object.pageShapeKey, rowName: row.name, message: 'В Shape Data найдено видимое техническое поле baa_*. Пересохраните шаблон после исправления генератора.' });
      }
    }
    for (const item of object.attributeRules || []) {
      if (item && item.parseError) {
        issues.push({ level: 'error', code: 'attribute_rule_invalid_json', pageShapeKey: object.pageShapeKey, rowName: item.rowName, message: 'Техническое правило атрибута в VSDX повреждено.' });
      }
    }
    if (!object.mappingKey) {
      issues.push({ level: 'error', code: 'missing_mapping_key', pageShapeKey: object.pageShapeKey, message: 'У фигуры нет технического ключа назначения _baa_MappingKey.' });
    } else if (version && !mappings.has(object.mappingKey)) {
      issues.push({ level: 'error', code: 'mapping_not_in_contract', pageShapeKey: object.pageShapeKey, mappingKey: object.mappingKey, message: 'Техническое назначение фигуры отсутствует в версии контракта.' });
    }
    if (!object.cmdbClasses || !object.cmdbClasses.length) {
      issues.push({ level: 'error', code: 'missing_template_class', pageShapeKey: object.pageShapeKey, mappingKey: object.mappingKey, message: 'У фигуры нет заполненного template_Class.' });
    }
    addRelationBindingIssues(object, issues);
  }
  return {
    success: !issues.some((issue) => issue.level === 'error'),
    metadata,
    contractVersion: version ? publicContractVersion(version) : null,
    summary: {
      objects: extracted.objects.length,
      mappings: mappings.size,
      errors: issues.filter((issue) => issue.level === 'error').length,
      warnings: issues.filter((issue) => issue.level === 'warning').length
    },
    assumptions: [
      'Техническая проверка не проверяет бизнес-обязательность атрибутов CMDB.',
      'Группы и контейнеры допустимы как визуальные объекты, если контракт назначен на их anchor.',
      'Непривязанные связи фиксируются как предупреждения, а не как запрет дальнейшей работы.',
      'Пользовательские данные ожидаются в template_*; технические поля ожидаются только в _baa_*.'
    ],
    issues,
    objects: extracted.objects.map((object) => ({
      pageShapeKey: object.pageShapeKey,
      mappingKey: object.mappingKey,
      cmdbClass: object.cmdbClass,
      relationBindingStatus: object.relationBindingStatus || '',
      valueCount: object.values && object.values.length || 0
    }))
  };
}

async function technicalTemplateContext(authToken, input = {}) {
  const buffer = Buffer.from(String(input.fileBase64 || ''), 'base64');
  if (!buffer.length) throw new Error('fileBase64 is required.');
  const extracted = withTempFile('cmdbaa-create-', '.vsdx', buffer, (filePath) => extractBaaObjectsFromVsdx(filePath));
  const metadata = extracted.contractMetadata || {};
  const issues = [];
  if (!metadata.contractVersionId && !metadata.contractVersionCode) {
    issues.push({ level: 'error', code: 'missing_contract_version', message: 'В файле нет технической версии контракта.' });
  }
  if (!metadata.contractPageShapeKey || String(metadata.contractObject || '').toLowerCase() !== 'true') {
    issues.push({ level: 'error', code: 'missing_contract_object', message: 'В файле не найден объект, к которому привязан контракт.' });
  }
  const versionsResult = await listConversionContractVersions(authToken);
  if (!versionsResult.success) {
    issues.push({ level: 'error', code: 'contract_versions_unavailable', message: versionsResult.message || 'Не удалось загрузить версии контрактов.' });
  }
  const version = (versionsResult.data || []).find((item) =>
    (metadata.contractVersionId && item.id === metadata.contractVersionId) ||
    (metadata.contractVersionCode && item.code === metadata.contractVersionCode)
  ) || null;
  if (!version && (metadata.contractVersionId || metadata.contractVersionCode)) {
    issues.push({ level: 'error', code: 'contract_version_not_found', message: 'Версия контракта из VSDX не найдена в CMDBuild.' });
  }
  if (version && metadata.contractVersionChecksum && version.rulesChecksum && metadata.contractVersionChecksum !== version.rulesChecksum) {
    issues.push({ level: 'error', code: 'contract_checksum_mismatch', message: 'Контрольная сумма правил версии контракта не совпадает.' });
  }
  const rules = parseRulesJson(version && version.rulesJson);
  const mappings = mappingByKeyFromRules(rules);
  if (!extracted.objects.length) {
    issues.push({ level: 'error', code: 'no_cmdb_objects', message: 'В файле не найдены фигуры с CMDB-назначениями.' });
  }
  for (const object of extracted.objects) {
    if (Array.isArray(object.unexpectedTechnicalRows) && object.unexpectedTechnicalRows.length) {
      for (const row of object.unexpectedTechnicalRows) {
        issues.push({ level: 'error', code: 'visible_lowercase_baa_field', pageShapeKey: object.pageShapeKey, rowName: row.name, message: 'В Shape Data найдено видимое техническое поле baa_*. Пересохраните шаблон после исправления генератора.' });
      }
    }
    for (const item of object.attributeRules || []) {
      if (item && item.parseError) {
        issues.push({ level: 'error', code: 'attribute_rule_invalid_json', pageShapeKey: object.pageShapeKey, rowName: item.rowName, message: 'Техническое правило атрибута в VSDX повреждено.' });
      }
    }
    if (!object.mappingKey) {
      issues.push({ level: 'error', code: 'missing_mapping_key', pageShapeKey: object.pageShapeKey, message: 'У фигуры нет технического ключа назначения _baa_MappingKey.' });
    } else if (version && !mappings.has(object.mappingKey)) {
      issues.push({ level: 'error', code: 'mapping_not_in_contract', pageShapeKey: object.pageShapeKey, mappingKey: object.mappingKey, message: 'Техническое назначение фигуры отсутствует в версии контракта.' });
    }
    if (!object.cmdbClasses || !object.cmdbClasses.length) {
      issues.push({ level: 'error', code: 'missing_template_class', pageShapeKey: object.pageShapeKey, mappingKey: object.mappingKey, message: 'У фигуры нет заполненного template_Class.' });
    }
    addRelationBindingIssues(object, issues);
  }
  return {
    success: !issues.some((issue) => issue.level === 'error'),
    metadata,
    contractVersion: version,
    summary: {
      objects: extracted.objects.length,
      mappings: mappings.size,
      errors: issues.filter((issue) => issue.level === 'error').length,
      warnings: issues.filter((issue) => issue.level === 'warning').length
    },
    issues,
    objects: extracted.objects
  };
}

async function createObjectsFromBaaTemplate(authToken, input = {}) {
  const execute = Boolean(input.execute);
  const valueOverrides = normalizeCreateValueOverrides(input.valueOverrides);
  const technical = await technicalTemplateContext(authToken, input);
  if (!technical.success) {
    return {
      success: false,
      executed: false,
      message: 'Создание невозможно: VSDX не прошел техническую проверку.',
      verification: {
        ...technical,
        contractVersion: publicContractVersion(technical.contractVersion)
      }
    };
  }
  const plan = buildCreationPlan(technical, valueOverrides);
  const businessIssues = await verifyBaaTemplate(authToken, input);
  const valueCompletenessCodes = new Set(['mandatory_attribute_empty', 'expression_value_empty', 'constant_value_empty']);
  const blockingIssues = (businessIssues.issues || []).filter((issue) => issue.level === 'error' && !valueCompletenessCodes.has(issue.code));
  if (!plan.objects.length) {
    return {
      success: false,
      executed: false,
      message: 'Создание невозможно: по VSDX не сформирован ни один объект.',
      verification: {
        metadata: technical.metadata,
        contractVersion: publicContractVersion(technical.contractVersion),
        summary: technical.summary
      },
      plan,
      results: [],
      canExecute: false,
      summary: {
        planned: 0,
        skipped: plan.skipped.length,
        created: 0,
        failed: 0
      }
    };
  }
  if (execute && (blockingIssues.length || plan.missingAttributes.length)) {
    return {
      success: false,
      executed: false,
      message: 'Создание невозможно: есть незаполненные обязательные атрибуты.',
      verification: {
        metadata: technical.metadata,
        contractVersion: publicContractVersion(technical.contractVersion),
        summary: technical.summary,
        issues: businessIssues.issues || []
      },
      plan,
      results: [],
      canExecute: false,
      summary: {
        planned: plan.objects.length,
        skipped: plan.skipped.length,
        contextPlanned: plan.objects.filter((item) => item.kind === 'context').length,
        missing: plan.missingAttributes.length,
        blockingIssues: blockingIssues.length,
        created: 0,
        failed: 0
      }
    };
  }
  const results = [];
  if (execute) {
    for (let index = 0; index < plan.objects.length; index += 1) {
      const item = plan.objects[index];
      const response = await cmdbuildRequest(`/cmdbuild/services/rest/v3/classes/${encodeURIComponent(item.className)}/cards`, authToken, {
        method: 'POST',
        body: item.payload
      });
      results.push({
        planIndex: index,
        pageShapeKey: item.pageShapeKey,
        mappingKey: item.mappingKey,
        className: item.className,
        kind: item.kind || 'object',
        relationBindingStatus: item.relationBindingStatus || '',
        endpoints: item.endpoints || null,
        payload: item.payload,
        attributeSources: item.attributeSources || [],
        success: response.ok,
        cmdbuildStatus: response.statusCode,
        id: response.json && response.json.data && (response.json.data._id || response.json.data.Id || response.json.data.id) || null,
        cmdbuildData: response.ok ? response.json && response.json.data || null : null,
        message: response.ok ? '' : cmdbuildErrorMessage(response, 'CMDBuild card create failed.')
      });
    }
  }
  return {
    success: !execute || results.every((item) => item.success),
    executed: execute,
    verification: {
      metadata: technical.metadata,
      contractVersion: publicContractVersion(technical.contractVersion),
      summary: technical.summary,
      issues: businessIssues.issues || []
    },
    plan,
    results,
    canExecute: !blockingIssues.length && !plan.missingAttributes.length,
    summary: {
      planned: plan.objects.length,
      skipped: plan.skipped.length,
      contextPlanned: plan.objects.filter((item) => item.kind === 'context').length,
      missing: plan.missingAttributes.length,
      blockingIssues: blockingIssues.length,
      created: results.filter((item) => item.success).length,
      failed: results.filter((item) => !item.success).length
    }
  };
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

function mappingSnapshot(classMap = {}, attributeMap = {}, attributeCatalog = {}, attributeListModes = {}, attributeSourceRules = {}) {
  return Object.keys(classMap || {}).map((key) => {
    const classes = normalizeClassValue(classMap[key]).split(',').map((item) => item.trim()).filter(Boolean);
    if (!classes.length) return null;
    const attributesByClass = {};
    const attributeRules = [];
    for (const className of classes) {
      const selectedNames = Array.isArray(attributeMap[`${key}::${className}`])
        ? attributeMap[`${key}::${className}`].map((item) => String(item || '').trim()).filter(Boolean)
        : [];
      const catalog = Array.isArray(attributeCatalog[className]) ? attributeCatalog[className] : [];
      const byName = new Map(catalog.map((attr) => [attr && attr.name, attr]).filter((item) => item[0]));
      attributesByClass[className] = selectedNames.map((attrName) => {
        const attr = byName.get(attrName) || { name: attrName };
        const sourceRule = attributeSourceRuleFor(attributeSourceRules, key, className, attrName);
        attributeRules.push(sourceRule);
        return {
          name: attrName,
          description: attr.description || attrName,
          type: attr.type || '',
          mandatory: Boolean(attr.mandatory),
          listMode: attr.resolvedListMode || attributeListModes[`${key}::${className}::${attrName}`] || 'none',
          listSource: attr.resolvedListSource || attr.lookupType || attr.targetClass || attr.domain || '',
          listWarning: attr.resolvedListWarning || '',
          sourceRule
        };
      }).sort((a, b) => String(a.name).localeCompare(String(b.name)));
    }
    return {
      key,
      classes: classes.sort((a, b) => String(a).localeCompare(String(b))),
      attributesByClass,
      attributeRules: attributeRules.sort((a, b) =>
        String(a.targetClass).localeCompare(String(b.targetClass)) ||
        String(a.targetAttribute).localeCompare(String(b.targetAttribute)) ||
        String(a.sourceRole).localeCompare(String(b.sourceRole)) ||
        String(a.sourceAttribute).localeCompare(String(b.sourceAttribute)) ||
        String(a.mode).localeCompare(String(b.mode))
      )
    };
  }).filter(Boolean).sort((a, b) => String(a.key).localeCompare(String(b.key)));
}

function mappingMapsFromKnownMappings(knownMappings = []) {
  const classMap = {};
  const attributeMap = {};
  const attributeListModes = {};
  const attributeSourceRules = {};
  for (const mapping of knownMappings || []) {
    const key = String(mapping && mapping.key || '').trim();
    if (!key) continue;
    const classes = Array.isArray(mapping.classes)
      ? mapping.classes.map((item) => String(item || '').trim()).filter(Boolean)
      : normalizeClassValue(mapping.classes || '').split(',').map((item) => item.trim()).filter(Boolean);
    if (classes.length) classMap[key] = normalizeClassValue([classMap[key] || '', ...classes].join(', '));
    const attributesByClass = mapping && mapping.attributesByClass && typeof mapping.attributesByClass === 'object'
      ? mapping.attributesByClass
      : {};
    for (const className of Object.keys(attributesByClass)) {
      const attrKey = `${key}::${className}`;
      const existing = new Set(Array.isArray(attributeMap[attrKey]) ? attributeMap[attrKey] : []);
      for (const attr of attributesByClass[className] || []) {
        const attrName = String(attr && (attr.name || attr.attrName) || '').trim();
        if (!attrName) continue;
        existing.add(attrName);
        if (attr.listMode) attributeListModes[`${attrKey}::${attrName}`] = String(attr.listMode);
        if (attr.sourceRule) attributeSourceRules[`${attrKey}::${attrName}`] = attr.sourceRule;
      }
      attributeMap[attrKey] = Array.from(existing).sort((a, b) => String(a).localeCompare(String(b)));
    }
  }
  return {
    classMap,
    attributeMap,
    attributeListModes,
    attributeSourceRules
  };
}

function mergeMappingMaps(base = {}, current = {}) {
  const classMap = { ...(base.classMap || {}) };
  const attributeMap = { ...(base.attributeMap || {}) };
  const attributeListModes = { ...(base.attributeListModes || {}) };
  const attributeSourceRules = { ...(base.attributeSourceRules || {}) };
  for (const [key, value] of Object.entries(current.classMap || {})) {
    const classes = normalizeClassValue([classMap[key] || '', value || ''].join(', '));
    if (classes) classMap[key] = classes;
  }
  for (const [key, values] of Object.entries(current.attributeMap || {})) {
    const merged = new Set(Array.isArray(attributeMap[key]) ? attributeMap[key] : []);
    for (const value of Array.isArray(values) ? values : []) {
      const normalized = String(value || '').trim();
      if (normalized) merged.add(normalized);
    }
    attributeMap[key] = Array.from(merged).sort((a, b) => String(a).localeCompare(String(b)));
  }
  Object.assign(attributeListModes, current.attributeListModes || {});
  Object.assign(attributeSourceRules, current.attributeSourceRules || {});
  return {
    classMap,
    attributeMap,
    attributeListModes,
    attributeSourceRules
  };
}

function currentMappingMaps(classMap = {}, attributeMap = {}, attributeListModes = {}, attributeSourceRules = {}) {
  return {
    classMap: classMap || {},
    attributeMap: attributeMap || {},
    attributeListModes: attributeListModes || {},
    attributeSourceRules: attributeSourceRules || {}
  };
}

function normalizeRelationEndpointMappings(value = {}) {
  const result = {};
  for (const [relationKey, mapping] of Object.entries(value || {})) {
    const key = String(relationKey || '').trim();
    if (!key || !mapping || typeof mapping !== 'object') continue;
    const rows = Array.isArray(mapping.attributes) ? mapping.attributes : [];
    const seen = new Set();
    const attributes = rows.map((row) => ({
      relationClassName: String(row && (row.relationClassName || row.targetClass || row.classOnRelation) || '').trim(),
      relationAttributeName: String(row && (row.relationAttributeName || row.targetAttribute || row.attributeOnRelation) || '').trim(),
      className: String(row && (row.className || row.endpointClass) || '').trim(),
      attributeName: String(row && (row.attributeName || row.endpointAttribute) || '').trim()
    })).filter((row) => {
      const rowKey = `${row.relationClassName}::${row.relationAttributeName}::${row.className}::${row.attributeName}`;
      if (!row.relationClassName || !row.relationAttributeName || !row.className || !row.attributeName || seen.has(rowKey)) return false;
      seen.add(rowKey);
      return true;
    }).sort((a, b) =>
      String(a.relationClassName).localeCompare(String(b.relationClassName)) ||
      String(a.relationAttributeName).localeCompare(String(b.relationAttributeName)) ||
      String(a.className).localeCompare(String(b.className)) ||
      String(a.attributeName).localeCompare(String(b.attributeName))
    );
    if (attributes.length) {
      result[key] = { attributes };
      continue;
    }
    const legacySides = {};
    for (const side of ['source', 'destination']) {
      const sideRows = Array.isArray(mapping[side]) ? mapping[side] : [];
      const sideSeen = new Set();
      legacySides[side] = sideRows.map((row) => ({
        className: String(row && (row.className || row.endpointClass) || '').trim(),
        attributeName: String(row && (row.attributeName || row.endpointAttribute) || '').trim()
      })).filter((row) => {
        const rowKey = `${row.className}::${row.attributeName}`;
        if (!row.className || !row.attributeName || sideSeen.has(rowKey)) return false;
        sideSeen.add(rowKey);
        return true;
      }).sort((a, b) =>
        String(a.className).localeCompare(String(b.className)) ||
        String(a.attributeName).localeCompare(String(b.attributeName))
      );
    }
    if (legacySides.source.length || legacySides.destination.length) result[key] = legacySides;
  }
  return result;
}

function relationEndpointMappingSignature(value = {}) {
  return JSON.stringify(normalizeRelationEndpointMappings(value));
}

function mergeRelationEndpointMappings(previous = {}, current = {}) {
  const normalizedPrevious = normalizeRelationEndpointMappings(previous);
  const normalizedCurrent = normalizeRelationEndpointMappings(current);
  const merged = normalizeRelationEndpointMappings({ ...normalizedPrevious, ...normalizedCurrent });
  return {
    relationEndpointMappings: merged,
    changed: relationEndpointMappingSignature(merged) !== relationEndpointMappingSignature(normalizedPrevious)
  };
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

function attributeRuleIdentity(rule) {
  return `${rule.targetClass || ''}::${rule.targetAttribute || ''}`;
}

function attributeRuleSignature(rule) {
  return [
    rule.targetClass || '',
    rule.targetAttribute || '',
    rule.sourceRole || '',
    rule.sourceAttribute || '',
    rule.mode || '',
    rule.constantValue || '',
    rule.defaultValue || '',
    rule.overrideAttribute || ''
  ].join('::');
}

function sortedAttributeRules(rules) {
  return Array.from(rules || []).sort((a, b) =>
    String(a.targetClass).localeCompare(String(b.targetClass)) ||
    String(a.targetAttribute).localeCompare(String(b.targetAttribute)) ||
    String(a.sourceRole).localeCompare(String(b.sourceRole)) ||
    String(a.sourceAttribute).localeCompare(String(b.sourceAttribute)) ||
    String(a.mode).localeCompare(String(b.mode))
  );
}

function mappingRulesFromItem(item = {}) {
  const byIdentity = new Map();
  for (const [className, attrs] of Object.entries(item.attributesByClass || {})) {
    for (const attr of Array.isArray(attrs) ? attrs : []) {
      if (!attr || !attr.name) continue;
      const rule = normalizeAttributeSourceRule(attr.sourceRule || {}, className, attr.name);
      byIdentity.set(attributeRuleIdentity(rule), rule);
    }
  }
  for (const rule of Array.isArray(item.attributeRules) ? item.attributeRules : []) {
    const normalized = normalizeAttributeSourceRule(rule, rule && rule.targetClass, rule && rule.targetAttribute);
    byIdentity.set(attributeRuleIdentity(normalized), normalized);
  }
  return sortedAttributeRules(byIdentity.values());
}

function mappingWithNormalizedRules(item) {
  return {
    key: item.key,
    classes: Array.isArray(item.classes) ? [...item.classes].sort((a, b) => String(a).localeCompare(String(b))) : [],
    attributesByClass: item.attributesByClass && typeof item.attributesByClass === 'object' ? { ...item.attributesByClass } : {},
    attributeRules: mappingRulesFromItem(item)
  };
}

function attributeSignature(attr) {
  const rule = normalizeAttributeSourceRule(attr && attr.sourceRule || {}, attr && attr.className || '', attr && attr.name || '');
  return JSON.stringify({
    name: attr && attr.name || '',
    description: attr && attr.description || '',
    type: attr && attr.type || '',
    mandatory: Boolean(attr && attr.mandatory),
    listMode: attr && attr.listMode || 'none',
    listSource: attr && attr.listSource || '',
    sourceRule: attributeRuleSignature(rule)
  });
}

function mergeKnownMappings(previous, current) {
  const byKey = new Map();
  for (const item of previous || []) {
    if (!item || !item.key) continue;
    byKey.set(item.key, mappingWithNormalizedRules(item));
  }
  const added = [];
  for (const item of current || []) {
    if (!item || !item.key) continue;
    if (!byKey.has(item.key)) {
      byKey.set(item.key, mappingWithNormalizedRules(item));
      added.push(item);
      continue;
    }
    const existing = byKey.get(item.key);
    const classSet = new Set(existing.classes || []);
    const existingRules = new Map((existing.attributeRules || []).map((rule) => [attributeRuleIdentity(rule), rule]));
    let changed = false;
    for (const className of item.classes || []) {
      if (!classSet.has(className)) changed = true;
      classSet.add(className);
      const prevAttrs = Array.isArray(existing.attributesByClass[className]) ? existing.attributesByClass[className] : [];
      const prevByName = new Map(prevAttrs.map((attr) => [attr && attr.name, attr]).filter((entry) => entry[0]));
      for (const attr of item.attributesByClass[className] || []) {
        if (!attr || !attr.name) continue;
        if (!prevByName.has(attr.name) || attributeSignature(prevByName.get(attr.name)) !== attributeSignature(attr)) changed = true;
        prevByName.set(attr.name, { ...prevByName.get(attr.name), ...attr });
        const rule = normalizeAttributeSourceRule(attr.sourceRule || {}, className, attr.name);
        const ruleKey = attributeRuleIdentity(rule);
        if (!existingRules.has(ruleKey) || attributeRuleSignature(existingRules.get(ruleKey)) !== attributeRuleSignature(rule)) changed = true;
        existingRules.set(ruleKey, rule);
      }
      existing.attributesByClass[className] = Array.from(prevByName.values()).sort((a, b) => String(a.name).localeCompare(String(b.name)));
    }
    existing.classes = Array.from(classSet).sort((a, b) => String(a).localeCompare(String(b)));
    for (const rule of item.attributeRules || []) {
      const normalizedRule = normalizeAttributeSourceRule(rule, rule && rule.targetClass, rule && rule.targetAttribute);
      const ruleKey = attributeRuleIdentity(normalizedRule);
      if (!existingRules.has(ruleKey) || attributeRuleSignature(existingRules.get(ruleKey)) !== attributeRuleSignature(normalizedRule)) changed = true;
      existingRules.set(ruleKey, normalizedRule);
    }
    existing.attributeRules = sortedAttributeRules(existingRules.values());
    if (changed) added.push(item);
    byKey.set(item.key, existing);
  }
  return {
    knownMappings: Array.from(byKey.values()).sort((a, b) => String(a.key).localeCompare(String(b.key))),
    addedMappings: added
  };
}

async function resolveContractVersionForEnrichment(authToken, input = {}) {
  const contract = input.contract || {};
  const currentTypes = typeSnapshot(input.types || []);
  const currentAggregates = aggregateSnapshot(input.aggregates || []);
  const currentMappings = mappingSnapshot(input.aggregateClassMap || {}, input.aggregateAttributeMap || {}, input.attributeCatalog || {}, input.attributeListModes || {}, input.attributeSourceRules || {});
  const typeRules = input.typeRules || {};
  const currentContractParams = normalizeContractParams(input.contractParams || typeRules.contractParams || []);
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
  const mergedMappings = mergeKnownMappings(Array.isArray(latestRules.knownMappings) ? latestRules.knownMappings : [], currentMappings);
  const mergedRelationEndpointMappings = mergeRelationEndpointMappings(latestRules.relationEndpointMappings || {}, input.relationEndpointMappings || {});
  const mergedContractParams = mergeContractParams(latestRules.contractParams || [], currentContractParams);
  const namespacesChanged = JSON.stringify(latestRules.shapeDataNamespaces || {}) !== JSON.stringify(SHAPE_DATA_NAMESPACES);
  if (latest && merged.addedTypes.length === 0 && mergedAggregates.addedAggregates.length === 0 && mergedMappings.addedMappings.length === 0 && !mergedRelationEndpointMappings.changed && !mergedContractParams.changed && !namespacesChanged) {
    return {
      version: latest,
      action: 'reused',
      addedTypes: [],
      knownTypes: merged.knownTypes,
      addedAggregates: [],
      knownAggregates: mergedAggregates.knownAggregates,
      addedMappings: [],
      knownMappings: mergedMappings.knownMappings,
      relationEndpointMappings: mergedRelationEndpointMappings.relationEndpointMappings,
      contractParams: mergedContractParams.contractParams
    };
  }
  const versionNumber = nextVersionNumber(contractVersions);
  const rulesObject = {
    ...typeRules,
    shapeDataNamespaces: SHAPE_DATA_NAMESPACES,
    knownTypes: merged.knownTypes,
    knownAggregates: mergedAggregates.knownAggregates,
    knownMappings: mergedMappings.knownMappings,
    contractParams: mergedContractParams.contractParams,
    relationEndpointMappings: mergedRelationEndpointMappings.relationEndpointMappings
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
    knownAggregates: mergedAggregates.knownAggregates,
    addedMappings: latest ? mergedMappings.addedMappings : currentMappings,
    knownMappings: mergedMappings.knownMappings,
    contractParams: mergedContractParams.contractParams,
    relationEndpointMappings: mergedRelationEndpointMappings.relationEndpointMappings
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
  if (section === 'check-template' || section === 'template-check' || section === 'technical-check') return 'check-template';
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
    .table-wrap{overflow:auto;border:1px solid var(--line);background:#fff}.type-table{width:100%;border-collapse:collapse}.type-table th,.type-table td{border-bottom:1px solid var(--line);padding:7px 8px;text-align:left;vertical-align:top}.type-table th{background:#f0f4f8;color:#334e68}.type-key{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:11px;color:var(--muted);overflow-wrap:anywhere}.shape-data{display:flex;gap:5px;flex-wrap:wrap}.sd-pill{border:1px solid var(--line);background:#f8fafc;border-radius:4px;padding:2px 5px;font-size:11px}.file-input{display:none}.file-name{color:var(--muted);font-size:12px}.file-status{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.checksum-status{padding:5px 7px;border:1px solid var(--line);background:#f8fafc;font-size:12px}.checksum-status.ok{border-color:#a7d8b5;color:var(--ok);background:#f4fbf6}.checksum-status.error{border-color:#f0b8b0;color:var(--danger);background:#fff7f5}.checksum-ext{width:110px}.check-label{display:flex;align-items:center;gap:7px;color:var(--text);font-size:13px}.check-label input{width:auto}.column-toggles{display:flex;gap:8px;flex-wrap:wrap;padding:6px 8px;border-bottom:1px solid var(--line);background:#f8fafc}.contract-selector{align-items:flex-end}.contract-selector button,.template-toolbar button{min-height:31px;padding:6px 10px}.contract-selector label{min-width:280px}.object-editor{display:grid;grid-template-columns:1fr;gap:10px;padding:10px;border-bottom:1px solid var(--line);background:#fff}.object-editor select{width:100%;min-height:0}.object-editor-left{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:8px;align-content:start}.object-editor-left label,.assignment-panel label{display:grid;gap:5px}.object-editor-right{display:grid;gap:8px}.assignment-panel{border:1px solid var(--line);background:#fff;padding:8px;margin-bottom:8px}.assignment-panel select{width:100%;min-height:0}.class-assignment{border:1px solid var(--line);background:#f8fafc;margin-bottom:8px}.class-assignment summary{cursor:pointer;padding:7px 8px}.class-assignment-body{padding:8px;border-top:1px solid var(--line);background:#fff}.attribute-group{border:1px solid var(--line);background:#f8fafc;margin:8px 0}.attribute-group summary{cursor:pointer;padding:7px 8px}.attribute-group-body{padding:8px;border-top:1px solid var(--line);background:#fff}.attribute-list{display:grid;gap:6px;max-height:220px;overflow:auto;border:1px solid var(--line);background:#f8fafc;padding:8px}.object-row{border:1px solid var(--line);background:#f8fafc;margin-bottom:7px}.object-row summary{cursor:pointer;padding:7px 8px}.object-row-body{display:grid;grid-template-columns:minmax(220px,360px) minmax(0,1fr);gap:8px;padding:8px;border-top:1px solid var(--line);background:#fff}.aggregate-summary{border:1px solid var(--line);background:#f8fafc;padding:8px}.aggregate-summary summary{cursor:pointer}.composition-list{display:grid;gap:4px;margin-top:6px}.composition-item{display:flex;justify-content:space-between;gap:8px;border-bottom:1px solid #e8eef5;padding-bottom:3px}.composition-item:last-child{border-bottom:0}.tabs{display:inline-flex;border:1px solid var(--line);background:#fff}.tabs button{border:0;border-right:1px solid var(--line);border-radius:0}.tabs button:last-child{border-right:0}.tabs button.active{background:var(--accent-soft);color:#07575b;font-weight:bold}.right-actions{display:flex;justify-content:flex-end;gap:8px;flex-wrap:wrap;margin-top:10px}.compact-toolbar{margin-bottom:8px}.compact-toolbar h3{margin-right:auto}.compact-actions{margin-top:6px}button.icon-button{width:30px;height:30px;padding:0;font-weight:bold}.template-toolbar{margin-bottom:8px}
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
      <a href="${UI_PREFIX}/check-template" data-section="check-template">Проверить шаблон</a>
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
    'check-template': 'Проверить шаблон',
    verify: 'Верифицировать',
    'create-objects': 'Создать объекты'
  };
  var defaultSettings = {
    checksumExtension: 'sha256',
    verifyChecksumOnPrepare: true,
    referenceFixedListLimit: 50
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
      keepDecorativeShapesUnchanged: true,
      decomposeAggregates: false
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
    settings.referenceFixedListLimit = Math.max(1, Number.parseInt(String(settings.referenceFixedListLimit || '50'), 10) || 50);
    return settings;
  }
  function writeSettings(settings) {
    var next = Object.assign({}, defaultSettings, settings || {});
    next.checksumExtension = String(next.checksumExtension || 'sha256').trim().replace(/^\\.+/, '') || 'sha256';
    next.verifyChecksumOnPrepare = next.verifyChecksumOnPrepare !== false;
    next.referenceFixedListLimit = Math.max(1, Number.parseInt(String(next.referenceFixedListLimit || '50'), 10) || 50);
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
  function currentDecomposeAggregates() {
    return Boolean(readTypeRules().presentation.decomposeAggregates);
  }
  function syncPrepareDecomposeFromRules() {
    if (typeof prepareState === 'undefined') return currentDecomposeAggregates();
    prepareState.decomposeAggregates = currentDecomposeAggregates();
    return prepareState.decomposeAggregates;
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
      '<label>Максимум объектов reference для постоянного списка<input id="settings-reference-limit" type="number" min="1" value="' + escapeHtml(settings.referenceFixedListLimit) + '"></label>',
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
      '<label class="check-label"><input id="rule-decompose-aggregates" type="checkbox"' + (rules.presentation.decomposeAggregates ? ' checked' : '') + ' data-rule-control="1">Декомпозировать группы и контейнеры</label>',
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
        keepDecorativeShapesUnchanged: Boolean(document.getElementById('rule-keep-decorative') && document.getElementById('rule-keep-decorative').checked),
        decomposeAggregates: Boolean(document.getElementById('rule-decompose-aggregates') && document.getElementById('rule-decompose-aggregates').checked)
      }
    };
  }
  function updateContractSelect() {
    updatePrepareContractSelect();
    updatePrepareContractVersionSelect();
  }
  function updatePrepareContractSelect() {
    var select = document.getElementById('prepare-contract');
    if (!select) return;
    select.innerHTML = contractOptionsHtml(contractsState.contracts);
    if (prepareState.contractId && Array.prototype.some.call(select.options, function (option) { return option.value === prepareState.contractId; })) {
      select.value = prepareState.contractId;
    }
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
    var contract = selectedPrepareContract();
    var version = selectedPrepareContractVersion();
    if (version) {
      target.textContent = 'Версия: ' + version.contractCode + ' / ' + version.version + ' / ' + version.code;
      return;
    }
    if (prepareState.contractMetadata && (prepareState.contractMetadata.contractVersionCode || prepareState.contractMetadata.contractVersionId)) {
      target.textContent = 'Версия: ' + (prepareState.contractMetadata.contractVersionCode || prepareState.contractMetadata.contractVersionId);
      return;
    }
    if (contract && (contract.code || contract.id)) {
      target.textContent = 'Контракт выбран: ' + (contract.code || contract.id) + '. Версия будет создана при обогащении.';
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
    if (!prepareState.contractId && !prepareState.contractCode) return null;
    return {
      id: prepareState.contractId || '',
      code: prepareState.contractCode || ''
    };
  }
  function prepareContractSelectorHtml() {
    var options = contractsState.contracts && contractsState.contracts.length
      ? contractsState.contracts.map(function (contract) {
        return '<option value="' + escapeHtml(contract.id || '') + '" data-code="' + escapeHtml(contract.code) + '"' + (contract.id === prepareState.contractId ? ' selected' : '') + '>' + escapeHtml(contract.code + (contract.name ? ' / ' + contract.name : '')) + '</option>';
      }).join('')
      : '<option value="">Нет контрактов</option>';
    return '<div class="column-toggles contract-selector"><label>Контракт<select id="prepare-contract">' + options + '</select></label><button type="button" data-action="assign-prepare-contract">Выбрать контракт</button><button type="button" data-action="reload-contracts">Обновить контракты</button><button class="primary" type="button" data-action="enrich-vsdx">Завершить наполнение и сохранить шаблон</button></div>';
  }
  function contractWorkspaceHtml() {
    return '<section class="section"><h2>Работа с контрактом шаблона</h2>' + prepareContractSelectorHtml() + contractBindingHtml() + '<div id="contract-work-status" class="notice">Выберите контракт и объект контракта на схеме перед сохранением шаблона.</div></section>';
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
      contractWorkspaceHtml(),
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
    loadCmdbClassesForPrepare();
  }
  function renderPrepare() {
    function tabButton(tab, label) {
      return '<button' + (prepareState.activeTab === tab ? ' class="active"' : '') + ' type="button" data-action="prepare-tab" data-tab="' + tab + '">' + label + '</button>';
    }
    app.innerHTML = [
      '<div class="toolbar template-toolbar"><button class="primary" type="button" data-action="choose-vsdx">Загрузить и разобрать vhdx</button><button type="button" data-action="choose-checksum">Загрузить файл контрольной суммы</button><input id="vsdx-file" class="file-input" type="file" multiple></div>',
      '<section class="section"><div class="toolbar"><div class="tabs">' + tabButton('types', 'Типы') + tabButton('shapes', 'Фигуры') + tabButton('enrich', 'Обогатить') + tabButton('relation-map', 'Отразить на связь') + tabButton('contract-params', 'Параметры контракта') + '</div></div><div id="prepare-view" class="notice">Загрузите .vsdx для извлечения типов фигур.</div></section>'
    ].join('');
    updatePrepareContractVersionSummary();
    loadContracts().then(loadContractVersions);
    loadCmdbClassesForPrepare();
    renderChecksumStatus(prepareState.checksum);
    renderPrepareData();
  }
  function renderVerify() {
    app.innerHTML = [
      '<div class="toolbar"><button class="primary" type="button" data-action="choose-verify-vsdx">Загрузить и проверить VSDX</button><button type="button" data-action="check-session">Проверить сессию</button><input id="verify-vsdx-file" class="file-input" type="file" accept=".vsdx"></div>',
      '<section class="section"><h2>Верифицировать</h2><p class="muted">Загрузите заполненный после обогащения VSDX. Проверка сверит версию контракта, назначенные классы и обязательные атрибуты.</p></section>',
      '<section class="section"><h3>Результат</h3><pre id="status">Проверка еще не запускалась.</pre></section>'
    ].join('');
  }
  function renderCheckTemplate() {
    app.innerHTML = [
      '<div class="toolbar"><button class="primary" type="button" data-action="choose-check-template-vsdx">Загрузить и проверить шаблон</button><button type="button" data-action="check-session">Проверить сессию</button><input id="check-template-vsdx-file" class="file-input" type="file" accept=".vsdx"></div>',
      '<section class="section"><h2>Проверить шаблон</h2><p class="muted">Техническая проверка файла: наличие версии контракта, объекта контракта, служебных _baa_* полей, назначений template_Class и состояния привязки связей. Бизнес-обязательность атрибутов здесь не проверяется.</p></section>',
      '<section class="section"><h3>Результат</h3><div id="status" class="notice">Проверка еще не запускалась.</div></section>'
    ].join('');
  }
  function renderCreate() {
    var fileLine = createState.fileName ? 'Файл: ' + createState.fileName : 'Файл не выбран';
    app.innerHTML = [
      '<div class="toolbar"><button class="primary" type="button" data-action="choose-create-vsdx">Загрузить VSDX и сформировать план</button><button type="button" data-action="rebuild-create-plan">Перестроить план</button><button type="button" data-action="execute-create-objects">Создать в CMDB</button><button type="button" data-action="check-session">Проверить сессию</button><input id="create-vsdx-file" class="file-input" type="file" accept=".vsdx"></div>',
      '<section class="section"><h2>Создать объекты</h2><p class="muted">' + escapeHtml(fileLine) + '</p><p class="muted">Сначала строится план. Недостающие обязательные значения можно дозаполнить ниже, перестроить план и только затем выполнить создание.</p></section>',
      '<section class="section"><h3>Результат</h3><div id="status" class="notice">Создание еще не запускалось.</div></section>'
    ].join('');
    if (createState.lastResult) showCreateResult(createState.lastResult, createState.lastOk);
  }
  function showStatus(value, ok) {
    var target = document.getElementById('status');
    if (!target) return;
    target.className = ok === false ? 'notice error' : ok === true ? 'notice ok' : 'notice';
    target.textContent = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  }
  function checkTemplateIssuesHtml(issues) {
    if (!issues || !issues.length) return '<div class="notice ok">Ошибок не найдено.</div>';
    return '<div class="table-wrap"><table class="type-table"><thead><tr><th>Уровень</th><th>Код</th><th>Фигура</th><th>Сообщение</th></tr></thead><tbody>' + issues.map(function (issue) {
      return '<tr><td>' + escapeHtml(issue.level || '') + '</td><td>' + escapeHtml(issue.code || '') + '</td><td>' + escapeHtml(issue.pageShapeKey || '') + '</td><td>' + escapeHtml(issue.message || '') + '</td></tr>';
    }).join('') + '</tbody></table></div>';
  }
  function showCheckTemplateResult(value, ok) {
    var target = document.getElementById('status');
    if (!target) return;
    if (!value || typeof value !== 'object') {
      showStatus(value || '', ok);
      return;
    }
    var success = Boolean(value.success);
    var errors = value.summary && value.summary.errors || (value.issues || []).filter(function (issue) { return issue.level === 'error'; }).length;
    var warnings = value.summary && value.summary.warnings || (value.issues || []).filter(function (issue) { return issue.level === 'warning'; }).length;
    target.className = success ? 'notice ok' : 'notice error';
    target.innerHTML = [
      '<div class="toolbar compact-toolbar"><strong>' + escapeHtml(success ? '✓ Шаблон проверен' : '✕ Есть ошибки') + '</strong><span class="muted">Ошибок: ' + escapeHtml(errors) + ' / предупреждений: ' + escapeHtml(warnings) + '</span></div>',
      success ? '<div>Техническая проверка шаблона выполнена успешно.</div>' : '<div>Исправьте ошибки ниже и повторите проверку.</div>',
      checkTemplateIssuesHtml(value.issues || []),
      '<details><summary>Техническая часть</summary><pre>' + escapeHtml(JSON.stringify(value, null, 2)) + '</pre></details>'
    ].join('');
  }
  function keyValueTableHtml(value) {
    var entries = Object.entries(value || {});
    if (!entries.length) return '<span class="muted">нет значений</span>';
    return '<div class="table-wrap"><table class="type-table"><thead><tr><th>Поле</th><th>Значение</th></tr></thead><tbody>' + entries.map(function (entry) {
      return '<tr><td>' + escapeHtml(entry[0]) + '</td><td>' + escapeHtml(entry[1]) + '</td></tr>';
    }).join('') + '</tbody></table></div>';
  }
  function endpointHtml(endpoint) {
    if (!endpoint || !endpoint.pageShapeKey) return '<span class="muted">не определен</span>';
    return escapeHtml(endpoint.pageShapeKey) + '<br><span class="muted">' + escapeHtml((endpoint.classes || []).join(', ') || 'класс не назначен') + '</span>';
  }
  function attributeSourcesTableHtml(sources) {
    if (!sources || !sources.length) return '<span class="muted">нет источников</span>';
    return '<div class="table-wrap"><table class="type-table"><thead><tr><th>Атрибут</th><th>Источник</th><th>Фигура</th><th>Обяз.</th><th>Значение</th></tr></thead><tbody>' + sources.map(function (item) {
      var source = item.sourceRole || '';
      if (item.sourceClass || item.sourceAttribute) source += ' / ' + [item.sourceClass, item.sourceAttribute].filter(Boolean).join('.');
      return '<tr><td>' + escapeHtml([item.targetClass, item.targetAttribute].filter(Boolean).join('.')) + '</td><td>' + escapeHtml(source) + '</td><td>' + escapeHtml(item.sourcePageShapeKey || '') + '</td><td>' + escapeHtml(item.mandatory ? 'да' : '') + '</td><td>' + escapeHtml(item.valuePresent ? 'есть' : 'пусто') + '</td></tr>';
    }).join('') + '</tbody></table></div>';
  }
  function createOverrideKey(item) {
    return String(Number(item.planIndex || 0)) + '::' + String(item.attribute || '');
  }
  function missingAttributesHtml(missing) {
    if (!missing || !missing.length) return '<div class="notice ok">Обязательные атрибуты заполнены.</div>';
    return '<div class="notice error"><strong>Есть незаполненные обязательные атрибуты: ' + escapeHtml(missing.length) + '</strong></div><div class="table-wrap"><table class="type-table"><thead><tr><th>План</th><th>Фигура</th><th>Класс</th><th>Атрибут</th><th>Источник</th><th>Дозаполнить</th></tr></thead><tbody>' + missing.map(function (item) {
      var source = item.expression || [item.sourceRole, item.sourceAttribute].filter(Boolean).join(' / ');
      var key = createOverrideKey(item);
      var value = createState.valueOverrides[key] || '';
      return '<tr><td>' + escapeHtml(Number(item.planIndex || 0) + 1) + '</td><td>' + escapeHtml(item.pageShapeKey || '') + '</td><td>' + escapeHtml(item.className || '') + '</td><td>' + escapeHtml(item.attribute || '') + '</td><td>' + escapeHtml(source) + '</td><td><input data-create-override-key="' + escapeHtml(key) + '" value="' + escapeHtml(value) + '"></td></tr>';
    }).join('') + '</tbody></table></div>';
  }
  function createPlanHtml(plan) {
    var objects = plan && plan.objects || [];
    if (!objects.length) return '<div class="notice">План пуст.</div>';
    return objects.map(function (item, index) {
      var endpointBlock = item.endpoints ? '<div class="grid"><div><strong>Source</strong><br>' + endpointHtml(item.endpoints.source) + '</div><div><strong>Destination</strong><br>' + endpointHtml(item.endpoints.destination) + '</div></div>' : '';
      var missingMark = item.missingAttributes && item.missingAttributes.length ? ' / не заполнено: ' + item.missingAttributes.length : '';
      return '<details class="object-row" open><summary><strong>' + escapeHtml(String(index + 1) + '. ' + item.className) + '</strong> <span class="muted">' + escapeHtml((item.kind || 'object') + missingMark) + ' / ' + escapeHtml(item.pageShapeKey || '') + '</span></summary><div class="object-row-body"><div>' + endpointBlock + '<div class="type-key">Mapping: ' + escapeHtml(item.mappingKey || '') + '</div></div><div><h4>Payload</h4>' + keyValueTableHtml(item.payload) + '<h4>Источники атрибутов</h4>' + attributeSourcesTableHtml(item.attributeSources) + '</div></div></details>';
    }).join('');
  }
  function createResultsTableHtml(results) {
    if (!results || !results.length) return '<span class="muted">создание не выполнялось</span>';
    return '<div class="table-wrap"><table class="type-table"><thead><tr><th>Класс</th><th>Тип</th><th>Фигура</th><th>Статус</th><th>ID</th><th>Сообщение</th></tr></thead><tbody>' + results.map(function (item) {
      return '<tr><td>' + escapeHtml(item.className || '') + '</td><td>' + escapeHtml(item.kind || 'object') + '</td><td>' + escapeHtml(item.pageShapeKey || '') + '</td><td>' + escapeHtml(item.success ? 'создано' : 'ошибка') + '</td><td>' + escapeHtml(item.id || '') + '</td><td>' + escapeHtml(item.message || '') + '</td></tr>';
    }).join('') + '</tbody></table></div>';
  }
  function showCreateResult(value, ok) {
    var target = document.getElementById('status');
    if (!target) return;
    target.className = ok === false ? 'notice error' : ok === true ? 'notice ok' : 'notice';
    if (!value || typeof value !== 'object') {
      target.textContent = String(value || '');
      return;
    }
    target.innerHTML = '<div class="toolbar compact-toolbar"><strong>' + escapeHtml(value.executed ? 'Создание объектов' : 'План создания') + '</strong><span class="muted">Запланировано: ' + escapeHtml(value.summary && value.summary.planned || 0) + ' / пропущено: ' + escapeHtml(value.summary && value.summary.skipped || 0) + ' / не заполнено: ' + escapeHtml(value.summary && value.summary.missing || 0) + ' / блокирующих ошибок: ' + escapeHtml(value.summary && value.summary.blockingIssues || 0) + ' / создано: ' + escapeHtml(value.summary && value.summary.created || 0) + ' / ошибок: ' + escapeHtml(value.summary && value.summary.failed || 0) + '</span></div>' + missingAttributesHtml(value.plan && value.plan.missingAttributes || []) + createPlanHtml(value.plan || {}) + '<h4>Результаты выполнения</h4>' + createResultsTableHtml(value.results || []);
  }
  var createState = {
    fileName: '',
    fileBase64: '',
    valueOverrides: {},
    lastResult: null,
    lastOk: null
  };
  var prepareState = {
    file: null,
    fileName: '',
    fileBase64: '',
    checksumFile: null,
    checksumFileName: '',
    checksumText: '',
    contractId: '',
    contractCode: '',
    contractVersionId: '',
    contractMetadata: null,
    contractAnchorKey: '',
    types: [],
    aggregates: [],
    selectedTypeKey: '',
    cmdbClasses: [],
    cmdbClassAttributes: {},
    classAssignments: {},
    collapsedClassAssignments: {},
    attributeAssignments: {},
    attributeListModes: {},
    attributeSourceRules: {},
    relationEndpointMappings: {},
    contractParams: [],
    selectedRelationKey: '',
    attributeColumns: {
      name: true,
      description: true,
      help: true,
      type: true,
      mandatory: true,
      list: true,
      source: true,
      valueSource: true,
      sourceMode: true
    },
    showConnectors: true,
    showShapeTechnicalInfo: false,
    decomposeAggregates: false,
    selectedRoleKey: '',
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
        contractId: prepareState.contractId,
        contractCode: prepareState.contractCode,
        contractVersionId: prepareState.contractVersionId,
        contractMetadata: prepareState.contractMetadata,
        contractAnchorKey: prepareState.contractAnchorKey,
        types: prepareState.types,
        aggregates: prepareState.aggregates,
        selectedTypeKey: prepareState.selectedTypeKey,
        selectedRoleKey: prepareState.selectedRoleKey,
        cmdbClassAttributes: prepareState.cmdbClassAttributes,
        classAssignments: prepareState.classAssignments,
        collapsedClassAssignments: prepareState.collapsedClassAssignments,
        attributeAssignments: prepareState.attributeAssignments,
        attributeListModes: prepareState.attributeListModes,
        attributeSourceRules: prepareState.attributeSourceRules,
        relationEndpointMappings: prepareState.relationEndpointMappings,
        contractParams: prepareState.contractParams,
        selectedRelationKey: prepareState.selectedRelationKey,
        attributeColumns: prepareState.attributeColumns,
        showConnectors: prepareState.showConnectors,
        showShapeTechnicalInfo: prepareState.showShapeTechnicalInfo,
        decomposeAggregates: prepareState.decomposeAggregates,
        activeTab: prepareState.activeTab,
        columns: prepareState.columns,
        checksum: prepareState.checksum
      }));
    } catch (error) {}
  }
  function syncVisibleAttributeAssignmentsFromDom() {
    var inputs = document.querySelectorAll('input[data-object-attribute]');
    if (!inputs || !inputs.length) return;
    var seen = {};
    var grouped = {};
    Array.prototype.forEach.call(inputs, function (input) {
      var key = input.getAttribute('data-object-attribute') || '';
      var value = input.value || '';
      if (!key || !value) return;
      seen[key] = true;
      if (!grouped[key]) grouped[key] = [];
      if (input.checked && grouped[key].indexOf(value) === -1) grouped[key].push(value);
    });
    Object.keys(seen).forEach(function (key) {
      prepareState.attributeAssignments[key] = (grouped[key] || []).sort(function (left, right) {
        return String(left).localeCompare(String(right));
      });
    });
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
      prepareState.contractId = stored.contractId || '';
      prepareState.contractCode = stored.contractCode || '';
      prepareState.contractVersionId = stored.contractVersionId || '';
      prepareState.contractMetadata = stored.contractMetadata || null;
      prepareState.contractAnchorKey = stored.contractAnchorKey || '';
      prepareState.types = Array.isArray(stored.types) ? stored.types : [];
      prepareState.aggregates = Array.isArray(stored.aggregates) ? stored.aggregates : [];
      prepareState.selectedTypeKey = stored.selectedTypeKey || '';
      prepareState.selectedRoleKey = stored.selectedRoleKey || '';
      prepareState.cmdbClassAttributes = stored.cmdbClassAttributes || {};
      prepareState.classAssignments = stored.classAssignments || {};
      prepareState.collapsedClassAssignments = stored.collapsedClassAssignments || {};
      prepareState.attributeAssignments = stored.attributeAssignments || {};
      prepareState.attributeListModes = stored.attributeListModes || {};
      prepareState.attributeSourceRules = stored.attributeSourceRules || {};
      prepareState.relationEndpointMappings = stored.relationEndpointMappings || {};
      prepareState.contractParams = Array.isArray(stored.contractParams) ? stored.contractParams : [];
      prepareState.selectedRelationKey = stored.selectedRelationKey || '';
      prepareState.attributeColumns = Object.assign({}, prepareState.attributeColumns, stored.attributeColumns || {});
      prepareState.showConnectors = stored.showConnectors !== false;
      prepareState.showShapeTechnicalInfo = stored.showShapeTechnicalInfo === true;
      prepareState.decomposeAggregates = stored.decomposeAggregates === true;
      prepareState.activeTab = stored.activeTab || 'types';
      prepareState.columns = Object.assign({}, prepareState.columns, stored.columns || {});
      prepareState.checksum = Object.assign({}, prepareState.checksum, stored.checksum || {});
    } catch (error) {}
    syncPrepareDecomposeFromRules();
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
  function assignmentModeHtml(aggregate) {
    if (aggregate && aggregate.kind === 'connector') {
      var sample = aggregate.instances && aggregate.instances[0];
      var connection = sample && sample.atoms && sample.atoms[0] && sample.atoms[0].connection || null;
      return '<div class="notice ok"><strong>Контекстное назначение связи</strong><br>CMDB-экземпляр будет собираться из source-объекта, линии связи и destination-объекта.' + (connection ? '<div class="type-key">Source Shape: ' + escapeHtml(connection.sourceShapeId || 'не определен') + ' / Destination Shape: ' + escapeHtml(connection.destinationShapeId || 'не определен') + '</div>' : '') + '</div>';
    }
    return '<div class="notice"><strong>Объектное назначение</strong><br>Выбранные атрибуты будут записаны на эту фигуру и затем собраны из нее как из self-источника.</div>';
  }
  function assignmentPanelTitle(aggregate) {
    return aggregate && aggregate.kind === 'connector' ? 'Контекстное назначение связи' : 'Назначение CMDB';
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
  function classDepth(item, byName) {
    var depth = 0;
    var parent = item && item.parent || '';
    var seen = {};
    while (parent && byName[parent] && !seen[parent]) {
      seen[parent] = true;
      depth += 1;
      parent = byName[parent].parent || '';
    }
    return depth;
  }
  function classSortKey(item, byName) {
    var chain = [];
    var cursor = item;
    var seen = {};
    while (cursor && cursor.name && !seen[cursor.name]) {
      seen[cursor.name] = true;
      chain.unshift(cursor.description || cursor.name);
      cursor = byName[cursor.parent || ''];
    }
    return chain.join(' / ').toLowerCase();
  }
  function sortedCmdbClasses() {
    var list = (prepareState.cmdbClasses || []).filter(function (item) { return item.active !== false && !item.prototype; });
    var byName = {};
    (prepareState.cmdbClasses || []).forEach(function (item) { if (item && item.name) byName[item.name] = item; });
    return list.slice().sort(function (left, right) {
      return classSortKey(left, byName).localeCompare(classSortKey(right, byName)) ||
        classDepth(left, byName) - classDepth(right, byName) ||
        String(left.name).localeCompare(String(right.name));
    });
  }
  function assignmentClasses(key) {
    var value = prepareState.classAssignments[key];
    if (Array.isArray(value)) return value.slice();
    return value ? [value] : [];
  }
  function selectedAssignmentClasses(key) {
    return assignmentClasses(key).filter(Boolean);
  }
  function setAssignmentClasses(key, values) {
    prepareState.classAssignments[key] = (values || []).slice();
  }
  function classAssignmentCollapseKey(key, index) {
    return key + '::slot::' + index;
  }
  function classSelectHtml(key, index, value) {
    return '<select data-object-class="' + escapeHtml(key) + '" data-object-class-index="' + escapeHtml(index) + '"><option value="">Класс не выбран</option>' + sortedCmdbClasses().map(function (item) {
      var label = item.description && item.description !== item.name ? item.description + ' / ' + item.name : item.name;
      return '<option value="' + escapeHtml(item.name) + '"' + (item.name === value ? ' selected' : '') + '>' + escapeHtml(label) + '</option>';
    }).join('') + '</select>';
  }
  function aggregateKindText(kind) {
    if (kind === 'container') return 'контейнер';
    if (kind === 'group') return 'группа';
    if (kind === 'single') return 'одиночная фигура';
    if (kind === 'connector') return 'связь';
    return kind || '';
  }
  function userValueText(source) {
    if (!source || !source.path) return '';
    return source.value || '[пустое значение]';
  }
  function pagePathText(source, fallbackPage) {
    var path = source && source.path || '';
    var marker = 'visio/pages/';
    var start = String(path).indexOf(marker);
    if (start !== -1) {
      var rest = String(path).slice(start);
      var end = rest.indexOf(' ');
      return end === -1 ? rest : rest.slice(0, end);
    }
    return fallbackPage ? 'visio/pages/' + fallbackPage : '';
  }
  function atomDisplayLabel(atom, index) {
    return userValueText(atom && atom.userValueSource) || atom && atom.label || ('Часть ' + (index + 1));
  }
  function lastAggregationText(entity) {
    var aggregation = entity && entity.lastAggregation;
    if (!aggregation) return '';
    var label = userValueText(aggregation.userValueSource) || aggregation.label || aggregation.shapeId || '';
    return aggregateKindText(aggregation.kind) + ': ' + label + (prepareState.showShapeTechnicalInfo && aggregation.shapeId ? ' / Shape ' + aggregation.shapeId : '');
  }
  function compositionText(atoms) {
    return (atoms || []).map(function (atom, index) {
      var label = atomDisplayLabel(atom, index);
      return label + ' #' + (atom.shapeId || '');
    }).join(' + ');
  }
  function aggregatePrimaryText(aggregate) {
    var own = userValueText(aggregate && aggregate.userValueSource);
    if (own) return own;
    var sample = aggregate && aggregate.instances && aggregate.instances[0];
    var textAtoms = sample ? (sample.atoms || []).filter(function (atom) { return atom.userValueSource && atom.userValueSource.path; }) : [];
    textAtoms.sort(function (a, b) {
      return (userValueText(a.userValueSource) === '[пустое значение]' ? 1 : 0) - (userValueText(b.userValueSource) === '[пустое значение]' ? 1 : 0);
    });
    if (textAtoms.length) return textAtoms.map(function (atom, index) { return atomDisplayLabel(atom, index); }).join(' + ');
    return aggregate && aggregate.label || '';
  }
  function hasVisibleUserText(aggregate) {
    if (aggregate && aggregate.userValueSource && aggregate.userValueSource.path && aggregate.userValueSource.value) return true;
    return (aggregate && aggregate.instances || []).some(function (instance) {
      return (instance.atoms || []).some(function (atom) {
        return atom.userValueSource && atom.userValueSource.path && atom.userValueSource.value;
      });
    });
  }
  function aggregateContextText(aggregate) {
    var sample = aggregate && aggregate.instances && aggregate.instances[0];
    var atomWithAggregation = sample && (sample.atoms || []).filter(function (atom) { return atom.lastAggregation; })[0];
    if (atomWithAggregation) return lastAggregationText(atomWithAggregation);
    if (aggregate && (aggregate.kind === 'group' || aggregate.kind === 'container')) {
      return aggregateKindText(aggregate.kind) + ': ' + (userValueText(aggregate.userValueSource) || aggregate.label || '');
    }
    return aggregateKindText(aggregate && aggregate.kind);
  }
  function aggregateOptionLabel(aggregate) {
    var sample = aggregate.instances && aggregate.instances[0];
    var composition = sample ? compositionText(sample.atoms) : (aggregate.atomRoles || []).map(function (role) { return role.label; }).join(' + ');
    if (!prepareState.showShapeTechnicalInfo) return aggregatePrimaryText(aggregate) + ' [' + aggregateContextText(aggregate) + ']';
    return aggregatePrimaryText(aggregate) + ' [' + aggregateContextText(aggregate) + ', ' + (aggregate.instances || []).length + '] ' + composition;
  }
  function aggregateSummaryHtml(aggregate) {
    var sample = aggregate && aggregate.instances && aggregate.instances[0];
    var atoms = sample && sample.atoms || [];
    var pagePath = pagePathText(aggregate && aggregate.userValueSource, sample && sample.page);
    var title = prepareState.decomposeAggregates && (aggregate.kind === 'group' || aggregate.kind === 'container') ? 'Состав агрегированного типа' : 'Состав выбранного типа';
    var visibleAtoms = atoms.slice(0, prepareState.showShapeTechnicalInfo ? 30 : 12).map(function (atom, index) {
      var label = atomDisplayLabel(atom, index);
      var path = pagePathText(atom.userValueSource, atom.page);
      var meta = prepareState.showShapeTechnicalInfo ? roleMetaText(atom) : '';
      return '<div class="composition-item"><strong>' + escapeHtml(label) + '</strong><span class="muted">' + escapeHtml([atom.kind, path, meta].filter(Boolean).join(' / ')) + '</span></div>';
    }).join('');
    var rest = atoms.length > (prepareState.showShapeTechnicalInfo ? 30 : 12) ? '<div class="muted">Еще элементов: ' + escapeHtml(atoms.length - (prepareState.showShapeTechnicalInfo ? 30 : 12)) + '</div>' : '';
    if (!prepareState.showShapeTechnicalInfo) {
      return '<details class="aggregate-summary"><summary><strong>' + escapeHtml(title) + '</strong></summary>' + (pagePath ? '<div class="type-key">Путь: ' + escapeHtml(pagePath) + '</div>' : '') + '<div class="composition-list">' + (visibleAtoms || '<div class="muted">Состав не найден.</div>') + rest + '</div></details>';
    }
    var source = aggregate.userValueSource || {};
    var sourceHtml = source.path ? '<div class="type-key">Пользовательское значение: ' + escapeHtml(source.name || 'Text') + ' = ' + escapeHtml(source.value || '[пустое значение]') + '<br>Путь: ' + escapeHtml(source.path) + '</div>' : '';
    var instances = (aggregate.instances || []).slice(0, 6).map(function (instance) {
      var instanceSource = instance.userValueSource || {};
      var title = instance.label || aggregate.label;
      var details = compositionText(instance.atoms);
      if (instanceSource.path) details += ' / ' + (instanceSource.name || 'Text') + ': ' + (instanceSource.value || '[пустое значение]');
      return '<div class="composition-item"><strong>' + escapeHtml(title) + '</strong><span class="muted">' + escapeHtml(details) + '</span></div>';
    }).join('');
    var instanceRest = (aggregate.instances || []).length > 6 ? '<div class="muted">Еще экземпляров: ' + escapeHtml((aggregate.instances || []).length - 6) + '</div>' : '';
    return '<details class="aggregate-summary"><summary><strong>' + escapeHtml(title) + '</strong></summary><div class="muted">' + escapeHtml(aggregateContextText(aggregate)) + ' / экземпляров: ' + escapeHtml((aggregate.instances || []).length) + ' / ролей: ' + escapeHtml((aggregate.atomRoles || []).length) + '</div>' + sourceHtml + '<div class="composition-list">' + (visibleAtoms || instances) + rest + instanceRest + '</div></details>';
  }
  function roleMetaText(role) {
    var parts = [];
    if (role.anonymous) parts.push('без имени в Visio');
    if (role.masterId) parts.push('Master ' + role.masterId);
    if (role.masterShapeId) parts.push('MasterShape ' + role.masterShapeId);
    if (role.shapeNameU && role.shapeNameU !== 'object') parts.push(role.shapeNameU);
    return parts.join(' / ');
  }
  function attributeSupportsList(attr) {
    var type = String(attr && attr.type || '').toLowerCase();
    return type === 'lookup' || type === 'reference';
  }
  function defaultAttributeListMode(attr) {
    var type = String(attr && attr.type || '').toLowerCase();
    if (type === 'lookup') return 'fixed';
    if (type === 'reference') return 'fixed';
    return 'none';
  }
  function attributeListModeKey(attrKey, attrName) {
    return attrKey + '::' + attrName;
  }
  function attributeSourceText(attr) {
    var type = String(attr && attr.type || '').toLowerCase();
    if (type === 'lookup') return attr.lookupType || attr.lookupName || attr.lookup || '';
    if (type === 'reference') return attr.targetClass || attr.target || attr.referenceClass || attr.domain || '';
    return '';
  }
  function attributeHelpText(attr) {
    return attr && (attr.help || attr.helpMessage || attr.helpText || attr.metadataHelp || attr.note || attr.notes || '') || '';
  }
  function attributeListSelectHtml(attrKey, attr) {
    if (!attributeSupportsList(attr)) return '-';
    var key = attributeListModeKey(attrKey, attr.name);
    var mode = prepareState.attributeListModes[key] || defaultAttributeListMode(attr);
    return '<select data-object-attribute-list-mode="' + escapeHtml(key) + '"><option value="none"' + (mode === 'none' ? ' selected' : '') + '>не наполнять</option><option value="fixed"' + (mode === 'fixed' ? ' selected' : '') + '>постоянный</option><option value="variable"' + (mode === 'variable' ? ' selected' : '') + '>переменный</option></select>';
  }
  function attributeSourceRuleKey(attrKey, attrName) {
    return attrKey + '::' + attrName;
  }
  function attributeSourceRule(attrKey, attr) {
    var key = attributeSourceRuleKey(attrKey, attr.name);
    var stored = prepareState.attributeSourceRules[key] || {};
    var sourceRole = stored.sourceRole || 'self';
    var mode = stored.mode || (sourceRole === 'manual' ? 'manual' : sourceRole === 'constant' ? 'constant' : sourceRole === 'default' ? 'default' : sourceRole === 'override' ? 'override' : 'copy');
    return {
      sourceRole: sourceRole,
      sourceAttribute: stored.sourceAttribute || attr.name || '',
      mode: mode
    };
  }
  function attributeSourceSelectHtml(attrKey, attr) {
    var key = attributeSourceRuleKey(attrKey, attr.name);
    var rule = attributeSourceRule(attrKey, attr);
    var roles = [
      ['self', 'Связь'],
      ['source', 'Источник'],
      ['destination', 'Назначение'],
      ['manual', 'Вручную'],
      ['constant', 'Константа'],
      ['default', 'По умолчанию'],
      ['override', 'Override']
    ];
    return '<select data-attribute-source-role="' + escapeHtml(key) + '" data-target-attribute="' + escapeHtml(attr.name) + '">' + roles.map(function (item) {
      return '<option value="' + escapeHtml(item[0]) + '"' + (item[0] === rule.sourceRole ? ' selected' : '') + '>' + escapeHtml(item[1]) + '</option>';
    }).join('') + '</select>';
  }
  function endpointShapeKeysForConnector(aggregate, sourceRole) {
    var keys = [];
    if (!aggregate || aggregate.kind !== 'connector') return keys;
    (aggregate.instances || []).forEach(function (instance) {
      var atom = instance.atoms && instance.atoms[0];
      var connection = atom && atom.connection;
      if (!connection) return;
      var shapeId = sourceRole === 'source' ? connection.sourceShapeId : connection.destinationShapeId;
      if (atom && atom.page && shapeId) keys.push(atom.page + ':' + shapeId);
    });
    return keys.filter(function (key, index, list) { return key && list.indexOf(key) === index; });
  }
  function assignmentKeysForShapeKeys(shapeKeys) {
    var wanted = new Set(shapeKeys || []);
    var result = [];
    (prepareState.aggregates || []).forEach(function (aggregate) {
      if (!aggregate || aggregate.kind === 'connector') return;
      var isAggregateObject = aggregate.kind === 'group' || aggregate.kind === 'container';
      (aggregate.instances || []).forEach(function (instance) {
        if (!prepareState.decomposeAggregates && isAggregateObject) {
          var anchor = instance.anchor || instancePrimaryAtom(instance);
          if (anchor && wanted.has(anchor.page + ':' + anchor.shapeId)) result.push(aggregate.aggregateTypeKey + '::__visual_object__');
          return;
        }
        (instance.atoms || []).forEach(function (atom) {
          if (atom && wanted.has(atom.page + ':' + atom.shapeId)) result.push(aggregate.aggregateTypeKey + '::' + atom.roleKey);
        });
      });
    });
    return result.filter(function (key, index, list) { return key && list.indexOf(key) === index; });
  }
  function sourceAttributeOptionsForConnector(aggregate, sourceRole) {
    var assignmentKeys = assignmentKeysForShapeKeys(endpointShapeKeysForConnector(aggregate, sourceRole));
    var options = [];
    var relationMapping = prepareState.relationEndpointMappings && prepareState.relationEndpointMappings[aggregate && aggregate.aggregateTypeKey || ''] || {};
    (relationMapping[sourceRole] || []).forEach(function (row) {
      if (!row || !row.className || !row.attributeName) return;
      var mappedValue = row.className + '.' + row.attributeName;
      if (options.some(function (item) { return item.value === mappedValue; })) return;
      options.push({
        value: mappedValue,
        label: row.className + ' / ' + row.attributeName + ' (mapping связи)'
      });
    });
    assignmentKeys.forEach(function (assignmentKey) {
      selectedAssignmentClasses(assignmentKey).forEach(function (className) {
        (prepareState.attributeAssignments[assignmentKey + '::' + className] || []).forEach(function (attrName) {
          var value = className + '.' + attrName;
          if (options.some(function (item) { return item.value === value; })) return;
          options.push({
            value: value,
            label: className + ' / ' + attrName
          });
        });
      });
    });
    return options.sort(function (left, right) { return left.label.localeCompare(right.label); });
  }
  function connectorAggregatesForMapping() {
    return (prepareState.aggregates || []).filter(function (aggregate) {
      return aggregate && aggregate.kind === 'connector' && aggregate.aggregateTypeKey;
    }).sort(function (left, right) {
      return aggregateOptionLabel(left).localeCompare(aggregateOptionLabel(right));
    });
  }
  function selectedRelationAggregate() {
    var connectors = connectorAggregatesForMapping();
    if (!connectors.length) return null;
    if (!prepareState.selectedRelationKey || !connectors.some(function (aggregate) { return aggregate.aggregateTypeKey === prepareState.selectedRelationKey; })) {
      prepareState.selectedRelationKey = connectors[0].aggregateTypeKey;
    }
    return connectors.filter(function (aggregate) { return aggregate.aggregateTypeKey === prepareState.selectedRelationKey; })[0] || connectors[0];
  }
  function relationAttributeOptionsForMapping(relationKey) {
    var scopedOptions = [];
    var fallbackOptions = [];
    var allAssignmentOptions = [];
    var aggregateLabels = {};
    connectorAggregatesForMapping().forEach(function (aggregate) {
      aggregateLabels[aggregate.aggregateTypeKey] = aggregatePrimaryText(aggregate) || aggregate.label || aggregate.aggregateTypeKey;
    });
    function addOption(target, className, attrName, ownerKey) {
      if (!className || !attrName) return;
      var value = className + '.' + attrName;
      if (target.some(function (item) { return item.value === value; })) return;
      var label = className + ' / ' + attrName;
      if (ownerKey && ownerKey !== relationKey) label += ' [' + (aggregateLabels[ownerKey] || ownerKey) + ']';
      target.push({
        value: value,
        className: className,
        attrName: attrName,
        label: label
      });
    }
    function ownerRelationKeyForAssignment(assignmentKey) {
      var best = '';
      connectorAggregatesForMapping().forEach(function (aggregate) {
        var key = aggregate.aggregateTypeKey || '';
        if (key && assignmentKey.indexOf(key + '::') === 0 && key.length > best.length) best = key;
      });
      return best;
    }
    function collectFromAssignmentKey(assignmentKey, ownerKey) {
      selectedAssignmentClasses(assignmentKey).forEach(function (className) {
        (prepareState.attributeAssignments[assignmentKey + '::' + className] || []).forEach(function (attrName) {
          addOption(ownerKey === relationKey ? scopedOptions : fallbackOptions, className, attrName, ownerKey);
        });
      });
    }
    function collectFromAttributeKey(attrKey, ownerKey) {
      var attrNames = prepareState.attributeAssignments[attrKey] || [];
      if (!attrNames.length) return;
      var className = '';
      var knownClasses = sortedCmdbClasses().map(function (item) { return item.name; }).filter(Boolean);
      knownClasses.some(function (name) {
        if (attrKey.slice(-1 * (name.length + 2)) === '::' + name) {
          className = name;
          return true;
        }
        return false;
      });
      if (!className) {
        var separator = attrKey.lastIndexOf('::');
        className = separator === -1 ? '' : attrKey.slice(separator + 2);
      }
      attrNames.forEach(function (attrName) {
        var target = ownerKey === relationKey ? scopedOptions : ownerKey ? fallbackOptions : allAssignmentOptions;
        addOption(target, className, attrName, ownerKey || 'все назначения');
      });
    }
    Object.keys(prepareState.classAssignments || {}).forEach(function (assignmentKey) {
      var ownerKey = ownerRelationKeyForAssignment(assignmentKey);
      if (!ownerKey) return;
      collectFromAssignmentKey(assignmentKey, ownerKey);
    });
    Object.keys(prepareState.attributeAssignments || {}).forEach(function (attrKey) {
      var ownerKey = ownerRelationKeyForAssignment(attrKey);
      collectFromAttributeKey(attrKey, ownerKey);
    });
    var result = scopedOptions.length ? scopedOptions : fallbackOptions.length ? fallbackOptions : allAssignmentOptions;
    return result.sort(function (left, right) { return left.label.localeCompare(right.label); });
  }
  function relationAttributeSelectHtml(relationKey, rowIndex, row) {
    var value = row && row.relationClassName && row.relationAttributeName ? row.relationClassName + '.' + row.relationAttributeName : '';
    var options = relationAttributeOptionsForMapping(relationKey);
    return '<select data-relation-map-relation-attribute="' + escapeHtml(relationKey) + '" data-index="' + escapeHtml(rowIndex) + '"><option value="">Атрибут связи не выбран</option>' + (value && !options.some(function (item) { return item.value === value; }) ? '<option value="' + escapeHtml(value) + '" selected>' + escapeHtml(value + ' (нет в назначениях связи)') + '</option>' : '') + options.map(function (item) {
      return '<option value="' + escapeHtml(item.value) + '"' + (item.value === value ? ' selected' : '') + '>' + escapeHtml(item.label) + '</option>';
    }).join('') + '</select>';
  }
  function relationEndpointRows(relationKey) {
    var mapping = prepareState.relationEndpointMappings || {};
    var relation = mapping[relationKey] || {};
    return Array.isArray(relation.attributes) ? relation.attributes.slice() : [];
  }
  function setRelationEndpointRows(relationKey, rows) {
    if (!prepareState.relationEndpointMappings) prepareState.relationEndpointMappings = {};
    prepareState.relationEndpointMappings[relationKey] = {
      attributes: (rows || []).map(function (row) {
      return {
        relationClassName: row && row.relationClassName || '',
        relationAttributeName: row && row.relationAttributeName || '',
        className: row && row.className || '',
        attributeName: row && row.attributeName || ''
      };
    })
    };
  }
  function relationEndpointAttributeOptionsHtml(className, selected) {
    if (className && !Object.prototype.hasOwnProperty.call(prepareState.cmdbClassAttributes, className)) {
      window.setTimeout(function () { loadCmdbClassAttributes(className); }, 0);
    }
    var attrs = className ? prepareState.cmdbClassAttributes[className] : [];
    if (!className) return '<option value="">Сначала выберите класс</option>';
    if (attrs === null || attrs === undefined) return '<option value="">Загружаю атрибуты...</option>';
    if (!attrs.length) return '<option value="">Нет атрибутов</option>';
    return '<option value="">Атрибут не выбран</option>' + attrs.slice().sort(function (left, right) {
      return String(left.description || left.name).localeCompare(String(right.description || right.name));
    }).map(function (attr) {
      var label = (attr.description && attr.description !== attr.name ? attr.description + ' / ' + attr.name : attr.name) + ' / ' + (attr.type || '');
      return '<option value="' + escapeHtml(attr.name) + '"' + (attr.name === selected ? ' selected' : '') + '>' + escapeHtml(label) + '</option>';
    }).join('');
  }
  function relationEndpointClassSelectHtml(relationKey, rowIndex, value) {
    return '<select data-relation-map-class="' + escapeHtml(relationKey) + '" data-index="' + escapeHtml(rowIndex) + '"><option value="">Класс не выбран</option>' + sortedCmdbClasses().map(function (item) {
      var label = item.description && item.description !== item.name ? item.description + ' / ' + item.name : item.name;
      return '<option value="' + escapeHtml(item.name) + '"' + (item.name === value ? ' selected' : '') + '>' + escapeHtml(label) + '</option>';
    }).join('') + '</select>';
  }
  function relationEndpointRowsHtml(relationKey) {
    var rows = relationEndpointRows(relationKey);
    if (!rows.length) rows = [{ relationClassName: '', relationAttributeName: '', className: '', attributeName: '' }];
    return '<div class="assignment-panel"><div class="toolbar compact-toolbar"><h3>Внешние источники атрибутов связи</h3></div><div class="table-wrap"><table class="type-table"><thead><tr><th>Атрибут связи</th><th>Endpoint класс</th><th>Endpoint атрибут</th><th>Действия</th></tr></thead><tbody>' + rows.map(function (row, index) {
      return '<tr><td>' + relationAttributeSelectHtml(relationKey, index, row) + '</td><td>' + relationEndpointClassSelectHtml(relationKey, index, row.className || '') + '</td><td><select data-relation-map-attribute="' + escapeHtml(relationKey) + '" data-index="' + escapeHtml(index) + '">' + relationEndpointAttributeOptionsHtml(row.className || '', row.attributeName || '') + '</select></td><td><button type="button" data-action="remove-relation-endpoint-map" data-relation-key="' + escapeHtml(relationKey) + '" data-index="' + escapeHtml(index) + '">Очистить</button></td></tr>';
    }).join('') + '</tbody></table></div><div class="right-actions compact-actions"><button class="icon-button" type="button" data-action="add-relation-endpoint-map" data-relation-key="' + escapeHtml(relationKey) + '">+</button></div></div>';
  }
  function relationMappingSummaryHtml() {
    var mappings = prepareState.relationEndpointMappings || {};
    var relationLabels = {};
    connectorAggregatesForMapping().forEach(function (aggregate) {
      relationLabels[aggregate.aggregateTypeKey] = aggregatePrimaryText(aggregate) || aggregate.label || aggregate.aggregateTypeKey;
    });
    var rows = Object.keys(mappings).sort().map(function (relationKey) {
      var mapping = mappings[relationKey] || {};
      var text = (mapping.attributes || []).filter(function (row) { return row.relationClassName && row.relationAttributeName && row.className && row.attributeName; }).map(function (row) {
        return row.relationClassName + '.' + row.relationAttributeName + ' <- ' + row.className + '.' + row.attributeName;
      }).join(', ');
      if (!text) return '';
      return '<tr><td><strong>' + escapeHtml(relationLabels[relationKey] || relationKey) + '</strong><div class="type-key">' + escapeHtml(relationKey) + '</div></td><td>' + escapeHtml(text) + '</td></tr>';
    }).filter(Boolean);
    if (!rows.length) return '<section class="section"><h3>Mapping связей</h3><div class="notice">Правила отражения на связь еще не добавлены.</div></section>';
    return '<section class="section"><h3>Mapping связей</h3><div class="table-wrap"><table class="type-table"><thead><tr><th>Связь</th><th>Атрибут связи и внешний источник</th></tr></thead><tbody>' + rows.join('') + '</tbody></table></div></section>';
  }
  function contractParamRowsHtml() {
    var params = prepareState.contractParams || [];
    if (!params.length) params = [{ name: '', description: '', type: 'string', required: false, defaultValue: '', listMode: 'none', values: [], help: '' }];
    return '<div class="table-wrap"><table class="type-table"><thead><tr><th>Имя</th><th>Описание</th><th>Тип</th><th>Обяз.</th><th>Default</th><th>Список</th><th>Значения</th><th>Помощь</th><th></th></tr></thead><tbody>' + params.map(function (param, index) {
      var valuesText = Array.isArray(param.values) ? param.values.join('; ') : String(param.valuesText || '');
      return '<tr>' +
        '<td><input data-contract-param-field="name" data-index="' + escapeHtml(index) + '" value="' + escapeHtml(param.name || '') + '" placeholder="environment"></td>' +
        '<td><input data-contract-param-field="description" data-index="' + escapeHtml(index) + '" value="' + escapeHtml(param.description || '') + '"></td>' +
        '<td><select data-contract-param-field="type" data-index="' + escapeHtml(index) + '">' +
          ['string', 'text', 'integer', 'decimal', 'boolean', 'date', 'datetime'].map(function (type) {
            return '<option value="' + escapeHtml(type) + '"' + (String(param.type || 'string') === type ? ' selected' : '') + '>' + escapeHtml(type) + '</option>';
          }).join('') +
        '</select></td>' +
        '<td><input type="checkbox" data-contract-param-field="required" data-index="' + escapeHtml(index) + '"' + (param.required ? ' checked' : '') + '></td>' +
        '<td><input data-contract-param-field="defaultValue" data-index="' + escapeHtml(index) + '" value="' + escapeHtml(param.defaultValue || '') + '"></td>' +
        '<td><select data-contract-param-field="listMode" data-index="' + escapeHtml(index) + '">' +
          ['none', 'fixed', 'variable'].map(function (mode) {
            return '<option value="' + escapeHtml(mode) + '"' + (String(param.listMode || 'none') === mode ? ' selected' : '') + '>' + escapeHtml(mode) + '</option>';
          }).join('') +
        '</select></td>' +
        '<td><input data-contract-param-field="valuesText" data-index="' + escapeHtml(index) + '" value="' + escapeHtml(valuesText) + '" placeholder="value1; value2"></td>' +
        '<td><input data-contract-param-field="help" data-index="' + escapeHtml(index) + '" value="' + escapeHtml(param.help || '') + '"></td>' +
        '<td><button type="button" data-action="remove-contract-param" data-index="' + escapeHtml(index) + '">Очистить</button></td>' +
      '</tr>';
    }).join('') + '</tbody></table></div>';
  }
  function contractParamsHtml() {
    return '<section class="section"><div class="toolbar compact-toolbar"><h3>Параметры контракта</h3><button class="primary" type="button" data-action="apply-contract-params">Применить</button><button type="button" data-action="add-contract-param">Добавить параметр</button><span id="contract-params-status" class="muted"></span></div><p class="muted">Параметры уровня контракта сохраняются в версии контракта и позже будут доступны в выражениях вида \${contractparam.name}.</p>' + contractParamRowsHtml() + '</section>';
  }
  function prepareRelationMappingHtml() {
    var connectors = connectorAggregatesForMapping();
    if (!connectors.length) return '<div class="notice">Связи в шаблоне не найдены.</div>';
    var selected = selectedRelationAggregate();
    var relationKey = selected && selected.aggregateTypeKey || '';
    var selector = '<label>Связь<select id="prepare-relation-selector">' + connectors.map(function (aggregate) {
      return '<option value="' + escapeHtml(aggregate.aggregateTypeKey) + '"' + (aggregate.aggregateTypeKey === relationKey ? ' selected' : '') + '>' + escapeHtml(aggregateOptionLabel(aggregate)) + '</option>';
    }).join('') + '</select></label>';
    return '<div class="object-editor"><div class="object-editor-left">' + selector + '</div><div class="object-editor-right">' + aggregateSummaryHtml(selected) + relationEndpointRowsHtml(relationKey) + '</div></div>' + relationMappingSummaryHtml();
  }
  function attributeSourceAttributeHtml(attrKey, attr, aggregate) {
    var key = attributeSourceRuleKey(attrKey, attr.name);
    var rule = attributeSourceRule(attrKey, attr);
    if (aggregate && aggregate.kind === 'connector' && (rule.sourceRole === 'source' || rule.sourceRole === 'destination')) {
      var options = sourceAttributeOptionsForConnector(aggregate, rule.sourceRole);
      var value = rule.sourceAttribute || '';
      var valueExists = options.some(function (item) { return item.value === value; });
      return '<select data-attribute-source-attribute="' + escapeHtml(key) + '" data-target-attribute="' + escapeHtml(attr.name) + '"><option value="">Не выбран</option>' + (value && !valueExists ? '<option value="' + escapeHtml(value) + '" selected>' + escapeHtml(value + ' (нет в назначениях)') + '</option>' : '') + options.map(function (item) {
        return '<option value="' + escapeHtml(item.value) + '"' + (item.value === value ? ' selected' : '') + '>' + escapeHtml(item.label) + '</option>';
      }).join('') + '</select>';
    }
    return '<input data-attribute-source-attribute="' + escapeHtml(key) + '" data-target-attribute="' + escapeHtml(attr.name) + '" value="' + escapeHtml(rule.sourceAttribute || '') + '">';
  }
  function attributeSourceModeHtml(attrKey, attr) {
    var key = attributeSourceRuleKey(attrKey, attr.name);
    var rule = attributeSourceRule(attrKey, attr);
    var modes = [
      ['copy', 'copy'],
      ['manual', 'manual'],
      ['constant', 'constant'],
      ['default', 'default'],
      ['override', 'override']
    ];
    return '<select data-attribute-source-mode="' + escapeHtml(key) + '" data-target-attribute="' + escapeHtml(attr.name) + '">' + modes.map(function (item) {
      return '<option value="' + escapeHtml(item[0]) + '"' + (item[0] === rule.mode ? ' selected' : '') + '>' + escapeHtml(item[1]) + '</option>';
    }).join('') + '</select>';
  }
  function attributeColumnsHtml() {
    var columns = prepareState.attributeColumns || {};
    var options = [
      ['name', 'Имя'],
      ['description', 'Описание'],
      ['help', 'Помощь'],
      ['type', 'Тип'],
      ['mandatory', 'Обязательное'],
      ['list', 'Список'],
      ['source', 'Источник'],
      ['valueSource', 'Источник значения'],
      ['sourceMode', 'Режим']
    ];
    return '<div class="column-toggles">' + options.map(function (item) {
      return '<label class="check-label"><input type="checkbox" data-attribute-column="' + escapeHtml(item[0]) + '"' + (columns[item[0]] !== false ? ' checked' : '') + '>' + escapeHtml(item[1]) + '</label>';
    }).join('') + '</div>';
  }
  function attributeTableHtml(attrKey, attrs, selectedAttrs, emptyText, isContextAssignment, aggregate) {
    if (!attrs.length) return '<div class="notice">' + escapeHtml(emptyText) + '</div>';
    var columns = prepareState.attributeColumns || {};
    var headers = ['<th>Выбор</th>'];
    if (columns.name !== false) headers.push('<th>Имя</th>');
    if (columns.description !== false) headers.push('<th>Описание</th>');
    if (columns.help !== false) headers.push('<th>Помощь</th>');
    if (columns.type !== false) headers.push('<th>Тип</th>');
    if (columns.mandatory !== false) headers.push('<th>Обязательное</th>');
    if (columns.list !== false) headers.push('<th>Список</th>');
    if (columns.source !== false) headers.push('<th>Источник</th>');
    if (isContextAssignment && columns.valueSource !== false) headers.push('<th>Источник значения</th>');
    if (isContextAssignment && columns.sourceMode !== false) headers.push('<th>Режим</th>');
    return '<div class="attribute-list"><table class="type-table"><thead><tr>' + headers.join('') + '</tr></thead><tbody>' + attrs.map(function (attr) {
      var cells = ['<td><input type="checkbox" data-object-attribute="' + escapeHtml(attrKey) + '" value="' + escapeHtml(attr.name) + '"' + (selectedAttrs.indexOf(attr.name) !== -1 ? ' checked' : '') + '></td>'];
      if (columns.name !== false) cells.push('<td><strong>' + escapeHtml(attr.name) + '</strong></td>');
      if (columns.description !== false) cells.push('<td>' + escapeHtml(attr.description || '') + '</td>');
      if (columns.help !== false) cells.push('<td>' + escapeHtml(attributeHelpText(attr) || '-') + '</td>');
      if (columns.type !== false) cells.push('<td>' + escapeHtml(attr.type || '') + '</td>');
      if (columns.mandatory !== false) cells.push('<td>' + escapeHtml(attr.mandatory ? 'да' : 'нет') + '</td>');
      if (columns.list !== false) cells.push('<td>' + attributeListSelectHtml(attrKey, attr) + '</td>');
      if (columns.source !== false) cells.push('<td>' + escapeHtml(attributeSourceText(attr) || '-') + '</td>');
      if (isContextAssignment && columns.valueSource !== false) cells.push('<td>' + attributeSourceSelectHtml(attrKey, attr) + '</td>');
      if (isContextAssignment && columns.sourceMode !== false) cells.push('<td>' + attributeSourceModeHtml(attrKey, attr) + '</td>');
      return '<tr>' + cells.join('') + '</tr>';
    }).join('') + '</tbody></table></div>';
  }
  function shouldTreatAsWholeVisualObject(aggregate) {
    return !prepareState.decomposeAggregates && aggregate && (aggregate.kind === 'group' || aggregate.kind === 'container');
  }
  function editorRolesForAggregate(aggregate) {
    if (shouldTreatAsWholeVisualObject(aggregate)) {
      return [{
        roleKey: '__visual_object__',
        label: aggregatePrimaryText(aggregate),
        kind: aggregate.kind,
        visualObject: true
      }];
    }
    return aggregate && aggregate.atomRoles || [];
  }
  function instancePrimaryAtom(instance) {
    if (instance && instance.anchor) return instance.anchor;
    var atoms = instance && instance.atoms || [];
    return atoms.filter(function (atom) { return atom.userValueSource && atom.userValueSource.value; })[0] ||
      atoms.filter(function (atom) { return atom.userValueSource && atom.userValueSource.path; })[0] ||
      atoms.filter(function (atom) { return atom.shapeData && atom.shapeData.length; })[0] ||
      atoms[0] ||
      null;
  }
  function contractAnchorForInstance(instance) {
    return instancePrimaryAtom(instance);
  }
  function contractObjectOptions() {
    var options = [];
    (prepareState.aggregates || []).forEach(function (aggregate) {
      if (!aggregate || !aggregate.instances || !aggregate.instances.length) return;
      if (aggregate.kind === 'connector') return;
      (aggregate.instances || []).forEach(function (instance, index) {
        var anchor = contractAnchorForInstance(instance);
        if (!anchor || !anchor.page || !anchor.shapeId) return;
        var key = anchor.page + ':' + anchor.shapeId;
        if (options.some(function (item) { return item.key === key; })) return;
        var label = (instance.label || aggregatePrimaryText(aggregate) || atomDisplayLabel(anchor, index)) + ' / ' + anchor.page + ' / Shape ' + anchor.shapeId;
        options.push({
          key: key,
          label: label,
          path: pagePathText(anchor.userValueSource || aggregate.userValueSource, anchor.page)
        });
      });
    });
    return options.sort(function (left, right) { return left.label.localeCompare(right.label); });
  }
  function contractBindingHtml() {
    var options = contractObjectOptions();
    if (!options.length) {
      return '<div class="assignment-panel"><h3>Привязка контракта к объекту</h3><div class="notice">Сначала загрузите и разберите VSDX в меню "Подготовить шаблон". После этого здесь появится выбор объекта контракта на схеме.</div></div>';
    }
    if (prepareState.contractAnchorKey && !options.some(function (item) { return item.key === prepareState.contractAnchorKey; })) {
      prepareState.contractAnchorKey = '';
    }
    var selected = options.filter(function (item) { return item.key === prepareState.contractAnchorKey; })[0];
    return '<div class="assignment-panel"><h3>Привязка контракта к объекту</h3><label>Объект контракта<select id="prepare-contract-anchor"><option value="">Не выбран</option>' + options.map(function (item) {
      return '<option value="' + escapeHtml(item.key) + '"' + (item.key === prepareState.contractAnchorKey ? ' selected' : '') + '>' + escapeHtml(item.label) + '</option>';
    }).join('') + '</select></label>' + (selected && selected.path ? '<div class="type-key">Путь: ' + escapeHtml(selected.path) + '</div>' : '') + '<div class="muted">Этот объект получит версию контракта и не будет наполняться как CMDB-объект.</div></div>';
  }
  function prepareObjectEditorHtml(types) {
    syncPrepareDecomposeFromRules();
    var candidates = (prepareState.aggregates || []).filter(function (aggregate) {
      if (!prepareState.showConnectors && aggregate.kind === 'connector') return false;
      if (!hasVisibleUserText(aggregate)) return false;
      return aggregate.atomRoles && aggregate.atomRoles.length && aggregate.instances && aggregate.instances.length;
    });
    var editorToggles = '<div class="column-toggles"><label class="check-label"><input type="checkbox" id="prepare-show-technical"' + (prepareState.showShapeTechnicalInfo ? ' checked' : '') + '>Показывать техническую информацию по фигуре</label><label class="check-label"><input type="checkbox" id="prepare-show-connectors"' + (prepareState.showConnectors ? ' checked' : '') + '>Показать связи</label></div>';
    if (!candidates.length) return editorToggles + '<div class="notice">Нет агрегированных типов для назначения CMDB-классов.</div>';
    if (!prepareState.selectedTypeKey || !candidates.some(function (aggregate) { return aggregate.aggregateTypeKey === prepareState.selectedTypeKey; })) {
      prepareState.selectedTypeKey = candidates[0].aggregateTypeKey;
    }
    var selected = candidates.filter(function (aggregate) { return aggregate.aggregateTypeKey === prepareState.selectedTypeKey; })[0] || candidates[0];
    var isContextAssignment = selected && selected.kind === 'connector';
    var editorRoles = editorRolesForAggregate(selected);
    if (!prepareState.selectedRoleKey || !editorRoles.some(function (role) { return role.roleKey === prepareState.selectedRoleKey; })) {
      prepareState.selectedRoleKey = editorRoles[0] && editorRoles[0].roleKey || '';
    }
    var selectedRole = editorRoles.filter(function (role) { return role.roleKey === prepareState.selectedRoleKey; })[0] || editorRoles[0];
    var left = '<label>Агрегированные типы<select id="prepare-type-selector">' + candidates.map(function (aggregate) {
      return '<option value="' + escapeHtml(aggregate.aggregateTypeKey) + '"' + (aggregate.aggregateTypeKey === selected.aggregateTypeKey ? ' selected' : '') + '>' + escapeHtml(aggregateOptionLabel(aggregate)) + '</option>';
    }).join('') + '</select></label><div class="type-key">Режим: ' + escapeHtml(isContextAssignment ? 'контекстное назначение связи' : 'объектное назначение') + '</div>';
    var roleSelector = editorRoles.length === 1 && editorRoles[0] && editorRoles[0].visualObject ? '' : '<label>Компонента типа<select id="prepare-atom-selector">' + editorRoles.map(function (role) {
      return '<option value="' + escapeHtml(role.roleKey) + '"' + (selectedRole && role.roleKey === selectedRole.roleKey ? ' selected' : '') + '>' + escapeHtml(atomDisplayLabel(role, 0) + (lastAggregationText(role) ? ' [' + lastAggregationText(role) + ']' : '')) + '</option>';
    }).join('') + '</select></label>';
    var rolePanel = '';
    if (selectedRole) {
      var key = selected.aggregateTypeKey + '::' + selectedRole.roleKey;
      var classes = assignmentClasses(key);
      if (!classes.length) classes = [''];
      var instances = (selected.instances || []).map(function (instance) {
        var atom = selectedRole.visualObject
          ? instancePrimaryAtom(instance)
          : (instance.atoms || []).filter(function (item) { return item.roleKey === selectedRole.roleKey; })[0];
        if (!atom) return '';
        var meta = roleMetaText(atom);
        var aggregationText = lastAggregationText(atom);
        var source = atom.userValueSource || {};
        var sourceHtml = source.path && prepareState.showShapeTechnicalInfo ? '<div class="type-key">Пользовательское значение: ' + escapeHtml(source.name || 'Text') + ' = ' + escapeHtml(source.value || '[пустое значение]') + '<br>Путь: ' + escapeHtml(source.path) + '</div>' : '';
        var summaryText = prepareState.showShapeTechnicalInfo
          ? (aggregationText ? aggregationText + ' / ' : '') + atom.page + ' / Shape ' + atom.shapeId + (meta ? ' / ' + meta : '')
          : (aggregationText ? aggregationText + ' / ' : '') + atom.page;
        var pagePath = pagePathText(source, atom.page);
        var bodyHtml = prepareState.showShapeTechnicalInfo
          ? '<div class="object-row-body"><div>' + sourceHtml + shapeDataHtml(atom.shapeData) + '</div></div>'
          : (pagePath ? '<div class="object-row-body"><div class="type-key">Путь: ' + escapeHtml(pagePath) + '</div></div>' : '');
        var title = selectedRole.visualObject ? (instance.label || aggregatePrimaryText(selected)) : atomDisplayLabel(atom, 0);
        var childCount = selectedRole.visualObject && instance.atoms ? ' / внутренних фигур: ' + instance.atoms.length : '';
        return '<details class="object-row"><summary><strong>' + escapeHtml(title) + '</strong><span class="muted"> ' + escapeHtml(summaryText + childCount) + '</span></summary>' + bodyHtml + '</details>';
      }).join('');
      var roleMeta = roleMetaText(selectedRole);
      var roleAggregation = lastAggregationText(selectedRole);
      var roleSummary = prepareState.showShapeTechnicalInfo
        ? (roleAggregation ? ' / ' + escapeHtml(roleAggregation) : '') + (roleMeta ? ' / ' + escapeHtml(roleMeta) : '')
        : (roleAggregation ? ' / ' + escapeHtml(roleAggregation) : '');
      var classBlocks = classes.map(function (className, classIndex) {
        var collapseKey = classAssignmentCollapseKey(key, classIndex);
        var openAttr = prepareState.collapsedClassAssignments[collapseKey] ? '' : ' open';
        if (className && !Object.prototype.hasOwnProperty.call(prepareState.cmdbClassAttributes, className)) {
          window.setTimeout(function () { loadCmdbClassAttributes(className); }, 0);
        }
        var attrKey = key + '::' + className;
        var selectedAttrs = prepareState.attributeAssignments[attrKey] || [];
        var attrs = className ? prepareState.cmdbClassAttributes[className] : [];
        var inheritedAttrs = Array.isArray(attrs) ? attrs.filter(function (attr) { return attr.inherited; }) : [];
        var ownAttrs = Array.isArray(attrs) ? attrs.filter(function (attr) { return !attr.inherited; }) : [];
        var attributesHtml = !className
          ? '<div class="notice">Выберите CMDB-класс, чтобы увидеть атрибуты.</div>'
          : attrs === null || attrs === undefined
            ? '<div class="notice">Загружаю атрибуты класса...</div>'
            : attrs.length
              ? attributeColumnsHtml() + '<details class="attribute-group"><summary><strong>Унаследованные атрибуты</strong><span class="muted"> ' + escapeHtml(inheritedAttrs.length) + '</span></summary><div class="attribute-group-body">' + attributeTableHtml(attrKey, inheritedAttrs, selectedAttrs, 'У выбранного класса нет унаследованных атрибутов.', isContextAssignment, selected) + '</div></details><h3>Атрибуты класса</h3>' + attributeTableHtml(attrKey, ownAttrs, selectedAttrs, 'У выбранного класса нет собственных атрибутов.', isContextAssignment, selected)
              : '<div class="notice">У выбранного класса нет доступных атрибутов.</div>';
        return '<details class="class-assignment" data-class-assignment-key="' + escapeHtml(key) + '" data-class-assignment-index="' + escapeHtml(classIndex) + '"' + openAttr + '><summary><strong>CMDB-класс ' + escapeHtml(classIndex + 1) + '</strong>' + (className ? '<span class="muted"> ' + escapeHtml(className) + '</span>' : '') + '</summary><div class="class-assignment-body"><label>Класс' + classSelectHtml(key, classIndex, className) + '</label><div class="right-actions compact-actions"><button type="button" data-action="remove-cmdb-class" data-class-key="' + escapeHtml(key) + '" data-class-index="' + escapeHtml(classIndex) + '">Скрыть</button></div>' + attributesHtml + '</div></details>';
      }).join('');
      var aggregateModeNotice = prepareState.decomposeAggregates && (selected.kind === 'group' || selected.kind === 'container')
        ? '<div class="notice">Агрегированный тип показан справочно. Классы назначаются только на выбранную внутреннюю фигуру.</div>'
        : '';
      rolePanel = aggregateModeNotice + '<div class="assignment-panel">' + assignmentModeHtml(selected) + '<div class="toolbar compact-toolbar"><h3>' + escapeHtml(assignmentPanelTitle(selected)) + '</h3><button class="primary" type="button" data-action="apply-template-mapping">Применить</button><span id="template-mapping-apply-status" class="muted"></span></div>' + classBlocks + '<div class="right-actions compact-actions"><button class="icon-button" type="button" data-action="add-cmdb-class" data-class-key="' + escapeHtml(key) + '">+</button></div></div>';
    }
    return editorToggles + '<div class="object-editor"><div class="object-editor-left">' + left + roleSelector + '</div><div class="object-editor-right">' + aggregateSummaryHtml(selected) + rolePanel + '</div></div>';
  }
  function aggregateByKeyMap() {
    var result = {};
    (prepareState.aggregates || []).forEach(function (aggregate) {
      if (aggregate && aggregate.aggregateTypeKey) result[aggregate.aggregateTypeKey] = aggregate;
    });
    return result;
  }
  function roleLabelForSummary(aggregate, roleKey) {
    if (roleKey === '__visual_object__') return aggregate ? aggregatePrimaryText(aggregate) : 'Тип целиком';
    var role = (aggregate && aggregate.atomRoles || []).filter(function (item) { return item.roleKey === roleKey; })[0];
    return role ? atomDisplayLabel(role, 0) : roleKey;
  }
  function assignmentSummaryRows() {
    var aggregates = aggregateByKeyMap();
    return Object.keys(prepareState.classAssignments || {}).sort().map(function (key) {
      var classes = selectedAssignmentClasses(key);
      if (!classes.length) return null;
      var separatorIndex = key.indexOf('::');
      var aggregateKey = separatorIndex === -1 ? key : key.slice(0, separatorIndex);
      var roleKey = separatorIndex === -1 ? '' : key.slice(separatorIndex + 2);
      var aggregate = aggregates[aggregateKey];
      var attrCount = 0;
      var listCounts = { fixed: 0, variable: 0, none: 0 };
      Object.keys(prepareState.attributeAssignments || {}).forEach(function (attrKey) {
        if (attrKey.indexOf(key + '::') !== 0) return;
        var selectedAttrs = prepareState.attributeAssignments[attrKey] || [];
        attrCount += selectedAttrs.length;
        selectedAttrs.forEach(function (attrName) {
          var mode = prepareState.attributeListModes[attrKey + '::' + attrName] || 'none';
          if (!Object.prototype.hasOwnProperty.call(listCounts, mode)) mode = 'none';
          listCounts[mode] += 1;
        });
      });
      return {
        key: key,
        aggregateKey: aggregateKey,
        roleKey: roleKey,
        typeLabel: aggregate ? aggregatePrimaryText(aggregate) : aggregateKey,
        roleLabel: roleLabelForSummary(aggregate, roleKey),
        classes: classes,
        attrCount: attrCount,
        listText: listCounts.fixed + ' постоянных / ' + listCounts.variable + ' переменных / ' + listCounts.none + ' без списка'
      };
    }).filter(Boolean);
  }
  function assignmentSummaryHtml() {
    var rows = assignmentSummaryRows();
    if (!rows.length) return '<section class="section"><h3>Назначено в шаблоне</h3><div class="notice">Назначения еще не добавлены.</div></section>';
    return '<section class="section"><h3>Назначено в шаблоне</h3><div class="table-wrap"><table class="type-table"><thead><tr><th>Тип</th><th>Компонента</th><th>Классы</th><th>Атрибутов</th><th>Списки</th><th>Действия</th></tr></thead><tbody>' +
      rows.map(function (row) {
        return '<tr><td><strong>' + escapeHtml(row.typeLabel) + '</strong><div class="type-key">' + escapeHtml(row.aggregateKey) + '</div></td><td>' + escapeHtml(row.roleLabel) + '</td><td>' + escapeHtml(row.classes.join(', ')) + '</td><td>' + escapeHtml(row.attrCount) + '</td><td>' + escapeHtml(row.listText) + '</td><td><button type="button" data-action="clear-assignment" data-assignment-key="' + escapeHtml(row.key) + '">Очистить</button></td></tr>';
      }).join('') +
      '</tbody></table></div></section>';
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
    if (!types.length) {
      target.className = 'notice';
      target.textContent = 'Загрузите .vsdx для извлечения типов фигур.';
      return;
    }
    target.className = 'table-wrap';
    if (prepareState.activeTab === 'enrich') {
      target.innerHTML = checksumWarningHtml() + prepareObjectEditorHtml(types) + assignmentSummaryHtml();
      return;
    }
    if (prepareState.activeTab === 'relation-map') {
      target.innerHTML = checksumWarningHtml() + prepareRelationMappingHtml();
      return;
    }
    if (prepareState.activeTab === 'contract-params') {
      target.className = '';
      target.innerHTML = checksumWarningHtml() + contractParamsHtml();
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
      target.innerHTML = checksumWarningHtml() + prepareColumnToggleHtml() + '<table class="type-table"><thead><tr>' + headers.join('') + '</tr></thead><tbody>' + rows.join('') + '</tbody></table>';
      return;
    }
    var typeHeaders = ['<th>Тип</th>'];
    if (prepareState.columns.count) typeHeaders.push('<th>Фигур</th>');
    if (prepareState.columns.pages) typeHeaders.push('<th>Страницы</th>');
    if (prepareState.columns.shapeData) typeHeaders.push('<th>Shape Data</th>');
    target.innerHTML = [
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
  function downloadTextFile(filename, text) {
    var blob = new Blob([String(text || '')], { type: 'text/plain;charset=utf-8' });
    var url = URL.createObjectURL(blob);
    var link = document.createElement('a');
    link.href = url;
    link.download = filename || 'checksum.txt';
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }
  function expectedChecksumName() {
    var file = selectedFile();
    var ext = readSettings().checksumExtension;
    return prepareState.fileName ? (prepareState.fileName + '.' + ext) : file ? (file.name + '.' + ext) : '';
  }
  function selectedChecksumFile() {
    return prepareState.checksumFile;
  }
  function normalizeUiContractParam(param) {
    var name = String(param && param.name || '').trim();
    if (!name) return null;
    var values = Array.isArray(param.values)
      ? param.values.map(function (item) { return String(item || '').trim(); }).filter(Boolean)
      : String(param.valuesText || '').split(/[;\\n,]/).map(function (item) { return item.trim(); }).filter(Boolean);
    var listMode = String(param.listMode || 'none');
    if (['none', 'fixed', 'variable'].indexOf(listMode) === -1) listMode = values.length ? 'fixed' : 'none';
    return {
      name: name,
      description: String(param.description || name).trim() || name,
      type: String(param.type || 'string').trim() || 'string',
      required: Boolean(param.required),
      defaultValue: String(param.defaultValue || ''),
      listMode: listMode,
      values: values,
      help: String(param.help || '').trim()
    };
  }
  function normalizedUiContractParams() {
    return (prepareState.contractParams || []).map(normalizeUiContractParam).filter(Boolean).sort(function (left, right) {
      return left.name.localeCompare(right.name);
    });
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
    syncPrepareDecomposeFromRules();
    var aggregateByKey = {};
    (prepareState.aggregates || []).forEach(function (aggregate) {
      if (aggregate && aggregate.aggregateTypeKey) aggregateByKey[aggregate.aggregateTypeKey] = aggregate;
    });
    var result = {};
    Object.keys(prepareState.classAssignments || {}).forEach(function (key) {
      var separatorIndex = key.indexOf('::');
      var aggregateKey = separatorIndex === -1 ? '' : key.slice(0, separatorIndex);
      var roleKey = separatorIndex === -1 ? '' : key.slice(separatorIndex + 2);
      var aggregate = aggregateByKey[aggregateKey];
      var isAggregateObject = aggregate && (aggregate.kind === 'group' || aggregate.kind === 'container');
      if (isAggregateObject && !prepareState.decomposeAggregates && roleKey !== '__visual_object__') return;
      if (isAggregateObject && prepareState.decomposeAggregates && roleKey === '__visual_object__') return;
      var value = prepareState.classAssignments[key];
      var normalized = Array.isArray(value) ? value.filter(Boolean).join(', ') : value;
      if (normalized) result[key] = normalized;
    });
    return result;
  }
  function loadCmdbClassesForPrepare() {
    return api('/cmdb/classes').then(function (result) {
      prepareState.cmdbClasses = result.response.ok ? (result.json.data || []) : [];
      renderPrepareData();
    }).catch(function () {});
  }
  function loadCmdbClassAttributes(className) {
    className = String(className || '');
    if (!className || Object.prototype.hasOwnProperty.call(prepareState.cmdbClassAttributes, className)) return Promise.resolve();
    prepareState.cmdbClassAttributes[className] = null;
    return api('/cmdb/classes/' + encodeURIComponent(className) + '/attributes').then(function (result) {
      prepareState.cmdbClassAttributes[className] = result.response.ok ? (result.json.data || []) : [];
      persistPrepareState();
      renderPrepareData();
    }).catch(function () {
      prepareState.cmdbClassAttributes[className] = [];
      persistPrepareState();
      renderPrepareData();
    });
  }
  function payloadHasContractVersion(payload) {
    var version = payload && payload.contractVersion;
    return Boolean(version && version.id && version.code && version.rulesChecksum);
  }
  function inspectVsdx() {
    syncPrepareDecomposeFromRules();
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
      prepareState.contractAnchorKey = prepareState.contractMetadata && prepareState.contractMetadata.contractPageShapeKey || prepareState.contractAnchorKey || '';
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
    var target = document.getElementById('prepare-view') || document.getElementById('contract-work-status');
    if (!target) return;
    target.className = ok === false ? 'notice error' : ok === true ? 'notice ok' : 'notice';
    target.textContent = typeof message === 'string' ? message : JSON.stringify(message, null, 2);
  }
  function enrichVsdx() {
    syncVisibleAttributeAssignmentsFromDom();
    syncPrepareDecomposeFromRules();
    var file = selectedFile();
    if (!file && !prepareState.fileBase64) {
      renderNotice('Выберите .vsdx файл.', false);
      return;
    }
    if (!prepareState.contractAnchorKey) {
      renderNotice('Выберите объект контракта в блоке "Привязка контракта к объекту".', false);
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
          contract: selectedPrepareContract(),
          contractAnchorKey: prepareState.contractAnchorKey,
          aggregateClassMap: mappingFromTable(),
          aggregateAttributeMap: prepareState.attributeAssignments || {},
          aggregateAttributeListModes: prepareState.attributeListModes || {},
          aggregateAttributeSourceRules: prepareState.attributeSourceRules || {},
          relationEndpointMappings: prepareState.relationEndpointMappings || {},
          contractParams: normalizedUiContractParams(),
          cmdbClassAttributes: prepareState.cmdbClassAttributes || {},
          settings: readSettings(),
          decomposeAggregates: prepareState.decomposeAggregates,
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
      if (result.json.checksum && result.json.checksum.text) {
        downloadTextFile(result.json.checksum.filename || ((result.json.filename || 'enriched.vsdx') + '.sha256'), result.json.checksum.text);
      }
      prepareState.contractVersionId = result.json.contractVersion && result.json.contractVersion.id || prepareState.contractVersionId;
      loadContractVersions();
      persistPrepareState();
      renderNotice('Контракт сохранен, VSDX и файл контрольной суммы загружены. Версия: ' + (result.json.contractVersion && result.json.contractVersion.code || ''), true);
    }).catch(function (error) {
      renderNotice(error && error.message ? error.message : String(error), false);
    });
  }
  function verifyVsdxFile(file) {
    if (!file) {
      showStatus('Выберите .vsdx файл.', false);
      return;
    }
    showStatus('Проверяю VSDX...', null);
    fileToBase64(file).then(function (base64) {
      return api('/vsdx/verify', {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'content-type': 'application/json'
        },
        body: JSON.stringify({
          filename: file.name || 'template.vsdx',
          fileBase64: base64
        })
      });
    }).then(function (result) {
      showStatus(result.json, result.response.ok);
    }).catch(function (error) {
      showStatus(error && error.message ? error.message : String(error), false);
    });
  }
  function checkTemplateVsdxFile(file) {
    if (!file) {
      showStatus('Выберите .vsdx файл.', false);
      return;
    }
    showStatus('Проверяю техническую целостность шаблона...', null);
    fileToBase64(file).then(function (base64) {
      return api('/vsdx/check-template', {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'content-type': 'application/json'
        },
        body: JSON.stringify({
          filename: file.name || 'template.vsdx',
          fileBase64: base64
        })
      });
    }).then(function (result) {
      showCheckTemplateResult(result.json, result.response.ok);
    }).catch(function (error) {
      showStatus(error && error.message ? error.message : String(error), false);
    });
  }
  function collectCreateOverrides() {
    Array.prototype.forEach.call(document.querySelectorAll('[data-create-override-key]'), function (input) {
      var key = input.getAttribute('data-create-override-key') || '';
      if (!key) return;
      createState.valueOverrides[key] = input.value || '';
    });
  }
  function submitCreateObjects(execute) {
    if (!createState.fileBase64) {
      showStatus('Выберите .vsdx файл.', false);
      return;
    }
    collectCreateOverrides();
    showStatus(execute ? 'Проверяю план и создаю объекты...' : 'Проверяю VSDX и строю план создания...', null);
    return api('/vsdx/create-objects', {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        filename: createState.fileName || 'template.vsdx',
        fileBase64: createState.fileBase64,
        execute: Boolean(execute),
        valueOverrides: createState.valueOverrides
      })
    }).then(function (result) {
      createState.lastResult = result.json;
      createState.lastOk = result.response.ok;
      showCreateResult(result.json, result.response.ok);
    }).catch(function (error) {
      showStatus(error && error.message ? error.message : String(error), false);
    });
  }
  function createObjectsFromVsdxFile(file) {
    if (!file) {
      showStatus('Выберите .vsdx файл.', false);
      return;
    }
    showStatus('Читаю VSDX и строю план создания...', null);
    fileToBase64(file).then(function (base64) {
      createState.fileName = file.name || 'template.vsdx';
      createState.fileBase64 = base64;
      createState.valueOverrides = {};
      createState.lastResult = null;
      createState.lastOk = null;
      return api('/vsdx/create-objects', {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'content-type': 'application/json'
        },
        body: JSON.stringify({
          filename: createState.fileName,
          fileBase64: base64,
          execute: false,
          valueOverrides: createState.valueOverrides
        })
      });
    }).then(function (result) {
      createState.lastResult = result.json;
      createState.lastOk = result.response.ok;
      showCreateResult(result.json, result.response.ok);
    }).catch(function (error) {
      showStatus(error && error.message ? error.message : String(error), false);
    });
  }
  function render(section) {
    setActive(section);
    if (section === 'schema') renderSchema();
    else if (section === 'contracts') renderContracts();
    else if (section === 'settings') renderSettings();
    else if (section === 'types') renderTypesSettings();
    else if (section === 'check-template') renderCheckTemplate();
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
        verifyChecksumOnPrepare: Boolean(document.getElementById('settings-verify-checksum') && document.getElementById('settings-verify-checksum').checked),
        referenceFixedListLimit: document.getElementById('settings-reference-limit') && document.getElementById('settings-reference-limit').value || 50
      });
      showStatus({
        success: true,
        checksumExtension: settings.checksumExtension,
        verifyChecksumOnPrepare: settings.verifyChecksumOnPrepare,
        referenceFixedListLimit: settings.referenceFixedListLimit
      }, true);
      return;
    }
    if (action === 'save-type-rules') {
      var rules = writeTypeRules(rulesFromControls());
      syncPrepareDecomposeFromRules();
      persistPrepareState();
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
    if (action === 'assign-prepare-contract') {
      var prepareContractSelect = document.getElementById('prepare-contract');
      if (prepareContractSelect && prepareContractSelect.value) {
        var option = prepareContractSelect.options[prepareContractSelect.selectedIndex];
        prepareState.contractId = prepareContractSelect.value || '';
        prepareState.contractCode = option && option.getAttribute('data-code') || '';
        prepareState.contractVersionId = '';
        persistPrepareState();
        updatePrepareContractVersionSummary();
        renderPrepareData();
      }
      return;
    }
    if (action === 'jump-assignment') {
      var jumpKey = button.getAttribute('data-assignment-key') || '';
      var jumpSeparator = jumpKey.indexOf('::');
      prepareState.selectedTypeKey = jumpSeparator === -1 ? jumpKey : jumpKey.slice(0, jumpSeparator);
      prepareState.selectedRoleKey = jumpSeparator === -1 ? '' : jumpKey.slice(jumpSeparator + 2);
      persistPrepareState();
      renderPrepareData();
      return;
    }
    if (action === 'clear-assignment') {
      var clearKey = button.getAttribute('data-assignment-key') || '';
      delete prepareState.classAssignments[clearKey];
      Object.keys(prepareState.attributeAssignments || {}).forEach(function (key) {
        if (key.indexOf(clearKey + '::') === 0) delete prepareState.attributeAssignments[key];
      });
      Object.keys(prepareState.attributeListModes || {}).forEach(function (key) {
        if (key.indexOf(clearKey + '::') === 0) delete prepareState.attributeListModes[key];
      });
      Object.keys(prepareState.attributeSourceRules || {}).forEach(function (key) {
        if (key.indexOf(clearKey + '::') === 0) delete prepareState.attributeSourceRules[key];
      });
      persistPrepareState();
      renderPrepareData();
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
      var verifyInputByButton = document.getElementById('verify-vsdx-file');
      if (verifyInputByButton) verifyInputByButton.click();
      return;
    }
    if (action === 'create-objects' || action === 'execute-create-objects') {
      submitCreateObjects(true);
      return;
    }
    if (action === 'rebuild-create-plan') {
      submitCreateObjects(false);
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
    if (action === 'choose-verify-vsdx') {
      var verifyInput = document.getElementById('verify-vsdx-file');
      if (verifyInput) verifyInput.click();
      return;
    }
    if (action === 'choose-check-template-vsdx') {
      var checkTemplateInput = document.getElementById('check-template-vsdx-file');
      if (checkTemplateInput) checkTemplateInput.click();
      return;
    }
    if (action === 'choose-create-vsdx') {
      var createInput = document.getElementById('create-vsdx-file');
      if (createInput) createInput.click();
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
    if (action === 'add-cmdb-class') {
      var addKey = button.getAttribute('data-class-key') || '';
      var addClasses = assignmentClasses(addKey);
      addClasses.push('');
      setAssignmentClasses(addKey, addClasses);
      delete prepareState.collapsedClassAssignments[classAssignmentCollapseKey(addKey, addClasses.length - 1)];
      persistPrepareState();
      renderPrepareData();
      return;
    }
    if (action === 'remove-cmdb-class') {
      var removeKey = button.getAttribute('data-class-key') || '';
      var removeIndex = Number.parseInt(button.getAttribute('data-class-index') || '0', 10);
      prepareState.collapsedClassAssignments[classAssignmentCollapseKey(removeKey, removeIndex)] = true;
      persistPrepareState();
      renderPrepareData();
      return;
    }
    if (action === 'add-relation-endpoint-map') {
      var relationAddKey = button.getAttribute('data-relation-key') || '';
      var relationAddRows = relationEndpointRows(relationAddKey);
      relationAddRows.push({ relationClassName: '', relationAttributeName: '', className: '', attributeName: '' });
      setRelationEndpointRows(relationAddKey, relationAddRows);
      persistPrepareState();
      renderPrepareData();
      return;
    }
    if (action === 'remove-relation-endpoint-map') {
      var relationRemoveKey = button.getAttribute('data-relation-key') || '';
      var relationRemoveIndex = Number.parseInt(button.getAttribute('data-index') || '0', 10);
      var relationRemoveRows = relationEndpointRows(relationRemoveKey);
      relationRemoveRows.splice(relationRemoveIndex, 1);
      setRelationEndpointRows(relationRemoveKey, relationRemoveRows);
      persistPrepareState();
      renderPrepareData();
      return;
    }
    if (action === 'add-contract-param') {
      prepareState.contractParams = (prepareState.contractParams || []).concat([{ name: '', description: '', type: 'string', required: false, defaultValue: '', listMode: 'none', values: [], help: '' }]);
      persistPrepareState();
      renderPrepareData();
      return;
    }
    if (action === 'remove-contract-param') {
      var contractParamIndex = Number.parseInt(button.getAttribute('data-index') || '0', 10);
      var contractParams = (prepareState.contractParams || []).slice();
      contractParams.splice(contractParamIndex, 1);
      prepareState.contractParams = contractParams;
      persistPrepareState();
      renderPrepareData();
      return;
    }
    if (action === 'apply-contract-params') {
      prepareState.contractParams = normalizedUiContractParams();
      persistPrepareState();
      renderPrepareData();
      var paramsStatus = document.getElementById('contract-params-status');
      if (paramsStatus) paramsStatus.textContent = 'Применено';
      return;
    }
    if (action === 'apply-template-mapping') {
      syncVisibleAttributeAssignmentsFromDom();
      persistPrepareState();
      var applyStatus = document.getElementById('template-mapping-apply-status');
      if (applyStatus) {
        applyStatus.textContent = 'Применено';
        window.setTimeout(function () {
          var currentStatus = document.getElementById('template-mapping-apply-status');
          if (currentStatus) currentStatus.textContent = '';
        }, 1600);
      }
      return;
    }
    if (action === 'enrich-vsdx') {
      enrichVsdx();
      return;
    }
    showStatus('Backend action "' + action + '" is reserved for the next implementation step.', true);
  });
  document.addEventListener('toggle', function (event) {
    var details = event.target;
    if (!details || !details.matches || !details.matches('details.class-assignment')) return;
    var key = details.getAttribute('data-class-assignment-key') || '';
    var index = Number.parseInt(details.getAttribute('data-class-assignment-index') || '0', 10);
    if (!key || Number.isNaN(index)) return;
    var collapseKey = classAssignmentCollapseKey(key, index);
    if (details.open) {
      delete prepareState.collapsedClassAssignments[collapseKey];
    } else {
      prepareState.collapsedClassAssignments[collapseKey] = true;
    }
    persistPrepareState();
  }, true);
  document.addEventListener('change', function (event) {
    if (event.target && (event.target.id === 'vsdx-file' || event.target.id === 'checksum-file')) {
      acceptProvidedFiles(event.target.files);
      event.target.value = '';
      return;
    }
    if (event.target && event.target.id === 'verify-vsdx-file') {
      verifyVsdxFile(event.target.files && event.target.files[0]);
      event.target.value = '';
      return;
    }
    if (event.target && event.target.id === 'check-template-vsdx-file') {
      checkTemplateVsdxFile(event.target.files && event.target.files[0]);
      event.target.value = '';
      return;
    }
    if (event.target && event.target.id === 'create-vsdx-file') {
      createObjectsFromVsdxFile(event.target.files && event.target.files[0]);
      event.target.value = '';
      return;
    }
    if (event.target && event.target.getAttribute('data-create-override-key')) {
      createState.valueOverrides[event.target.getAttribute('data-create-override-key') || ''] = event.target.value || '';
      return;
    }
    if (event.target && (event.target.id === 'settings-checksum-extension' || event.target.id === 'settings-verify-checksum' || event.target.id === 'settings-reference-limit')) {
      writeSettings({
        checksumExtension: document.getElementById('settings-checksum-extension') && document.getElementById('settings-checksum-extension').value || 'sha256',
        verifyChecksumOnPrepare: Boolean(document.getElementById('settings-verify-checksum') && document.getElementById('settings-verify-checksum').checked),
        referenceFixedListLimit: document.getElementById('settings-reference-limit') && document.getElementById('settings-reference-limit').value || 50
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
    if (event.target && event.target.getAttribute('data-attribute-column')) {
      prepareState.attributeColumns[event.target.getAttribute('data-attribute-column')] = Boolean(event.target.checked);
      persistPrepareState();
      renderPrepareData();
    }
    if (event.target && event.target.id === 'prepare-show-connectors') {
      prepareState.showConnectors = Boolean(event.target.checked);
      if (!prepareState.showConnectors) {
        var selected = (prepareState.aggregates || []).filter(function (aggregate) { return aggregate.aggregateTypeKey === prepareState.selectedTypeKey; })[0];
        if (selected && selected.kind === 'connector') prepareState.selectedTypeKey = '';
      }
      persistPrepareState();
      renderPrepareData();
    }
    if (event.target && event.target.id === 'prepare-show-technical') {
      prepareState.showShapeTechnicalInfo = Boolean(event.target.checked);
      persistPrepareState();
      renderPrepareData();
    }
    if (event.target && event.target.id === 'prepare-type-selector') {
      prepareState.selectedTypeKey = event.target.value || '';
      prepareState.selectedRoleKey = '';
      persistPrepareState();
      renderPrepareData();
    }
    if (event.target && event.target.id === 'prepare-atom-selector') {
      prepareState.selectedRoleKey = event.target.value || '';
      persistPrepareState();
      renderPrepareData();
    }
    if (event.target && event.target.id === 'prepare-contract-anchor') {
      prepareState.contractAnchorKey = event.target.value || '';
      persistPrepareState();
      renderPrepareData();
    }
    if (event.target && event.target.id === 'prepare-relation-selector') {
      prepareState.selectedRelationKey = event.target.value || '';
      persistPrepareState();
      renderPrepareData();
    }
    if (event.target && event.target.getAttribute('data-relation-map-class')) {
      var relationClassKey = event.target.getAttribute('data-relation-map-class') || '';
      var relationClassIndex = Number.parseInt(event.target.getAttribute('data-index') || '0', 10);
      var relationClassRows = relationEndpointRows(relationClassKey);
      while (relationClassRows.length <= relationClassIndex) relationClassRows.push({ relationClassName: '', relationAttributeName: '', className: '', attributeName: '' });
      relationClassRows[relationClassIndex] = Object.assign({}, relationClassRows[relationClassIndex], {
        className: event.target.value || '',
        attributeName: ''
      });
      setRelationEndpointRows(relationClassKey, relationClassRows);
      persistPrepareState();
      loadCmdbClassAttributes(event.target.value || '');
      renderPrepareData();
    }
    if (event.target && event.target.getAttribute('data-relation-map-attribute')) {
      var relationAttrKey = event.target.getAttribute('data-relation-map-attribute') || '';
      var relationAttrIndex = Number.parseInt(event.target.getAttribute('data-index') || '0', 10);
      var relationAttrRows = relationEndpointRows(relationAttrKey);
      while (relationAttrRows.length <= relationAttrIndex) relationAttrRows.push({ relationClassName: '', relationAttributeName: '', className: '', attributeName: '' });
      relationAttrRows[relationAttrIndex] = Object.assign({}, relationAttrRows[relationAttrIndex], {
        attributeName: event.target.value || ''
      });
      setRelationEndpointRows(relationAttrKey, relationAttrRows);
      persistPrepareState();
      renderPrepareData();
    }
    if (event.target && event.target.getAttribute('data-relation-map-relation-attribute')) {
      var relationTargetKey = event.target.getAttribute('data-relation-map-relation-attribute') || '';
      var relationTargetIndex = Number.parseInt(event.target.getAttribute('data-index') || '0', 10);
      var relationTargetRows = relationEndpointRows(relationTargetKey);
      var separator = String(event.target.value || '').indexOf('.');
      while (relationTargetRows.length <= relationTargetIndex) relationTargetRows.push({ relationClassName: '', relationAttributeName: '', className: '', attributeName: '' });
      relationTargetRows[relationTargetIndex] = Object.assign({}, relationTargetRows[relationTargetIndex], {
        relationClassName: separator === -1 ? '' : String(event.target.value || '').slice(0, separator),
        relationAttributeName: separator === -1 ? '' : String(event.target.value || '').slice(separator + 1)
      });
      setRelationEndpointRows(relationTargetKey, relationTargetRows);
      persistPrepareState();
      renderPrepareData();
    }
    if (event.target && event.target.getAttribute('data-contract-param-field')) {
      var paramField = event.target.getAttribute('data-contract-param-field') || '';
      var paramIndex = Number.parseInt(event.target.getAttribute('data-index') || '0', 10);
      var params = (prepareState.contractParams || []).slice();
      while (params.length <= paramIndex) params.push({ name: '', description: '', type: 'string', required: false, defaultValue: '', listMode: 'none', values: [], help: '' });
      var currentParam = Object.assign({}, params[paramIndex] || {});
      if (paramField === 'required') currentParam.required = Boolean(event.target.checked);
      else if (paramField === 'valuesText') currentParam.values = String(event.target.value || '').split(/[;\\n,]/).map(function (item) { return item.trim(); }).filter(Boolean);
      else currentParam[paramField] = event.target.value || '';
      params[paramIndex] = currentParam;
      prepareState.contractParams = params;
      persistPrepareState();
    }
    if (event.target && event.target.getAttribute('data-object-class')) {
      var classKey = event.target.getAttribute('data-object-class');
      var classIndex = Number.parseInt(event.target.getAttribute('data-object-class-index') || '0', 10);
      var className = event.target.value || '';
      var classValues = assignmentClasses(classKey);
      while (classValues.length <= classIndex) classValues.push('');
      classValues[classIndex] = className;
      setAssignmentClasses(classKey, classValues);
      persistPrepareState();
      loadCmdbClassAttributes(className);
      renderPrepareData();
    }
    if (event.target && event.target.getAttribute('data-object-attribute')) {
      var attributeKey = event.target.getAttribute('data-object-attribute');
      var current = prepareState.attributeAssignments[attributeKey] || [];
      var attrName = event.target.value || '';
      if (event.target.checked && current.indexOf(attrName) === -1) current = current.concat([attrName]);
      if (!event.target.checked) current = current.filter(function (item) { return item !== attrName; });
      prepareState.attributeAssignments[attributeKey] = current;
      persistPrepareState();
    }
    if (event.target && event.target.getAttribute('data-object-attribute-list-mode')) {
      prepareState.attributeListModes[event.target.getAttribute('data-object-attribute-list-mode')] = event.target.value || 'none';
      persistPrepareState();
    }
    if (event.target && event.target.getAttribute('data-attribute-source-role')) {
      var roleRuleKey = event.target.getAttribute('data-attribute-source-role');
      var roleRule = prepareState.attributeSourceRules[roleRuleKey] || {};
      var roleValue = event.target.value || 'self';
      var targetAttribute = event.target.getAttribute('data-target-attribute') || '';
      prepareState.attributeSourceRules[roleRuleKey] = Object.assign({}, roleRule, {
        targetAttribute: targetAttribute,
        sourceRole: roleValue,
        sourceAttribute: roleRule.sourceAttribute || targetAttribute,
        mode: roleValue === 'manual' ? 'manual' : roleValue === 'constant' ? 'constant' : roleValue === 'default' ? 'default' : roleValue === 'override' ? 'override' : 'copy'
      });
      persistPrepareState();
      renderPrepareData();
    }
    if (event.target && event.target.getAttribute('data-attribute-source-attribute')) {
      var attrRuleKey = event.target.getAttribute('data-attribute-source-attribute');
      var attrRule = prepareState.attributeSourceRules[attrRuleKey] || {};
      prepareState.attributeSourceRules[attrRuleKey] = Object.assign({}, attrRule, {
        targetAttribute: event.target.getAttribute('data-target-attribute') || '',
        sourceAttribute: event.target.value || ''
      });
      persistPrepareState();
    }
    if (event.target && event.target.getAttribute('data-attribute-source-mode')) {
      var modeRuleKey = event.target.getAttribute('data-attribute-source-mode');
      var modeRule = prepareState.attributeSourceRules[modeRuleKey] || {};
      prepareState.attributeSourceRules[modeRuleKey] = Object.assign({}, modeRule, {
        targetAttribute: event.target.getAttribute('data-target-attribute') || '',
        mode: event.target.value || 'copy'
      });
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
  const classAttributesMatch = requestUrl.pathname.match(new RegExp(`^${API_PREFIX.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/cmdb/classes/([^/]+)/attributes$`));
  if (classAttributesMatch) {
    if (!methodAllowed(req, res, 'GET')) return;
    const className = decodeURIComponent(classAttributesMatch[1] || '');
    const attributes = await cmdbuildRequest(`/cmdbuild/services/rest/v3/classes/${encodeURIComponent(className)}/attributes?limit=500&detailed=true`, authToken);
    sendJson(res, attributes.ok ? 200 : 502, {
      success: attributes.ok,
      cmdbuildStatus: attributes.statusCode,
      data: Array.isArray(attributes.json && attributes.json.data)
        ? attributes.json.data.map((item) => ({
          name: item.name || '',
          description: item.description || item._description_translation || '',
          help: item.help || item.helpMessage || item.helpText || item._help_translation || item.metadata && (item.metadata.help || item.metadata.cm_help || item.metadata.note) || '',
          type: item.type || '',
          mandatory: Boolean(item.mandatory),
          inherited: Boolean(item.inherited),
          active: item.active !== false,
          writable: item.writable !== false,
          hidden: Boolean(item.hidden),
          system: Boolean(item.system),
          lookupType: String(item.lookupType || item.lookup || item.lookupName || item._lookupType || ''),
          targetClass: String(item.targetClass || item.target || item.referenceClass || item.destination || ''),
          domain: String(item.domain || item.domainName || item._domain || ''),
          rawSource: {
            lookupType: String(item.lookupType || item.lookup || item.lookupName || item._lookupType || ''),
            targetClass: String(item.targetClass || item.target || item.referenceClass || item.destination || ''),
            domain: String(item.domain || item.domainName || item._domain || '')
          }
        })).filter((item) => item.name && item.active !== false && !item.hidden)
        : [],
      message: attributes.ok ? '' : cmdbuildErrorMessage(attributes, 'CMDBuild class attributes list failed.')
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
  if (requestUrl.pathname === `${API_PREFIX}/vsdx/verify`) {
    if (!methodAllowed(req, res, 'POST')) return;
    try {
      const body = await readJsonBody(req);
      const result = await verifyBaaTemplate(authToken, body);
      sendJson(res, result.success ? 200 : 422, {
        ...result,
        contractVersion: publicContractVersion(result.contractVersion)
      });
    } catch (error) {
      sendJson(res, 400, {
        success: false,
        message: error && error.message ? error.message : String(error)
      });
    }
    return;
  }
  if (requestUrl.pathname === `${API_PREFIX}/vsdx/check-template`) {
    if (!methodAllowed(req, res, 'POST')) return;
    try {
      const body = await readJsonBody(req);
      const result = await checkBaaTemplateTechnical(authToken, body);
      sendJson(res, result.success ? 200 : 422, result);
    } catch (error) {
      sendJson(res, 400, {
        success: false,
        message: error && error.message ? error.message : String(error)
      });
    }
    return;
  }
  if (requestUrl.pathname === `${API_PREFIX}/vsdx/create-objects`) {
    if (!methodAllowed(req, res, 'POST')) return;
    try {
      const body = await readJsonBody(req);
      const result = await createObjectsFromBaaTemplate(authToken, body);
      sendJson(res, result.success ? 200 : 422, result);
    } catch (error) {
      sendJson(res, 400, {
        success: false,
        message: error && error.message ? error.message : String(error)
      });
    }
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
    const contractAnchorKey = String(body.contractAnchorKey || '').trim();
    const typeClassMap = body.typeClassMap && typeof body.typeClassMap === 'object' && !Array.isArray(body.typeClassMap)
      ? body.typeClassMap
      : {};
    const aggregateClassMap = body.aggregateClassMap && typeof body.aggregateClassMap === 'object' && !Array.isArray(body.aggregateClassMap)
      ? body.aggregateClassMap
      : {};
    const aggregateAttributeMap = body.aggregateAttributeMap && typeof body.aggregateAttributeMap === 'object' && !Array.isArray(body.aggregateAttributeMap)
      ? body.aggregateAttributeMap
      : {};
    let attributeCatalog = body.cmdbClassAttributes && typeof body.cmdbClassAttributes === 'object' && !Array.isArray(body.cmdbClassAttributes)
      ? body.cmdbClassAttributes
      : {};
    const attributeListModes = body.aggregateAttributeListModes && typeof body.aggregateAttributeListModes === 'object' && !Array.isArray(body.aggregateAttributeListModes)
      ? body.aggregateAttributeListModes
      : {};
    const attributeSourceRules = body.aggregateAttributeSourceRules && typeof body.aggregateAttributeSourceRules === 'object' && !Array.isArray(body.aggregateAttributeSourceRules)
      ? body.aggregateAttributeSourceRules
      : {};
    const relationEndpointMappings = body.relationEndpointMappings && typeof body.relationEndpointMappings === 'object' && !Array.isArray(body.relationEndpointMappings)
      ? body.relationEndpointMappings
      : {};
    const contractParams = normalizeContractParams(Array.isArray(body.contractParams) ? body.contractParams : []);
    const settings = body.settings && typeof body.settings === 'object' && !Array.isArray(body.settings)
      ? body.settings
      : {};
    const preparedAt = new Date().toISOString();
    const preparedBy = String(body.preparedBy || '').trim();
    if (!contractAnchorKey) {
      sendJson(res, 400, {
        success: false,
        message: 'Contract object is required. Select an object in the diagram before enrichment.'
      });
      return;
    }
    const result = withTempFile('cmdbaa-enrich-', '.vsdx', inputBuffer, (filePath, dir) => {
      const outputPath = path.join(dir, 'enriched.vsdx');
      const typeRules = parseContractRules(body.typeRules || {});
      typeRules.presentation = {
        ...(typeRules.presentation || {}),
        decomposeAggregates: Boolean(body.decomposeAggregates)
      };
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
    let listResolution = { attributeCatalog, warnings: [] };
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
      listResolution = await resolveAttributeListValues(authToken, attributeCatalog, attributeListModes, settings);
      attributeCatalog = listResolution.attributeCatalog;
      versionResolution = await resolveContractVersionForEnrichment(authToken, {
        contract,
        existingMetadata: result.existingMetadata,
        types: result.types,
        aggregates: result.aggregates,
        aggregateClassMap,
        aggregateAttributeMap,
        attributeListModes,
        attributeSourceRules,
        relationEndpointMappings,
        contractParams,
        attributeCatalog,
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
    const knownContractAnchorKeys = aggregatePageShapeKeys(result.aggregates);
    if (!knownContractAnchorKeys.has(contractAnchorKey)) {
      sendJson(res, 400, {
        success: false,
        message: 'Selected contract object was not found in the current VSDX.'
      });
      return;
    }
    const effectiveMappingMaps = mergeMappingMaps(
      mappingMapsFromKnownMappings(versionResolution.knownMappings || []),
      currentMappingMaps(aggregateClassMap, aggregateAttributeMap, attributeListModes, attributeSourceRules)
    );
    const shapeMappings = shapeMappingsFromAggregates(result.aggregates, effectiveMappingMaps.classMap, {
      decomposeAggregates: Boolean(body.decomposeAggregates),
      aggregateAttributeMap: effectiveMappingMaps.attributeMap,
      attributeListModes: effectiveMappingMaps.attributeListModes,
      attributeSourceRules: effectiveMappingMaps.attributeSourceRules,
      attributeCatalog,
      contractAnchorKey
    });
    shapeMappings.metadataByPageShapeId[contractAnchorKey] = {
      ...(shapeMappings.metadataByPageShapeId[contractAnchorKey] || {}),
      contractAnchor: 'true',
      mappingKey: '',
      roleKey: '',
      cmdbEntitySlot: ''
    };
    const enriched = withTempFile('cmdbaa-enrich-', '.vsdx', inputBuffer, (filePath, dir) => {
      const outputPath = path.join(dir, 'enriched.vsdx');
      const pages = enrichVsdxFile(filePath, outputPath, {
        classByTypeKey: typeClassMap,
        classByPageShapeId: shapeMappings.classByPageShapeId,
        metadataByPageShapeId: shapeMappings.metadataByPageShapeId,
        rules: contractRules,
        contractVersion: fixedContractVersion,
        contractPageShapeKey: contractAnchorKey,
        preparedAt,
        preparedBy
      });
      return {
        pages,
        buffer: fs.readFileSync(outputPath)
      };
    });
    const filename = String(body.filename || 'template.vsdx').replace(/\.vsdx$/i, '') + '.enriched.vsdx';
    const checksumExtension = String(settings.checksumExtension || 'sha256').trim().replace(/^\.+/, '') || 'sha256';
    const checksumAlgorithm = checksumAlgorithmFromExtension(checksumExtension);
    const outputChecksum = digestHex(checksumAlgorithm, enriched.buffer);
    const checksumFilename = `${filename}.${checksumExtension}`;
    sendJson(res, 200, {
      success: true,
      filename,
      fileBase64: enriched.buffer.toString('base64'),
      checksum: {
        filename: checksumFilename,
        algorithm: checksumAlgorithm,
        extension: checksumExtension,
        value: outputChecksum,
        text: `${checksumAlgorithm} ${outputChecksum}  ${filename}\n`
      },
      summary: {
        pages: enriched.pages,
        mappedTypes: Object.keys(typeClassMap).length,
        mappedAggregateRoles: Object.keys(aggregateClassMap).length,
        mappedShapes: Object.keys(shapeMappings.classByPageShapeId).length,
        mappedShapeAssignments: shapeMappings.mapped.length,
        skippedShapeAssignments: shapeMappings.skipped.length,
        skippedShapeAssignmentReasons: Array.from(new Set(shapeMappings.skipped.map((item) => item.reason).filter(Boolean))),
        versionAction: versionResolution.action,
        addedTypes: versionResolution.addedTypes.length,
        knownTypes: versionResolution.knownTypes.length,
        addedAggregates: versionResolution.addedAggregates.length,
        knownAggregates: versionResolution.knownAggregates.length,
        addedMappings: versionResolution.addedMappings.length,
        knownMappings: versionResolution.knownMappings.length,
        contractParams: versionResolution.contractParams.length,
        listWarnings: listResolution.warnings.length
      },
      contractVersion: fixedContractVersion,
      versionAction: versionResolution.action,
      addedTypes: versionResolution.addedTypes,
      addedAggregates: versionResolution.addedAggregates,
      addedMappings: versionResolution.addedMappings,
      contractParams: versionResolution.contractParams,
      warnings: listResolution.warnings,
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
    'function normalize(v){v=String(v||"").toLowerCase();if(v==="schema"||v==="cmdb-schema")return"schema";if(v==="contracts"||v==="contract"||v==="conversion-contracts")return"contracts";if(v==="settings"||v==="config"||v==="configuration")return"settings";if(v==="types"||v==="type-settings"||v==="visio-types")return"types";if(v==="check-template"||v==="template-check"||v==="technical-check")return"check-template";if(v==="verify"||v==="verification")return"verify";if(v==="create-objects"||v==="create"||v==="objects")return"create-objects";return"prepare-template";}',
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
