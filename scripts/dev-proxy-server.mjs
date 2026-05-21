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
        inherited: Boolean(attr.inherited),
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
      },
      {
        name: 'BAAVerificationInputContract',
        description: 'BAA verification input contract',
        parent: root,
        prototype: false,
        attributes: [
          { name: 'BAAContractVersionId', description: 'BAA contract version id', type: 'string', mandatory: true, unique: false, showInGrid: true, maxLength: 64 },
          { name: 'BAAContractVersionCode', description: 'BAA contract version code', type: 'string', mandatory: true, unique: false, showInGrid: true, maxLength: 100 },
          { name: 'ContractVersion', description: 'Verification contract version', type: 'string', mandatory: true, unique: false, showInGrid: true, maxLength: 50 },
          { name: 'ContractStatus', description: 'Verification contract status', type: 'string', mandatory: true, unique: false, showInGrid: true, maxLength: 32 },
          { name: 'SchemaJson', description: 'Input schema JSON', type: 'text', mandatory: true, unique: false, showInGrid: false },
          { name: 'SchemaChecksum', description: 'Schema checksum', type: 'string', mandatory: true, unique: false, showInGrid: true, maxLength: 128 },
          { name: 'CreatedBy', description: 'Created by', type: 'string', mandatory: false, unique: false, showInGrid: true, maxLength: 100 },
          { name: 'CreatedAt', description: 'Created at', type: 'string', mandatory: false, unique: false, showInGrid: true, maxLength: 40 }
        ]
      },
      {
        name: 'BAAVerificationOutputContract',
        description: 'BAA verification output contract',
        parent: root,
        prototype: false,
        attributes: [
          { name: 'BAAContractVersionId', description: 'BAA contract version id', type: 'string', mandatory: true, unique: false, showInGrid: true, maxLength: 64 },
          { name: 'BAAContractVersionCode', description: 'BAA contract version code', type: 'string', mandatory: true, unique: false, showInGrid: true, maxLength: 100 },
          { name: 'ContractVersion', description: 'Verification contract version', type: 'string', mandatory: true, unique: false, showInGrid: true, maxLength: 50 },
          { name: 'ContractStatus', description: 'Verification contract status', type: 'string', mandatory: true, unique: false, showInGrid: true, maxLength: 32 },
          { name: 'SchemaJson', description: 'Output schema JSON', type: 'text', mandatory: true, unique: false, showInGrid: false },
          { name: 'SchemaChecksum', description: 'Schema checksum', type: 'string', mandatory: true, unique: false, showInGrid: true, maxLength: 128 },
          { name: 'CreatedBy', description: 'Created by', type: 'string', mandatory: false, unique: false, showInGrid: true, maxLength: 100 },
          { name: 'CreatedAt', description: 'Created at', type: 'string', mandatory: false, unique: false, showInGrid: true, maxLength: 40 }
        ]
      },
      {
        name: 'BAAVerificationEndpoint',
        description: 'BAA verification endpoint',
        parent: root,
        prototype: false,
        attributes: [
          { name: 'InputContractCode', description: 'Input contract code', type: 'string', mandatory: true, unique: false, showInGrid: true, maxLength: 100 },
          { name: 'InputContractVersion', description: 'Input contract version', type: 'string', mandatory: true, unique: false, showInGrid: true, maxLength: 50 },
          { name: 'OutputContractCode', description: 'Output contract code', type: 'string', mandatory: true, unique: false, showInGrid: true, maxLength: 100 },
          { name: 'OutputContractVersion', description: 'Output contract version', type: 'string', mandatory: true, unique: false, showInGrid: true, maxLength: 50 },
          { name: 'EndpointUrl', description: 'Endpoint URL', type: 'string', mandatory: true, unique: false, showInGrid: true, maxLength: 500 },
          { name: 'EndpointMethod', description: 'Endpoint method', type: 'string', mandatory: true, unique: false, showInGrid: true, maxLength: 16 },
          { name: 'ParamsJson', description: 'Call parameters JSON', type: 'text', mandatory: false, unique: false, showInGrid: false },
          { name: 'ResultInterpretationJson', description: 'Result interpretation JSON', type: 'text', mandatory: false, unique: false, showInGrid: false },
          { name: 'EndpointStatus', description: 'Endpoint status', type: 'string', mandatory: true, unique: false, showInGrid: true, maxLength: 32 },
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

function sanitizeVerificationContractCard(data) {
  if (!data || typeof data !== 'object') return null;
  return {
    id: data._id || data.Id || data.id || null,
    code: data.Code || data.code || '',
    description: data.Description || data.description || data._Description_description || '',
    baaContractVersionId: data.BAAContractVersionId || data.bAAContractVersionId || '',
    baaContractVersionCode: data.BAAContractVersionCode || data.bAAContractVersionCode || '',
    version: data.ContractVersion || data.contractVersion || '',
    status: data.ContractStatus || data.contractStatus || 'Draft',
    schemaJson: data.SchemaJson || data.schemaJson || '',
    schemaChecksum: data.SchemaChecksum || data.schemaChecksum || '',
    createdBy: data.CreatedBy || data.createdBy || '',
    createdAt: data.CreatedAt || data.createdAt || ''
  };
}

function sanitizeVerificationEndpointCard(data) {
  if (!data || typeof data !== 'object') return null;
  return {
    id: data._id || data.Id || data.id || null,
    code: data.Code || data.code || '',
    description: data.Description || data.description || data._Description_description || '',
    inputContractCode: data.InputContractCode || data.inputContractCode || '',
    inputContractVersion: data.InputContractVersion || data.inputContractVersion || '',
    outputContractCode: data.OutputContractCode || data.outputContractCode || '',
    outputContractVersion: data.OutputContractVersion || data.outputContractVersion || '',
    endpointUrl: data.EndpointUrl || data.endpointUrl || '',
    method: data.EndpointMethod || data.endpointMethod || 'POST',
    paramsJson: data.ParamsJson || data.paramsJson || '',
    resultInterpretationJson: data.ResultInterpretationJson || data.resultInterpretationJson || '',
    status: data.EndpointStatus || data.endpointStatus || 'Draft',
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

function verificationClassNames(settings = {}) {
  return {
    input: validateCmdbuildIdentifier(settings.verificationInputContractClass || 'BAAVerificationInputContract', 'verification input contract class'),
    output: validateCmdbuildIdentifier(settings.verificationOutputContractClass || 'BAAVerificationOutputContract', 'verification output contract class'),
    endpoint: validateCmdbuildIdentifier(settings.verificationEndpointClass || 'BAAVerificationEndpoint', 'verification endpoint class')
  };
}

async function listVerificationContracts(authToken, className) {
  const response = await cmdbuildRequest(`/cmdbuild/services/rest/v3/classes/${encodeURIComponent(className)}/cards?limit=200&detailed=true`, authToken);
  return {
    success: response.ok,
    cmdbuildStatus: response.statusCode,
    data: Array.isArray(response.json && response.json.data)
      ? response.json.data.map(sanitizeVerificationContractCard).filter(Boolean)
      : [],
    message: response.ok ? '' : cmdbuildErrorMessage(response, `CMDBuild ${className} list failed.`)
  };
}

async function createVerificationContract(authToken, className, input = {}) {
  const code = validateBusinessCode(input.code || input.Code, 'verification contract code');
  const version = String(input.version || input.ContractVersion || '1').trim() || '1';
  const description = String(input.description || input.Description || code).trim() || code;
  const status = validateContractVersionStatus(input.status || input.ContractStatus || 'Draft');
  const schemaText = String(input.schemaJson || input.SchemaJson || '{}').trim() || '{}';
  let schemaObject;
  try {
    schemaObject = JSON.parse(schemaText);
  } catch {
    throw new Error('SchemaJson must be valid JSON.');
  }
  const normalizedSchemaJson = JSON.stringify(schemaObject, null, 2);
  const schemaChecksum = digestHex('sha256', Buffer.from(normalizedSchemaJson, 'utf8'));
  const response = await cmdbuildRequest(`/cmdbuild/services/rest/v3/classes/${encodeURIComponent(className)}/cards`, authToken, {
    method: 'POST',
    body: {
      Code: code,
      Description: description,
      BAAContractVersionId: String(input.baaContractVersionId || input.BAAContractVersionId || '').trim(),
      BAAContractVersionCode: String(input.baaContractVersionCode || input.BAAContractVersionCode || '').trim(),
      ContractVersion: version,
      ContractStatus: status,
      SchemaJson: normalizedSchemaJson,
      SchemaChecksum: schemaChecksum,
      CreatedBy: String(input.createdBy || input.CreatedBy || '').trim(),
      CreatedAt: new Date().toISOString()
    }
  });
  return {
    success: response.ok,
    cmdbuildStatus: response.statusCode,
    data: sanitizeVerificationContractCard(response.json && response.json.data),
    schemaChecksum,
    message: response.ok ? '' : cmdbuildErrorMessage(response, `CMDBuild ${className} create failed.`)
  };
}

async function listVerificationEndpoints(authToken, className) {
  const response = await cmdbuildRequest(`/cmdbuild/services/rest/v3/classes/${encodeURIComponent(className)}/cards?limit=200&detailed=true`, authToken);
  return {
    success: response.ok,
    cmdbuildStatus: response.statusCode,
    data: Array.isArray(response.json && response.json.data)
      ? response.json.data.map(sanitizeVerificationEndpointCard).filter(Boolean)
      : [],
    message: response.ok ? '' : cmdbuildErrorMessage(response, `CMDBuild ${className} endpoint list failed.`)
  };
}

function findVerificationContractItem(items = [], code = '', version = '') {
  const wantedCode = String(code || '').trim();
  const wantedVersion = String(version || '').trim();
  return (items || []).find((item) =>
    (!wantedCode || item.code === wantedCode) &&
    (!wantedVersion || item.version === wantedVersion)
  ) || null;
}

async function resolveVerificationContractSelection(authToken, settings, kind, code, version) {
  const classes = verificationClassNames(settings || {});
  const className = kind === 'output' ? classes.output : classes.input;
  const result = await listVerificationContracts(authToken, className);
  if (!result.success) return { success: false, message: result.message, className };
  const contract = findVerificationContractItem(result.data, code, version);
  if (!contract) return { success: false, message: `${kind} verification contract was not found: ${code || '*'} / ${version || '*'}`, className };
  if (contract.status !== 'Active') return { success: false, message: `${kind} verification contract is not Active: ${contract.code} / ${contract.version} / ${contract.status}`, className, contract };
  let schema = {};
  try {
    schema = JSON.parse(contract.schemaJson || '{}');
  } catch {
    return { success: false, message: `${kind} verification contract SchemaJson is invalid JSON.`, className, contract };
  }
  return { success: true, className, contract, schema };
}

function validatePlanAgainstInputContract(plan = {}, schema = {}) {
  const issues = [];
  const planClasses = new Map();
  for (const object of plan.objects || []) {
    const className = object.className || '';
    if (!className) continue;
    if (!planClasses.has(className)) planClasses.set(className, new Set());
    const attrs = planClasses.get(className);
    for (const source of object.attributeSources || []) {
      if (source.targetAttribute) attrs.add(source.targetAttribute);
    }
    for (const attrName of Object.keys(object.payload || {})) attrs.add(attrName);
  }
  for (const cls of Array.isArray(schema.classes) ? schema.classes : []) {
    if (!cls || !cls.name) continue;
    if (!planClasses.has(cls.name)) {
      issues.push({ level: 'error', code: 'input_contract_class_missing', className: cls.name, message: `В плане нет класса из input contract: ${cls.name}` });
      continue;
    }
    const attrs = planClasses.get(cls.name);
    for (const attr of Array.isArray(cls.attributes) ? cls.attributes : []) {
      if (attr && attr.name && !attrs.has(attr.name)) {
        issues.push({ level: 'error', code: 'input_contract_attribute_missing', className: cls.name, attribute: attr.name, message: `В плане нет атрибута из input contract: ${cls.name}.${attr.name}` });
      }
    }
  }
  const contextCount = (plan.objects || []).filter((item) => item.kind === 'context').length;
  const requiredRelations = Array.isArray(schema.relations) ? schema.relations : [];
  if (requiredRelations.length && !contextCount) {
    issues.push({ level: 'error', code: 'input_contract_relations_missing', message: 'Input contract ожидает relation context, но в плане нет объектов kind=context.' });
  }
  return issues;
}

function validateObjectByContractShape(value, shape = {}, path = '') {
  const issues = [];
  const rules = shape && typeof shape === 'object' ? shape : {};
  for (const [field, rule] of Object.entries(rules)) {
    const currentPath = path ? `${path}.${field}` : field;
    const mandatory = Boolean(rule && rule.mandatory);
    const expectedType = String(rule && rule.type || '');
    const hasValue = value && Object.prototype.hasOwnProperty.call(value, field);
    if (mandatory && !hasValue) {
      issues.push({ level: 'error', code: 'output_contract_field_missing', message: `В ответе нет обязательного поля ${currentPath}.` });
      continue;
    }
    if (!hasValue) continue;
    const actual = value[field];
    if (expectedType === 'array' && !Array.isArray(actual)) issues.push({ level: 'error', code: 'output_contract_type_mismatch', message: `${currentPath} должен быть array.` });
    if (expectedType === 'object' && (!actual || typeof actual !== 'object' || Array.isArray(actual))) issues.push({ level: 'error', code: 'output_contract_type_mismatch', message: `${currentPath} должен быть object.` });
    if (expectedType === 'boolean' && typeof actual !== 'boolean') issues.push({ level: 'error', code: 'output_contract_type_mismatch', message: `${currentPath} должен быть boolean.` });
    if (expectedType === 'string' && typeof actual !== 'string') issues.push({ level: 'error', code: 'output_contract_type_mismatch', message: `${currentPath} должен быть string.` });
    if (expectedType === 'number' && typeof actual !== 'number') issues.push({ level: 'error', code: 'output_contract_type_mismatch', message: `${currentPath} должен быть number.` });
    if (Array.isArray(rule.allowed) && !rule.allowed.includes(String(actual))) issues.push({ level: 'error', code: 'output_contract_value_not_allowed', message: `${currentPath} имеет недопустимое значение.` });
  }
  return issues;
}

function validateVerificationOutputByContract(value, schema = {}) {
  const issues = validateVerificationOutput(value);
  if (!value || typeof value !== 'object' || Array.isArray(value)) return issues;
  if (schema && schema.response) {
    issues.push(...validateObjectByContractShape(value, schema.response, 'response'));
    if (Array.isArray(value.items) && schema.response.items && schema.response.items.item) {
      value.items.forEach((item, index) => {
        issues.push(...validateObjectByContractShape(item, schema.response.items.item, `items[${index}]`));
      });
    }
    if (Array.isArray(value.tables) && schema.response.tables && schema.response.tables.item) {
      value.tables.forEach((table, index) => {
        issues.push(...validateObjectByContractShape(table, schema.response.tables.item, `tables[${index}]`));
      });
    }
  }
  return issues;
}

function defaultResultInterpretation() {
  return {
    mode: 'rows_present_is_error',
    target: { scope: 'all_tables', tableCode: '' },
    severity: 'error',
    messageIfMatched: 'Найдены данные, требующие внимания',
    messageIfNotMatched: 'Данные не найдены',
    showTablesOnMatched: true,
    showTablesOnNotMatched: false
  };
}

function normalizeResultInterpretation(input = {}) {
  const defaults = defaultResultInterpretation();
  const raw = input && typeof input === 'object' && !Array.isArray(input) ? input : {};
  const mode = [
    'rows_present_is_error',
    'rows_absent_is_error',
    'rows_present_is_warning',
    'rows_absent_is_warning',
    'manual_review',
    'technical_only'
  ].includes(String(raw.mode || '')) ? String(raw.mode) : defaults.mode;
  const target = raw.target && typeof raw.target === 'object' && !Array.isArray(raw.target) ? raw.target : {};
  const scope = target.scope === 'table' ? 'table' : 'all_tables';
  const severity = ['error', 'warning', 'info'].includes(String(raw.severity || '')) ? String(raw.severity) : defaults.severity;
  return {
    mode,
    target: {
      scope,
      tableCode: String(target.tableCode || raw.tableCode || '').trim()
    },
    severity,
    messageIfMatched: String(raw.messageIfMatched || defaults.messageIfMatched),
    messageIfNotMatched: String(raw.messageIfNotMatched || defaults.messageIfNotMatched),
    showTablesOnMatched: typeof raw.showTablesOnMatched === 'boolean' ? raw.showTablesOnMatched : defaults.showTablesOnMatched,
    showTablesOnNotMatched: typeof raw.showTablesOnNotMatched === 'boolean' ? raw.showTablesOnNotMatched : defaults.showTablesOnNotMatched
  };
}

function parseResultInterpretationJson(value) {
  try {
    return normalizeResultInterpretation(JSON.parse(String(value || '{}')));
  } catch {
    return normalizeResultInterpretation({});
  }
}

function interpretVerificationTables(response = {}, interpretationInput = {}) {
  const interpretation = normalizeResultInterpretation(interpretationInput);
  if (!response || typeof response !== 'object' || Array.isArray(response)) {
    return {
      interpretation,
      status: 'technical_error',
      matched: true,
      rowCount: 0,
      message: 'Ответ внешней верификации не является JSON object.',
      showTables: false,
      items: [{ level: 'error', code: 'verification_response_invalid', message: 'Ответ внешней верификации не является JSON object.' }]
    };
  }
  if (response.success === false) {
    return {
      interpretation,
      status: 'technical_error',
      matched: true,
      rowCount: 0,
      message: response.message || 'Endpoint вернул техническую ошибку.',
      showTables: false,
      items: [{ level: 'error', code: 'verification_endpoint_error', message: response.message || 'Endpoint вернул техническую ошибку.' }]
    };
  }
  const tables = Array.isArray(response.tables) ? response.tables : [];
  const selectedTables = interpretation.target.scope === 'table'
    ? tables.filter((table) => String(table && table.code || '') === interpretation.target.tableCode)
    : tables;
  const rowCount = selectedTables.reduce((sum, table) => sum + (Array.isArray(table && table.rows) ? table.rows.length : 0), 0);
  const hasRows = rowCount > 0;
  let matched = false;
  if (interpretation.mode === 'rows_present_is_error' || interpretation.mode === 'rows_present_is_warning') matched = hasRows;
  if (interpretation.mode === 'rows_absent_is_error' || interpretation.mode === 'rows_absent_is_warning') matched = !hasRows;
  if (interpretation.mode === 'manual_review') matched = hasRows;
  if (interpretation.mode === 'technical_only') matched = false;
  let status = 'passed';
  if (interpretation.mode === 'manual_review') status = 'manual_review';
  else if (interpretation.mode === 'technical_only') status = 'passed';
  else if (matched && (interpretation.mode.endsWith('_is_error') || interpretation.severity === 'error')) status = 'failed';
  else if (matched) status = 'warning';
  const level = status === 'failed' ? 'error' : status === 'warning' || status === 'manual_review' ? 'warning' : 'info';
  const message = matched ? interpretation.messageIfMatched : interpretation.messageIfNotMatched;
  return {
    interpretation,
    status,
    matched,
    rowCount,
    message,
    showTables: matched ? interpretation.showTablesOnMatched : interpretation.showTablesOnNotMatched,
    items: [{
      level,
      code: `verification_interpretation_${status}`,
      message: `${message}. Строк: ${rowCount}.`,
      data: {
        rowCount,
        mode: interpretation.mode,
        target: interpretation.target
      }
    }]
  };
}

async function createVerificationEndpoint(authToken, className, input = {}) {
  const code = validateBusinessCode(input.code || input.Code, 'verification endpoint code');
  const description = String(input.description || input.Description || code).trim() || code;
  const method = String(input.method || input.EndpointMethod || 'POST').trim().toUpperCase() || 'POST';
  if (method !== 'POST') throw new Error('Only POST verification endpoint method is supported.');
  const paramsText = String(input.paramsJson || input.ParamsJson || '{}').trim() || '{}';
  try {
    JSON.parse(paramsText);
  } catch {
    throw new Error('ParamsJson must be valid JSON.');
  }
  const interpretationText = String(input.resultInterpretationJson || input.ResultInterpretationJson || '{}').trim() || '{}';
  try {
    JSON.parse(interpretationText);
  } catch {
    throw new Error('ResultInterpretationJson must be valid JSON.');
  }
  const response = await cmdbuildRequest(`/cmdbuild/services/rest/v3/classes/${encodeURIComponent(className)}/cards`, authToken, {
    method: 'POST',
    body: {
      Code: code,
      Description: description,
      InputContractCode: String(input.inputContractCode || input.InputContractCode || '').trim(),
      InputContractVersion: String(input.inputContractVersion || input.InputContractVersion || '').trim(),
      OutputContractCode: String(input.outputContractCode || input.OutputContractCode || '').trim(),
      OutputContractVersion: String(input.outputContractVersion || input.OutputContractVersion || '').trim(),
      EndpointUrl: String(input.endpointUrl || input.EndpointUrl || '').trim(),
      EndpointMethod: method,
      ParamsJson: JSON.stringify(JSON.parse(paramsText), null, 2),
      ResultInterpretationJson: JSON.stringify(JSON.parse(interpretationText), null, 2),
      EndpointStatus: String(input.status || input.EndpointStatus || 'Draft').trim() || 'Draft',
      CreatedBy: String(input.createdBy || input.CreatedBy || '').trim(),
      CreatedAt: new Date().toISOString()
    }
  });
  return {
    success: response.ok,
    cmdbuildStatus: response.statusCode,
    data: sanitizeVerificationEndpointCard(response.json && response.json.data),
    message: response.ok ? '' : cmdbuildErrorMessage(response, `CMDBuild ${className} endpoint create failed.`)
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
  const containers = objects
    .filter((object) => object && object.page && Array.isArray(object.containedShapeIds) && object.containedShapeIds.length)
    .sort((left, right) => left.containedShapeIds.length - right.containedShapeIds.length);
  for (const object of containers) {
    for (const shapeId of object.containedShapeIds) {
      const key = `${object.page}:${shapeId}`;
      if (!result.has(key)) result.set(key, object);
    }
  }
  return result;
}

function uniqueObjectsFromShapeMap(shapeByKey) {
  return Array.from(new Set(Array.from(shapeByKey && shapeByKey.values ? shapeByKey.values() : [])));
}

function objectContainsShape(container, object) {
  return Boolean(
    container &&
    object &&
    container.page === object.page &&
    String(container.shapeId || '') !== String(object.shapeId || '') &&
    Array.isArray(container.containedShapeIds) &&
    container.containedShapeIds.includes(String(object.shapeId || ''))
  );
}

function containedCmdbObjects(shapeByKey, container) {
  if (!container) return [];
  return uniqueObjectsFromShapeMap(shapeByKey)
    .filter((object) => objectContainsShape(container, object) && Array.isArray(object.cmdbClasses) && object.cmdbClasses.length);
}

function endpointPointFor(object, sourceRole) {
  const geometry = object && object.geometry || {};
  if (sourceRole === 'source' && Number.isFinite(geometry.beginX) && Number.isFinite(geometry.beginY)) {
    return { x: geometry.beginX, y: geometry.beginY };
  }
  if (sourceRole === 'destination' && Number.isFinite(geometry.endX) && Number.isFinite(geometry.endY)) {
    return { x: geometry.endX, y: geometry.endY };
  }
  return null;
}

function pointDistanceToObject(point, object) {
  const geometry = object && object.geometry || {};
  if (!point || !Number.isFinite(geometry.pinX) || !Number.isFinite(geometry.pinY) || !Number.isFinite(geometry.width) || !Number.isFinite(geometry.height)) return null;
  const halfWidth = Math.max(geometry.width / 2, 0);
  const halfHeight = Math.max(geometry.height / 2, 0);
  const dx = Math.max(Math.abs(point.x - geometry.pinX) - halfWidth, 0);
  const dy = Math.max(Math.abs(point.y - geometry.pinY) - halfHeight, 0);
  return Math.hypot(dx, dy);
}

function endpointObjectByGeometry(shapeByKey, object, sourceRole) {
  const point = endpointPointFor(object, sourceRole);
  if (!point) return null;
  const candidates = Array.from(new Set(shapeByKey.values()))
    .filter((candidate) =>
      candidate &&
      candidate !== object &&
      candidate.page === object.page &&
      Array.isArray(candidate.cmdbClasses) &&
      candidate.cmdbClasses.length &&
      !candidate.sourceShapeId &&
      !candidate.destinationShapeId
    )
    .map((candidate) => ({ candidate, distance: pointDistanceToObject(point, candidate) }))
    .filter((item) => item.distance !== null && item.distance <= 0.08)
    .sort((left, right) => {
      if (left.distance !== right.distance) return left.distance - right.distance;
      const leftGeometry = left.candidate.geometry || {};
      const rightGeometry = right.candidate.geometry || {};
      return (leftGeometry.width || 0) * (leftGeometry.height || 0) - (rightGeometry.width || 0) * (rightGeometry.height || 0);
    });
  return candidates.length ? candidates[0].candidate : null;
}

function objectForEndpoint(shapeByKey, object, shapeId, sourceRole = '') {
  if (shapeId) {
    const exact = shapeByKey.get(`${object.page}:${shapeId}`);
    if (exact) return exact;
  }
  return endpointObjectByGeometry(shapeByKey, object, sourceRole);
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

function systemAttributeCatalog(className) {
  return [
    { name: 'Code', description: 'Code', type: 'string', mandatory: true, inherited: true, active: true, writable: true, system: true },
    { name: 'Description', description: 'Description', type: 'string', mandatory: true, inherited: true, active: true, writable: true, system: true }
  ];
}

function mergeClassAttributeCatalog(mapping, className, catalog = []) {
  const byName = attributeDefinitionMap(mapping, className);
  for (const attr of [...systemAttributeCatalog(className), ...(Array.isArray(catalog) ? catalog : [])]) {
    if (!attr || !attr.name || attr.active === false || attr.hidden) continue;
    if (byName.has(attr.name)) {
      byName.set(attr.name, { ...attr, ...byName.get(attr.name) });
    } else {
      byName.set(attr.name, {
        name: attr.name,
        description: attr.description || attr.name,
        type: attr.type || '',
        mandatory: Boolean(attr.mandatory),
        inherited: Boolean(attr.inherited),
        validation: attr.validation || '',
        sourceRule: {
          targetClass: className,
          targetAttribute: attr.name,
          sourceRole: 'manual',
          sourceAttribute: attr.name,
          mode: 'manual'
        }
      });
    }
  }
  return byName;
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

function endpointClassSet(endpointObject, shapeByKey) {
  const result = new Set(endpointObject && endpointObject.cmdbClasses || []);
  for (const object of containedCmdbObjects(shapeByKey, endpointObject)) {
    for (const className of object.cmdbClasses || []) result.add(className);
  }
  return result;
}

function sourceAttributeRefFromRelationMapping(object, rule, endpointObject, relationEndpointMappings, shapeByKey = null) {
  const sourceRole = rule && rule.sourceRole || 'self';
  if (!['source', 'destination'].includes(sourceRole)) {
    return sourceAttributeRef(rule, endpointObject && endpointObject.cmdbClasses && endpointObject.cmdbClasses[0] || '');
  }
  const relationKey = relationEndpointMappingKeyForObject(object);
  const relationMapping = relationEndpointMappings && relationEndpointMappings[relationKey] || {};
  const attributeMappings = Array.isArray(relationMapping.attributes) ? relationMapping.attributes : [];
  const endpointClasses = endpointClassSet(endpointObject, shapeByKey);
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

function endpointAttributeResolution(endpointObject, className, attrName, shapeByKey) {
  if (!endpointObject || !className || !attrName) return { status: 'missing', value: undefined, sourceObject: null, candidates: [] };
  const ownValue = valueForClassAttribute(endpointObject, className, attrName);
  if (typeof ownValue !== 'undefined' && String(ownValue || '').trim()) {
    return { status: 'direct', value: ownValue, sourceObject: endpointObject, candidates: [endpointObject] };
  }
  const candidates = containedCmdbObjects(shapeByKey, endpointObject)
    .filter((object) => (object.cmdbClasses || []).includes(className))
    .map((object) => ({ object, value: valueForClassAttribute(object, className, attrName) }))
    .filter((item) => typeof item.value !== 'undefined' && String(item.value || '').trim());
  if (candidates.length === 1) {
    return { status: 'contained', value: candidates[0].value, sourceObject: candidates[0].object, candidates: [candidates[0].object] };
  }
  if (candidates.length > 1) {
    return { status: 'ambiguous', value: undefined, sourceObject: null, candidates: candidates.map((item) => item.object) };
  }
  return { status: 'missing', value: ownValue, sourceObject: endpointObject, candidates: [] };
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
  const endpointObject = objectForEndpoint(shapeByKey, object, endpointShapeId, sourceRole);
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
  const ref = sourceAttributeRefFromRelationMapping(object, rule, endpointObject, relationEndpointMappings, shapeByKey);
  const resolution = endpointAttributeResolution(endpointObject, ref.className, ref.attrName, shapeByKey);
  if (resolution.status === 'ambiguous') {
    issues.push({
      level: 'error',
      code: 'endpoint_attribute_ambiguous',
      pageShapeKey: object.pageShapeKey,
      endpointPageShapeKey: endpointObject.pageShapeKey,
      candidatePageShapeKeys: resolution.candidates.map((candidate) => candidate.pageShapeKey),
      className,
      attribute: attr.name,
      sourceRole,
      sourceClass: ref.className,
      sourceAttribute: ref.attrName,
      message: 'Внутри endpoint-группы найдено несколько подходящих источников атрибута. Выберите более точную привязку или исправьте связь в Visio.'
    });
    return;
  }
  if (attr.mandatory && resolution.status === 'missing') {
    issues.push({
      level: 'error',
      code: 'endpoint_attribute_missing',
      pageShapeKey: object.pageShapeKey,
      endpointPageShapeKey: endpointObject.pageShapeKey,
      className,
      attribute: attr.name,
      sourceRole,
      sourceClass: ref.className,
      sourceAttribute: ref.attrName,
      message: 'Для обязательного атрибута связи не найдено значение на endpoint-объекте или внутри его группы.'
    });
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
  return objectForEndpoint(shapeByKey, object, shapeId, role);
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
    const endpointObject = objectForEndpoint(shapeByKey, object, endpointShapeId, sourceRole);
    const ref = sourceAttributeRefFromRelationMapping(object, rule, endpointObject, relationEndpointMappings, shapeByKey);
    if (!endpointObject || !ref.className || !ref.attrName) return undefined;
    const resolution = endpointAttributeResolution(endpointObject, ref.className, ref.attrName, shapeByKey);
    return resolution.status === 'ambiguous' ? undefined : resolution.value;
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
  const endpointObject = objectForEndpoint(shapeByKey, object, endpointShapeId, sourceRole);
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
    type: attr.type || '',
    attributeType: attr.type || '',
    validation: attr.validation || '',
    mandatory: Boolean(attr.mandatory),
    inherited: Boolean(attr.inherited),
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
    const ref = sourceAttributeRefFromRelationMapping(object, rule, endpointObject, relationEndpointMappings, shapeByKey);
    const resolution = endpointAttributeResolution(endpointObject, ref.className, ref.attrName, shapeByKey);
    return {
      ...trace,
      endpoint,
      sourcePageShapeKey: resolution.sourceObject && resolution.sourceObject.pageShapeKey || endpoint.pageShapeKey,
      sourceClass: ref.className,
      sourceAttribute: ref.attrName,
      sourceResolution: resolution.status,
      candidatePageShapeKeys: resolution.candidates.map((candidate) => candidate.pageShapeKey)
    };
  }
  if (sourceRole === 'constant') return { ...trace, sourceAttribute: '' };
  if (sourceRole === 'override') return { ...trace, overrideAttribute: rule.overrideAttribute || rule.targetAttribute || attr.name || '' };
  return trace;
}

function objectPayloadForClass(object, className, mapping, shapeByKey, relationEndpointMappings, contractParams = [], classAttributeCatalog = {}) {
  const values = valueByRowName(object);
  const payload = {};
  const attributeSources = [];
  const attrByName = mergeClassAttributeCatalog(mapping, className, classAttributeCatalog[className] || []);
  const ruleByAttribute = new Map(mappingAttributeRules(mapping, className).map((rule) => [rule.targetAttribute, rule]));
  for (const attrItem of attrByName.values()) {
    const rule = ruleByAttribute.get(attrItem.name) || normalizeAttributeSourceRule(attrItem.sourceRule || {}, className, attrItem.name);
    const attr = attrByName.get(rule.targetAttribute) || attrItem || { name: rule.targetAttribute };
    if (!attr.name) continue;
    const value = payloadValueFromRule(object, className, attr, rule, shapeByKey, relationEndpointMappings, contractParams);
    if (typeof value !== 'undefined') payload[attr.name] = value;
    attributeSources.push(attributeSourceTrace(object, className, attr, rule, shapeByKey, value, relationEndpointMappings));
  }
  const name = values.template_Name || values.CMDB_Name || object.objectType || `${className} ${object.pageShapeKey}`;
  if (!payload.Code) payload.Code = safeBusinessCode(`${className}-${object.page}-${object.shapeId}`);
  if (!payload.Description) payload.Description = String(name || payload.Code).slice(0, 250);
  for (const source of attributeSources) {
    const attrName = source && source.targetAttribute || '';
    if (!attrName || !Object.prototype.hasOwnProperty.call(payload, attrName)) continue;
    source.valuePresent = typeof payload[attrName] !== 'undefined' && String(payload[attrName] || '').trim() !== '';
  }
  for (const systemAttr of [
    { name: 'Code', description: 'Code', type: 'string' },
    { name: 'Description', description: 'Description', type: 'string' }
  ]) {
    if (attributeSources.some((source) => source.targetAttribute === systemAttr.name)) continue;
    const value = payload[systemAttr.name];
    attributeSources.unshift({
      targetClass: className,
      targetAttribute: systemAttr.name,
      type: systemAttr.type,
      attributeType: systemAttr.type,
      mandatory: true,
      inherited: true,
      description: systemAttr.description,
      sourceRole: 'system',
      sourceAttribute: systemAttr.name,
      expression: '',
      sourcePageShapeKey: object.pageShapeKey,
      valuePresent: typeof value !== 'undefined' && String(value || '').trim() !== ''
    });
  }
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

function normalizeCreateClassValueRules(value) {
  const rows = Array.isArray(value)
    ? value
    : Object.entries(value && typeof value === 'object' ? value : {}).map(([key, ruleValue]) => {
      const parts = String(key || '').split('::');
      return { className: parts[0] || '', attribute: parts[1] || '', value: ruleValue };
    });
  const result = [];
  const seen = new Set();
  for (const row of rows) {
    const className = String(row && (row.className || row.targetClass) || '').trim();
    const attribute = String(row && (row.attribute || row.targetAttribute) || '').trim();
    const ruleValue = String(row && row.value || '').trim();
    if (!className || !attribute || !ruleValue) continue;
    const key = `${className}::${attribute}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push({ className, attribute, value: ruleValue });
  }
  return result.sort((a, b) =>
    String(a.className).localeCompare(String(b.className)) ||
    String(a.attribute).localeCompare(String(b.attribute))
  );
}

function sourceRuleFromCreateClassValueRule(row) {
  const value = String(row && row.value || '').trim();
  const base = {
    targetClass: row.className,
    targetAttribute: row.attribute,
    sourceAttribute: '',
    constantValue: '',
    defaultValue: '',
    overrideAttribute: ''
  };
  if (hasExpression(value)) {
    return {
      ...base,
      sourceRole: 'self',
      sourceAttribute: value,
      mode: 'copy'
    };
  }
  return {
    ...base,
    sourceRole: 'constant',
    constantValue: value,
    mode: 'constant'
  };
}

function applyCreateClassValueRulesToRules(rules, classValueRules) {
  const normalizedRules = normalizeCreateClassValueRules(classValueRules);
  if (!normalizedRules.length) return { rules, changed: false, applied: [] };
  const byIdentity = new Map(normalizedRules.map((row) => [`${row.className}::${row.attribute}`, row]));
  let changed = false;
  const knownMappings = (Array.isArray(rules.knownMappings) ? rules.knownMappings : []).map((mapping) => {
    const next = mappingWithNormalizedRules(mapping);
    const attrRules = new Map((next.attributeRules || []).map((rule) => [attributeRuleIdentity(rule), rule]));
    for (const className of next.classes || []) {
      const rowsForClass = normalizedRules.filter((row) => row.className === className);
      if (!rowsForClass.length) continue;
      const attrs = Array.isArray(next.attributesByClass[className]) ? next.attributesByClass[className] : [];
      const attrNames = new Set(attrs.map((attr) => attr && attr.name).filter(Boolean));
      for (const row of rowsForClass) {
        if (attrNames.has(row.attribute)) continue;
        attrs.push({
          name: row.attribute,
          description: row.attribute,
          type: row.attribute === 'Code' || row.attribute === 'Description' ? 'string' : '',
          mandatory: row.attribute === 'Code' || row.attribute === 'Description',
          inherited: row.attribute === 'Code' || row.attribute === 'Description'
        });
        attrNames.add(row.attribute);
        changed = true;
      }
      next.attributesByClass[className] = attrs.map((attr) => {
        if (!attr || !attr.name) return attr;
        const row = byIdentity.get(`${className}::${attr.name}`);
        if (!row) return attr;
        const sourceRule = sourceRuleFromCreateClassValueRule(row);
        const existingRule = normalizeAttributeSourceRule(attr.sourceRule || {}, className, attr.name);
        if (attributeRuleSignature(existingRule) !== attributeRuleSignature(sourceRule)) changed = true;
        attrRules.set(attributeRuleIdentity(sourceRule), sourceRule);
        return { ...attr, sourceRule };
      });
    }
    next.attributeRules = sortedAttributeRules(attrRules.values());
    return next;
  });
  return {
    rules: { ...rules, knownMappings },
    changed,
    applied: normalizedRules
  };
}

function normalizeCmdbAttributeItem(item = {}) {
  const metadata = item.metadata && typeof item.metadata === 'object' ? item.metadata : {};
  const validation =
    item.validationRule || item.validationRules || item.validation || item.validator || item.validators ||
    item.validationScript || item.validationCode || item.jsValidation || item.javascriptValidation ||
    metadata.validationRule || metadata.validationRules || metadata.validation || metadata.validator || metadata.validators ||
    metadata.validationScript || metadata.validationCode || metadata.jsValidation || metadata.javascriptValidation || '';
  return {
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
    validation: typeof validation === 'string' ? validation : JSON.stringify(validation || ''),
    rawSource: {
      lookupType: String(item.lookupType || item.lookup || item.lookupName || item._lookupType || ''),
      targetClass: String(item.targetClass || item.target || item.referenceClass || item.destination || ''),
      domain: String(item.domain || item.domainName || item._domain || ''),
      validation
    }
  };
}

function valueIsPresent(value) {
  return typeof value !== 'undefined' && value !== null && String(value).trim() !== '';
}

function planPayloadValue(payload, attrName) {
  if (!payload || !attrName) return undefined;
  if (Object.prototype.hasOwnProperty.call(payload, attrName)) return payload[attrName];
  const foundKey = Object.keys(payload).find((key) => key.toLowerCase() === String(attrName).toLowerCase());
  return foundKey ? payload[foundKey] : undefined;
}

function extractValidationText(validation) {
  if (!validation) return '';
  if (typeof validation === 'string') return validation;
  if (typeof validation === 'object') {
    return String(validation.script || validation.js || validation.expression || validation.value || validation.rule || JSON.stringify(validation));
  }
  return String(validation || '');
}

function parseRequiredWhenValidation(validationText, fallbackAttribute) {
  const text = String(validationText || '').replace(/\s+/g, ' ').trim();
  if (!text) return null;
  const portMatch = text.match(/([A-Za-z_][A-Za-z0-9_]*)[^\n;{}]{0,120}(?:TCP|UDP)[^\n;{}]{0,180}([A-Za-z_][A-Za-z0-9_]*)/i);
  const requiredMatch = text.match(/(?:isEmpty|isBlank|isNull|!|===\s*['"]{2}|==\s*['"]{2})[^\n;{}]{0,120}([A-Za-z_][A-Za-z0-9_]*)/i);
  if (/TCP/i.test(text) && /UDP/i.test(text) && /port/i.test(text)) {
    return {
      triggerAttribute: portMatch && !/port/i.test(portMatch[1]) ? portMatch[1] : 'Protocol',
      triggerValues: ['TCP', 'UDP'],
      requiredAttribute: /dport|destination.*port/i.test(text) ? 'dport' : fallbackAttribute,
      message: 'Для TCP/UDP должен быть заполнен destination port.'
    };
  }
  if (requiredMatch) {
    return {
      triggerAttribute: '',
      triggerValues: [],
      requiredAttribute: fallbackAttribute,
      message: 'Атрибут не прошел CMDBuild validation.'
    };
  }
  return null;
}

function validatePlanWithCmdbRules(plan, classAttributeCatalog = {}) {
  const issues = [];
  for (const item of plan && plan.objects || []) {
    const attrs = classAttributeCatalog[item.className] || [];
    for (const attr of attrs) {
      const validationText = extractValidationText(attr.validation);
      if (!validationText.trim()) continue;
      const parsed = parseRequiredWhenValidation(validationText, attr.name);
      if (!parsed) {
        issues.push({
          level: 'warning',
          code: 'cmdb_validation_not_supported',
          pageShapeKey: item.pageShapeKey,
          className: item.className,
          attribute: attr.name,
          message: 'У атрибута есть CMDBuild validation JS, но автоматическая проверка этого выражения пока не поддерживается.'
        });
        continue;
      }
      const triggerValue = parsed.triggerAttribute ? planPayloadValue(item.payload, parsed.triggerAttribute) : '';
      const triggered = parsed.triggerValues.length
        ? parsed.triggerValues.some((value) => String(triggerValue || '').toUpperCase() === value)
        : true;
      if (!triggered) continue;
      const requiredValue = planPayloadValue(item.payload, parsed.requiredAttribute);
      if (!valueIsPresent(requiredValue)) {
        issues.push({
          level: 'error',
          code: 'cmdb_validation_failed',
          pageShapeKey: item.pageShapeKey,
          className: item.className,
          attribute: parsed.requiredAttribute,
          sourceAttribute: parsed.triggerAttribute,
          message: parsed.message || 'План не проходит CMDBuild validation.'
        });
      }
    }
  }
  return issues;
}

async function loadClassAttributeCatalog(authToken, classNames = []) {
  const result = {};
  for (const className of Array.from(new Set((classNames || []).map((item) => String(item || '').trim()).filter(Boolean))).sort()) {
    const response = await cmdbuildRequest(`/cmdbuild/services/rest/v3/classes/${encodeURIComponent(className)}/attributes?limit=500&detailed=true`, authToken);
    result[className] = response.ok && Array.isArray(response.json && response.json.data)
      ? response.json.data.map(normalizeCmdbAttributeItem).filter((item) => item.name && item.active !== false && !item.hidden && item.writable !== false)
      : [];
  }
  return result;
}

async function persistContractRulesVersion(authToken, currentVersion, rules, createdBy = '') {
  if (!currentVersion || (!currentVersion.contractId && !currentVersion.contractCode)) {
    throw new Error('Contract version is required to save class-level fill rules.');
  }
  const versionsResult = await listConversionContractVersions(authToken);
  const allVersions = versionsResult.success ? versionsResult.data : [];
  const resolvedContract = {
    id: currentVersion.contractId || '',
    code: currentVersion.contractCode || ''
  };
  const contractVersions = contractVersionsFor(allVersions, resolvedContract);
  const versionNumber = nextVersionNumber(contractVersions);
  const created = await createConversionContractVersion(authToken, {
    contractId: resolvedContract.id,
    contractCode: resolvedContract.code,
    code: `${resolvedContract.code || 'contract'}-v${versionNumber}`,
    version: versionNumber,
    status: 'Active',
    rulesJson: JSON.stringify(rules, null, 2),
    createdBy
  });
  if (!created.success) throw new Error(created.message || 'Failed to create contract version.');
  return created.data;
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

function applyCreateOverrides(payloadPlan, overrides, planIndex, object, className, shapeByKey, contractParams) {
  if (!overrides || !overrides.size) return payloadPlan;
  const payload = { ...payloadPlan.payload };
  const attributeSources = payloadPlan.attributeSources.map((source) => {
    const attrName = source.targetAttribute || '';
    const overrideValue = createOverrideValue(overrides, planIndex, object, className, attrName);
    if (typeof overrideValue === 'undefined') return source;
    const resolvedOverride = hasExpression(overrideValue)
      ? evaluateExpression(overrideValue, { object, className, attr: { name: attrName }, rule: {}, shapeByKey, contractParams })
      : overrideValue;
    payload[attrName] = resolvedOverride;
    return {
      ...source,
      sourceRole: 'ui_override',
      sourceAttribute: String(overrideValue || ''),
      sourcePageShapeKey: object.pageShapeKey,
      expression: hasExpression(overrideValue) ? String(overrideValue || '') : '',
      valuePresent: typeof resolvedOverride !== 'undefined' && String(resolvedOverride || '').trim() !== ''
    };
  });
  return { payload, attributeSources };
}

function buildCreationPlan(verification, valueOverrides = new Map(), classAttributeCatalog = {}) {
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
      const rawPayloadPlan = objectPayloadForClass(object, className, mapping, shapeByKey, relationEndpointMappings, contractParams, classAttributeCatalog);
      const payloadPlan = applyCreateOverrides(rawPayloadPlan, valueOverrides, planIndex, object, className, shapeByKey, contractParams);
      const missingAttributes = payloadPlan.attributeSources.filter((source) => source.mandatory && !source.valuePresent).map((source) => ({
        className: source.targetClass,
        attribute: source.targetAttribute,
        description: source.description || '',
        sourceRole: source.sourceRole || '',
        sourceAttribute: source.sourceAttribute || '',
        expression: source.expression || '',
        pageShapeKey: source.sourcePageShapeKey || object.pageShapeKey,
        planIndex
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

function normalizeCreateSelection(input = {}) {
  const raw = input && typeof input === 'object' && !Array.isArray(input) ? input : {};
  const mode = raw.mode === 'objects' ? 'objects' : 'classes';
  const classes = new Set((Array.isArray(raw.classes) ? raw.classes : []).map((item) => String(item || '').trim()).filter(Boolean));
  const planIndexes = new Set((Array.isArray(raw.planIndexes) ? raw.planIndexes : [])
    .map((item) => Number.parseInt(String(item), 10))
    .filter(Number.isFinite));
  return { mode, classes, planIndexes, explicit: Boolean(raw.explicit) };
}

function selectedPlanIndexSet(plan, selection) {
  const objects = plan && Array.isArray(plan.objects) ? plan.objects : [];
  const normalized = normalizeCreateSelection(selection);
  const result = new Set();
  if (!objects.length) return result;
  if (normalized.mode === 'objects') {
    if (!normalized.planIndexes.size && !normalized.explicit) {
      objects.forEach((_, index) => result.add(index));
    } else {
      normalized.planIndexes.forEach((index) => {
        if (index >= 0 && index < objects.length) result.add(index);
      });
    }
    return result;
  }
  if (!normalized.classes.size && !normalized.explicit) {
    objects.forEach((_, index) => result.add(index));
  } else {
    objects.forEach((object, index) => {
      if (normalized.classes.has(String(object.className || ''))) result.add(index);
    });
  }
  return result;
}

function filterPlanForSelection(plan, selection) {
  const selected = selectedPlanIndexSet(plan, selection);
  const objects = [];
  const indexMap = new Map();
  (plan.objects || []).forEach((object, index) => {
    if (!selected.has(index)) return;
    indexMap.set(index, objects.length);
    objects.push(object);
  });
  return {
    ...plan,
    objects,
    selectedOriginalPlanIndexes: Array.from(selected).sort((left, right) => left - right),
    missingAttributes: (plan.missingAttributes || [])
      .filter((missing) => selected.has(Number(missing.planIndex)))
      .map((missing) => ({
        ...missing,
        originalPlanIndex: missing.planIndex,
        planIndex: indexMap.has(Number(missing.planIndex)) ? indexMap.get(Number(missing.planIndex)) : missing.planIndex
      }))
  };
}

function filterIssuesForSelectedPlan(issues = [], selectedPlan = {}) {
  const selectedObjects = selectedPlan.objects || [];
  const selectedPairs = new Set(selectedObjects.map((object) => `${object.pageShapeKey || ''}::${object.className || ''}`));
  const selectedShapes = new Set(selectedObjects.map((object) => object.pageShapeKey || '').filter(Boolean));
  const selectedClasses = new Set(selectedObjects.map((object) => object.className || '').filter(Boolean));
  return issues.filter((issue) => {
    if (!issue) return false;
    if (Number.isFinite(Number(issue.planIndex))) return Number(issue.planIndex) >= 0 && Number(issue.planIndex) < selectedObjects.length;
    const pageShapeKey = String(issue.pageShapeKey || '');
    const className = String(issue.className || '');
    if (!pageShapeKey && !className) return true;
    if (pageShapeKey && className) return selectedPairs.has(`${pageShapeKey}::${className}`);
    if (pageShapeKey) return selectedShapes.has(pageShapeKey);
    return selectedClasses.has(className);
  });
}

function planObjectMatchesIssue(object = {}, index, issue = {}) {
  if (!issue || issue.level !== 'error') return false;
  const rawPlanIndex = issue.planIndex;
  if (rawPlanIndex !== undefined && rawPlanIndex !== null && String(rawPlanIndex).trim() !== '' && Number.isFinite(Number(rawPlanIndex))) {
    return Number(rawPlanIndex) === index;
  }
  const pageShapeKey = String(issue.pageShapeKey || '');
  const className = String(issue.className || '');
  if (!pageShapeKey && !className) return true;
  if (pageShapeKey && pageShapeKey !== String(object.pageShapeKey || '')) return false;
  if (className && className !== String(object.className || '')) return false;
  return true;
}

function filterReadyPlanForExternalVerification(plan = {}, issues = []) {
  const objects = Array.isArray(plan.objects) ? plan.objects : [];
  const blockingIssues = Array.isArray(issues) ? issues.filter((issue) => issue && issue.level === 'error') : [];
  const readyObjects = [];
  const excludedObjects = [];
  const indexMap = new Map();
  objects.forEach((object, index) => {
    const objectMissing = Array.isArray(object.missingAttributes) ? object.missingAttributes : [];
    const objectIssues = blockingIssues.filter((issue) => planObjectMatchesIssue(object, index, issue));
    if (objectMissing.length || objectIssues.length) {
      excludedObjects.push({
        planIndex: index,
        pageShapeKey: object.pageShapeKey || '',
        className: object.className || '',
        missingAttributes: objectMissing.length,
        blockingIssues: objectIssues.map((issue) => ({
          code: issue.code || '',
          message: issue.message || ''
        }))
      });
      return;
    }
    indexMap.set(index, readyObjects.length);
    readyObjects.push(object);
  });
  return {
    objects: readyObjects,
    skipped: plan.skipped || [],
    missingAttributes: (plan.missingAttributes || [])
      .filter((missing) => indexMap.has(Number(missing.planIndex)))
      .map((missing) => ({
        ...missing,
        originalPlanIndex: missing.planIndex,
        planIndex: indexMap.get(Number(missing.planIndex))
      })),
    readiness: {
      sourceObjects: objects.length,
      readyObjects: readyObjects.length,
      excludedObjects: excludedObjects.length,
      excluded: excludedObjects
    }
  };
}

function buildVerificationInputContractSchema(contractVersion = {}, plan = {}) {
  const rules = parseRulesJson(contractVersion && contractVersion.rulesJson);
  const classes = new Map();
  for (const object of plan.objects || []) {
    const className = object.className || '';
    if (!className) continue;
    if (!classes.has(className)) classes.set(className, new Map());
    const attrMap = classes.get(className);
    for (const source of object.attributeSources || []) {
      const attrName = source.targetAttribute || '';
      if (!attrName || attrMap.has(attrName)) continue;
      attrMap.set(attrName, {
        name: attrName,
        description: source.description || attrName,
        type: source.type || source.attributeType || '',
        mandatory: Boolean(source.mandatory),
        inherited: Boolean(source.inherited),
        sourceRole: source.sourceRole || '',
        sourceAttribute: source.sourceAttribute || ''
      });
    }
  }
  return {
    kind: 'BAAVerificationInputContract',
    schemaVersion: '1',
    baaContractVersion: publicContractVersion(contractVersion),
    classes: Array.from(classes.entries()).sort((a, b) => a[0].localeCompare(b[0])).map(([name, attrs]) => ({
      name,
      attributes: Array.from(attrs.values()).sort((a, b) => String(a.name).localeCompare(String(b.name)))
    })),
    relations: (plan.objects || []).filter((item) => item.kind === 'context').map((item, index) => ({
      planIndex: index,
      className: item.className || '',
      pageShapeKey: item.pageShapeKey || '',
      sourceClass: item.endpoints && item.endpoints.source && (item.endpoints.source.cmdbClasses || [])[0] || '',
      destinationClass: item.endpoints && item.endpoints.destination && (item.endpoints.destination.cmdbClasses || [])[0] || '',
      relationBindingStatus: item.relationBindingStatus || ''
    })),
    contractParams: normalizeContractParams(rules.contractParams || [])
  };
}

function buildVerificationOutputContractSchema(contractVersion = {}) {
  return {
    kind: 'BAAVerificationOutputContract',
    schemaVersion: '2',
    baaContractVersion: publicContractVersion(contractVersion),
    response: {
      success: { type: 'boolean', mandatory: true },
      status: { type: 'string', mandatory: false, allowed: ['completed', 'error', 'failed', 'passed'] },
      title: { type: 'string', mandatory: false },
      message: { type: 'string', mandatory: false },
      summary: { type: 'object', mandatory: false },
      items: {
        type: 'array',
        mandatory: false,
        item: {
          level: { type: 'string', mandatory: true, allowed: ['error', 'warning', 'info'] },
          code: { type: 'string', mandatory: true },
          message: { type: 'string', mandatory: true },
          planIndex: { type: 'number', mandatory: false },
          className: { type: 'string', mandatory: false },
          attribute: { type: 'string', mandatory: false },
          pageShapeKey: { type: 'string', mandatory: false },
          data: { type: 'object', mandatory: false }
        }
      },
      tables: {
        type: 'array',
        mandatory: false,
        item: {
          code: { type: 'string', mandatory: true },
          title: { type: 'string', mandatory: false },
          columns: { type: 'array', mandatory: true },
          rows: { type: 'array', mandatory: true }
        }
      },
      data: { type: 'object', mandatory: false }
    }
  };
}

function buildVerificationPayload(plan = {}, inputContract = {}, endpoint = {}, params = {}, contractParams = []) {
  return {
    source: 'CMDB BAA',
    inputContract: {
      code: inputContract.code || '',
      version: inputContract.version || '',
      checksum: inputContract.schemaChecksum || ''
    },
    contractParams: normalizeContractParams(contractParams),
    endpoint: {
      code: endpoint.code || '',
      params
    },
    plan: {
      objects: (plan.objects || []).map((item, index) => ({
        planIndex: index,
        kind: item.kind || 'object',
        className: item.className || '',
        pageShapeKey: item.pageShapeKey || '',
        mappingKey: item.mappingKey || '',
        relationBindingStatus: item.relationBindingStatus || '',
        endpoints: item.endpoints || null,
        payload: item.payload || {},
        attributeSources: item.attributeSources || []
      })),
      missingAttributes: plan.missingAttributes || [],
      skipped: plan.skipped || []
    }
  };
}

function validateVerificationOutput(value) {
  const issues = [];
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return [{ level: 'error', code: 'verification_output_not_object', message: 'Ответ внешней верификации должен быть JSON object.' }];
  }
  if (typeof value.success !== 'boolean') issues.push({ level: 'error', code: 'verification_output_missing_success', message: 'В ответе внешней верификации нет boolean поля success.' });
  if (!Array.isArray(value.items) && !Array.isArray(value.tables)) issues.push({ level: 'error', code: 'verification_output_missing_result', message: 'В ответе внешней верификации должен быть массив items или tables.' });
  (Array.isArray(value.items) ? value.items : []).forEach((item, index) => {
    if (!item || typeof item !== 'object') {
      issues.push({ level: 'error', code: 'verification_output_item_invalid', message: `items[${index}] должен быть объектом.` });
      return;
    }
    if (!['error', 'warning', 'info'].includes(String(item.level || ''))) issues.push({ level: 'error', code: 'verification_output_item_level_invalid', message: `items[${index}].level должен быть error/warning/info.` });
    if (!String(item.code || '').trim()) issues.push({ level: 'error', code: 'verification_output_item_code_missing', message: `items[${index}].code обязателен.` });
    if (!String(item.message || '').trim()) issues.push({ level: 'error', code: 'verification_output_item_message_missing', message: `items[${index}].message обязателен.` });
  });
  (Array.isArray(value.tables) ? value.tables : []).forEach((table, index) => {
    if (!table || typeof table !== 'object' || Array.isArray(table)) {
      issues.push({ level: 'error', code: 'verification_output_table_invalid', message: `tables[${index}] должен быть объектом.` });
      return;
    }
    if (!String(table.code || '').trim()) issues.push({ level: 'error', code: 'verification_output_table_code_missing', message: `tables[${index}].code обязателен.` });
    if (!Array.isArray(table.columns)) issues.push({ level: 'error', code: 'verification_output_table_columns_missing', message: `tables[${index}].columns должен быть array.` });
    if (!Array.isArray(table.rows)) issues.push({ level: 'error', code: 'verification_output_table_rows_missing', message: `tables[${index}].rows должен быть array.` });
    (Array.isArray(table.columns) ? table.columns : []).forEach((column, columnIndex) => {
      if (!column || typeof column !== 'object' || Array.isArray(column) || !String(column.name || '').trim()) {
        issues.push({ level: 'error', code: 'verification_output_table_column_invalid', message: `tables[${index}].columns[${columnIndex}].name обязателен.` });
      }
    });
    (Array.isArray(table.rows) ? table.rows : []).forEach((row, rowIndex) => {
      if (!row || typeof row !== 'object' || Array.isArray(row)) {
        issues.push({ level: 'error', code: 'verification_output_table_row_invalid', message: `tables[${index}].rows[${rowIndex}] должен быть объектом.` });
      }
    });
  });
  return issues;
}

function resolveParamsObject(paramsJson = '{}', context = {}) {
  let params;
  try {
    params = JSON.parse(String(paramsJson || '{}'));
  } catch {
    params = {};
  }
  const replacer = (value) => {
    if (typeof value === 'string') {
      return value.replace(/\$\{contractparam\.([^}]+)\}/g, (_, name) => contractParamValue(context.contractParams || [], name))
        .replace(/\$\{session\.username\}/g, context.username || '')
        .replace(/\$\{session\.requestId\}/g, context.requestId || '');
    }
    if (Array.isArray(value)) return value.map(replacer);
    if (value && typeof value === 'object') {
      const next = {};
      for (const [key, item] of Object.entries(value)) next[key] = replacer(item);
      return next;
    }
    return value;
  };
  return replacer(params);
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
  const requestedVersionId = String(input.contractVersionId || '').trim();
  const requestedVersionCode = String(input.contractVersionCode || '').trim();
  const version = (versionsResult.data || []).find((item) =>
    (requestedVersionId && item.id === requestedVersionId) ||
    (requestedVersionCode && item.code === requestedVersionCode) ||
    (!requestedVersionId && !requestedVersionCode && metadata.contractVersionId && item.id === metadata.contractVersionId) ||
    (!requestedVersionId && !requestedVersionCode && metadata.contractVersionCode && item.code === metadata.contractVersionCode)
  ) || null;
  if (!version && (metadata.contractVersionId || metadata.contractVersionCode)) {
    issues.push({ level: 'error', code: 'contract_version_not_found', message: 'Версия контракта из VSDX не найдена в CMDBuild.' });
  }
  const versionOverridden = Boolean(version && ((requestedVersionId && requestedVersionId !== metadata.contractVersionId) || (requestedVersionCode && requestedVersionCode !== metadata.contractVersionCode)));
  if (versionOverridden) {
    issues.push({ level: 'warning', code: 'contract_version_overridden', message: 'Для планирования используется версия контракта из текущей сессии; VSDX еще ссылается на предыдущую версию. Сохраните шаблон, чтобы зафиксировать новую версию в файле.' });
  }
  if (!versionOverridden && version && metadata.contractVersionChecksum && version.rulesChecksum && metadata.contractVersionChecksum !== version.rulesChecksum) {
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
  const requestedVersionId = String(input.contractVersionId || '').trim();
  const requestedVersionCode = String(input.contractVersionCode || '').trim();
  const version = (versionsResult.data || []).find((item) =>
    (requestedVersionId && item.id === requestedVersionId) ||
    (requestedVersionCode && item.code === requestedVersionCode) ||
    (!requestedVersionId && !requestedVersionCode && metadata.contractVersionId && item.id === metadata.contractVersionId) ||
    (!requestedVersionId && !requestedVersionCode && metadata.contractVersionCode && item.code === metadata.contractVersionCode)
  ) || null;
  if (!version && (metadata.contractVersionId || metadata.contractVersionCode)) {
    issues.push({ level: 'error', code: 'contract_version_not_found', message: 'Версия контракта из VSDX не найдена в CMDBuild.' });
  }
  const versionOverridden = Boolean(version && ((requestedVersionId && requestedVersionId !== metadata.contractVersionId) || (requestedVersionCode && requestedVersionCode !== metadata.contractVersionCode)));
  if (versionOverridden) {
    issues.push({ level: 'warning', code: 'contract_version_overridden', message: 'Для планирования используется версия контракта из текущей сессии; VSDX еще ссылается на предыдущую версию. Сохраните шаблон, чтобы зафиксировать новую версию в файле.' });
  }
  if (!versionOverridden && version && metadata.contractVersionChecksum && version.rulesChecksum && metadata.contractVersionChecksum !== version.rulesChecksum) {
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
  if (execute) {
    const checksumText = String(input.checksumText || '').trim();
    if (!checksumText) {
      return {
        success: false,
        executed: false,
        message: 'Создание невозможно: не загружен файл контрольной суммы.',
        verification: { metadata: {}, contractVersion: null, summary: {}, issues: [{ level: 'error', code: 'missing_checksum_file', message: 'Перед созданием объектов загрузите файл контрольной суммы.' }] },
        plan: { objects: [], skipped: [], missingAttributes: [] },
        results: [],
        canExecute: false,
        summary: { planned: 0, skipped: 0, missing: 0, blockingIssues: 1, created: 0, failed: 0 }
      };
    }
    const checksum = verifyChecksum(Buffer.from(String(input.fileBase64 || ''), 'base64'), checksumText);
    if (!checksum.ok) {
      return {
        success: false,
        executed: false,
        message: checksum.message || 'Создание невозможно: контрольная сумма не проверена.',
        checksum,
        verification: { metadata: {}, contractVersion: null, summary: {}, issues: [{ level: 'error', code: 'checksum_invalid', message: checksum.message || 'Контрольная сумма не проверена.' }] },
        plan: { objects: [], skipped: [], missingAttributes: [] },
        results: [],
        canExecute: false,
        summary: { planned: 0, skipped: 0, missing: 0, blockingIssues: 1, created: 0, failed: 0 }
      };
    }
  }
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
  let contractRulesUpdate = { changed: false, applied: [] };
  if (input.saveClassValueRules || input.classValueRules) {
    const currentRules = parseRulesJson(technical.contractVersion && technical.contractVersion.rulesJson);
    contractRulesUpdate = applyCreateClassValueRulesToRules(currentRules, input.classValueRules || []);
    if (contractRulesUpdate.changed) {
      const savedVersion = input.saveClassValueRules
        ? await persistContractRulesVersion(authToken, technical.contractVersion, contractRulesUpdate.rules, input.createdBy || '')
        : { ...technical.contractVersion, rulesJson: JSON.stringify(contractRulesUpdate.rules, null, 2) };
      technical.contractVersion = {
        ...technical.contractVersion,
        ...savedVersion,
        rulesJson: savedVersion.rulesJson || JSON.stringify(contractRulesUpdate.rules, null, 2)
      };
    }
  }
  const planClassNames = Array.from(new Set((technical.objects || []).flatMap((object) => object.cmdbClasses || [])));
  const classAttributeCatalog = await loadClassAttributeCatalog(authToken, planClassNames);
  const fullPlan = buildCreationPlan(technical, valueOverrides, classAttributeCatalog);
  const plan = filterPlanForSelection(fullPlan, input.createSelection || {});
  const businessIssues = await verifyBaaTemplate(authToken, input);
  const settings = input.settings && typeof input.settings === 'object' && !Array.isArray(input.settings) ? input.settings : {};
  const checkCmdbValidators = settings.checkCmdbValidatorsInSystem !== false;
  const cmdbValidationIssues = checkCmdbValidators ? validatePlanWithCmdbRules(plan, classAttributeCatalog) : [];
  const valueCompletenessCodes = new Set(['mandatory_attribute_empty', 'expression_value_empty', 'constant_value_empty']);
  const planMissingIssues = (plan.missingAttributes || []).map((missing) => ({
    level: 'error',
    code: 'plan_mandatory_attribute_empty',
    pageShapeKey: missing.pageShapeKey || '',
    className: missing.className || '',
    attribute: missing.attribute || '',
    sourceRole: missing.sourceRole || '',
    sourceAttribute: missing.sourceAttribute || '',
    expression: missing.expression || '',
    planIndex: missing.planIndex,
    message: 'В плане создания не заполнен обязательный атрибут.'
  }));
  const createIssues = filterIssuesForSelectedPlan((businessIssues.issues || [])
    .filter((issue) => !valueCompletenessCodes.has(issue.code))
    .concat(planMissingIssues, cmdbValidationIssues), plan);
  const blockingIssues = createIssues.filter((issue) => issue.level === 'error');
  if (!plan.objects.length) {
    return {
      success: false,
      executed: false,
      message: 'Создание невозможно: по VSDX не сформирован ни один объект.',
      verification: {
        metadata: technical.metadata,
        contractVersion: publicContractVersion(technical.contractVersion),
        summary: technical.summary,
        issues: createIssues
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
        issues: createIssues
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
  const canExecute = !blockingIssues.length;
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
    success: execute ? results.every((item) => item.success) : canExecute,
    executed: execute,
    verification: {
      metadata: technical.metadata,
      contractVersion: publicContractVersion(technical.contractVersion),
      summary: technical.summary,
      issues: createIssues
    },
    contractRulesUpdate,
    plan,
    classAttributeCatalog,
    results,
    canExecute,
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

async function preparedVerificationContext(authToken, input = {}) {
  const technical = await technicalTemplateContext(authToken, input);
  if (!technical.success) {
    return { success: false, technical, plan: { objects: [], skipped: [], missingAttributes: [] }, message: 'VSDX не прошел техническую проверку.' };
  }
  const planClassNames = Array.from(new Set((technical.objects || []).flatMap((object) => object.cmdbClasses || [])));
  const classAttributeCatalog = await loadClassAttributeCatalog(authToken, planClassNames);
  const fullPlan = buildCreationPlan(technical, normalizeCreateValueOverrides(input.valueOverrides), classAttributeCatalog);
  const businessIssues = await verifyBaaTemplate(authToken, input);
  const valueCompletenessCodes = new Set(['mandatory_attribute_empty', 'expression_value_empty', 'constant_value_empty']);
  const blockingIssues = (businessIssues.issues || []).filter((issue) =>
    issue.level === 'error' && !valueCompletenessCodes.has(issue.code)
  );
  const plan = filterReadyPlanForExternalVerification(fullPlan, blockingIssues);
  return { success: true, technical, fullPlan, plan, classAttributeCatalog, readiness: plan.readiness };
}

async function generateVerificationContracts(authToken, input = {}) {
  const context = await preparedVerificationContext(authToken, input);
  if (!context.success) return context;
  const inputSchema = buildVerificationInputContractSchema(context.technical.contractVersion, context.plan);
  const outputSchema = buildVerificationOutputContractSchema(context.technical.contractVersion);
  return {
    success: true,
    contractVersion: publicContractVersion(context.technical.contractVersion),
    inputContract: inputSchema,
    inputChecksum: digestHex('sha256', Buffer.from(JSON.stringify(inputSchema, null, 2), 'utf8')),
    outputContract: outputSchema,
    outputChecksum: digestHex('sha256', Buffer.from(JSON.stringify(outputSchema, null, 2), 'utf8')),
    summary: {
      classes: inputSchema.classes.length,
      relations: inputSchema.relations.length,
      objects: context.plan.objects.length,
      sourceObjects: context.readiness && context.readiness.sourceObjects || context.plan.objects.length,
      excludedObjects: context.readiness && context.readiness.excludedObjects || 0
    }
  };
}

async function publishVerificationContracts(authToken, input = {}) {
  const settings = input.settings && typeof input.settings === 'object' && !Array.isArray(input.settings) ? input.settings : {};
  const classes = verificationClassNames(settings);
  const generated = await generateVerificationContracts(authToken, input);
  if (!generated.success) return generated;
  const version = generated.contractVersion || {};
  const suffix = version.code || version.id || 'contract';
  const contractNumber = String(input.verificationContractVersion || '1').trim() || '1';
  const createdBy = String(input.createdBy || '').trim();
  const inputCreated = await createVerificationContract(authToken, classes.input, {
    code: input.inputCode || `${suffix}-verification-input-v${contractNumber}`,
    description: input.inputDescription || `${suffix} verification input v${contractNumber}`,
    baaContractVersionId: version.id || '',
    baaContractVersionCode: version.code || '',
    version: contractNumber,
    status: input.status || 'Active',
    schemaJson: JSON.stringify(generated.inputContract, null, 2),
    createdBy
  });
  const outputCreated = await createVerificationContract(authToken, classes.output, {
    code: input.outputCode || `${suffix}-verification-output-v${contractNumber}`,
    description: input.outputDescription || `${suffix} verification output v${contractNumber}`,
    baaContractVersionId: version.id || '',
    baaContractVersionCode: version.code || '',
    version: contractNumber,
    status: input.status || 'Active',
    schemaJson: JSON.stringify(generated.outputContract, null, 2),
    createdBy
  });
  return {
    success: Boolean(inputCreated.success && outputCreated.success),
    generated,
    input: inputCreated,
    output: outputCreated,
    classes
  };
}

async function runExternalVerification(authToken, input = {}) {
  const settings = input.settings && typeof input.settings === 'object' && !Array.isArray(input.settings) ? input.settings : {};
  const classes = verificationClassNames(settings);
  const endpointClass = classes.endpoint;
  let endpoint = input.endpoint && typeof input.endpoint === 'object' && !Array.isArray(input.endpoint) ? input.endpoint : null;
  if (!endpoint || !endpoint.endpointUrl) {
    const endpoints = await listVerificationEndpoints(authToken, endpointClass);
    if (!endpoints.success) return { success: false, message: endpoints.message, endpointClass };
    const endpointCode = String(input.endpointCode || '').trim();
    endpoint = (endpoints.data || []).find((item) => endpointCode ? item.code === endpointCode : item.status === 'Active') || null;
  }
  if (!endpoint || !endpoint.endpointUrl) {
    return { success: false, message: 'Verification endpoint is not configured.', endpointClass };
  }
  if (endpoint.status && endpoint.status !== 'Active') {
    return { success: false, message: `Verification endpoint is not Active: ${endpoint.code || ''} / ${endpoint.status}`, endpoint };
  }
  const context = await preparedVerificationContext(authToken, input);
  if (!context.success) return context;
  const inputCode = endpoint.inputContractCode || input.inputContractCode || '';
  const inputVersion = endpoint.inputContractVersion || input.inputContractVersion || '';
  const outputCode = endpoint.outputContractCode || input.outputContractCode || '';
  const outputVersion = endpoint.outputContractVersion || input.outputContractVersion || '';
  const inputContract = await resolveVerificationContractSelection(authToken, settings, 'input', inputCode, inputVersion);
  if (!inputContract.success) return { success: false, message: inputContract.message, inputContract };
  const outputContract = await resolveVerificationContractSelection(authToken, settings, 'output', outputCode, outputVersion);
  if (!outputContract.success) return { success: false, message: outputContract.message, outputContract };
  const inputIssues = validatePlanAgainstInputContract(context.plan, inputContract.schema);
  if (inputIssues.some((issue) => issue.level === 'error')) {
    return {
      success: false,
      message: 'Current plan does not match selected input contract.',
      endpoint,
      inputContract: inputContract.contract,
      outputContract: outputContract.contract,
      items: inputIssues,
      summary: {
        errors: inputIssues.filter((item) => item.level === 'error').length,
        warnings: inputIssues.filter((item) => item.level === 'warning').length,
        infos: inputIssues.filter((item) => item.level === 'info').length
      }
    };
  }
  const rules = parseRulesJson(context.technical.contractVersion && context.technical.contractVersion.rulesJson);
  const params = resolveParamsObject(endpoint.paramsJson || input.paramsJson || '{}', {
    contractParams: normalizeContractParams(rules.contractParams || []),
    username: input.createdBy || '',
    requestId: crypto.randomUUID ? crypto.randomUUID() : String(Date.now())
  });
  const contractParams = normalizeContractParams(rules.contractParams || []);
  const payload = buildVerificationPayload(context.plan, {
    code: inputContract.contract.code || '',
    version: inputContract.contract.version || '',
    schemaChecksum: inputContract.contract.schemaChecksum || ''
  }, endpoint, params, contractParams);
  const response = await postVerificationEndpoint(endpoint.endpointUrl, authToken, payload);
  const outputIssues = validateVerificationOutputByContract(response.json, outputContract.schema);
  const interpretation = interpretVerificationTables(response.json, parseResultInterpretationJson(endpoint.resultInterpretationJson || input.resultInterpretationJson || '{}'));
  const externalItems = response.json && Array.isArray(response.json.items) ? response.json.items : [];
  const items = outputIssues.concat(interpretation.items || []).concat(externalItems.map((item) => ({
    level: item.level || 'info',
    code: item.code || '',
    message: item.message || '',
    planIndex: item.planIndex,
    className: item.className || '',
    attribute: item.attribute || '',
    pageShapeKey: item.pageShapeKey || '',
    data: item.data || null
  })));
  return {
    success: response.ok && !outputIssues.some((issue) => issue.level === 'error') && interpretation.status !== 'failed' && interpretation.status !== 'technical_error',
    endpoint,
    inputContract: inputContract.contract,
    outputContract: outputContract.contract,
    interpretation,
    requestPayload: payload,
    response: response.json,
    cmdbcustompageStatus: response.statusCode,
    items,
    summary: {
      errors: items.filter((item) => item.level === 'error').length,
      warnings: items.filter((item) => item.level === 'warning').length,
      infos: items.filter((item) => item.level === 'info').length
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
          inherited: Boolean(attr.inherited),
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
    inherited: Boolean(attr && attr.inherited),
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

function conversionSchemaReadiness(schema) {
  const root = schema && schema.root ? schema.root : DEFAULT_SCHEMA_ROOT;
  const requiredClassNames = new Set([
    root,
    'BAAConversionContract',
    'BAAConversionContractVersion'
  ]);
  const requiredDataClassNames = new Set([
    'BAAConversionContract',
    'BAAConversionContractVersion'
  ]);
  const classByName = new Map((Array.isArray(schema && schema.classes) ? schema.classes : [])
    .map((item) => [item.name, item]));
  const missing = [];
  for (const name of requiredClassNames) {
    const classResult = classByName.get(name);
    if (!classResult || !classResult.exists) {
      missing.push({ type: 'class', name });
    }
  }
  for (const name of requiredDataClassNames) {
    const classResult = classByName.get(name);
    for (const attribute of Array.isArray(classResult && classResult.attributes) ? classResult.attributes : []) {
      if (!attribute.exists) {
        missing.push({
          type: 'attribute',
          className: name,
          name: attribute.name
        });
      }
    }
  }
  const conflicts = (Array.isArray(schema && schema.conflicts) ? schema.conflicts : [])
    .filter((item) => requiredClassNames.has(item.name) || requiredClassNames.has(item.className));
  const errors = (Array.isArray(schema && schema.errors) ? schema.errors : [])
    .filter((item) => {
      const issueName = item.name || item.className || '';
      if (item.type === 'parent' && issueName === root && classByName.get(root)?.exists) {
        return false;
      }
      return requiredClassNames.has(issueName);
    });
  return {
    ready: !missing.length && !conflicts.length && !errors.length,
    missing,
    conflicts,
    errors
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

async function postVerificationEndpoint(endpointUrl, authToken, payload) {
  const raw = String(endpointUrl || '').trim();
  if (!raw) throw new Error('Verification endpoint URL is required.');
  const target = raw.startsWith('http://') || raw.startsWith('https://')
    ? new URL(raw)
    : new URL(raw, CMDBUILD_ORIGIN);
  const body = JSON.stringify(payload);
  return await new Promise((resolve) => {
    const headers = {
      accept: 'application/json',
      'content-type': 'application/json',
      'content-length': Buffer.byteLength(body),
      'CMDBuild-Authorization': authToken
    };
    const request = http.request({
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port,
      method: 'POST',
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
        } catch {}
        resolve({ ok: response.statusCode >= 200 && response.statusCode < 300, statusCode: response.statusCode, json, text });
      });
    });
    request.on('error', (error) => resolve({ ok: false, statusCode: 0, json: null, text: '', error: error.message }));
    request.write(body);
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
  if (section === 'prepare-verification' || section === 'verification-rules' || section === 'verification-prepare') return 'prepare-verification';
  if (section === 'verify' || section === 'verification') return 'verify';
  if (section === 'prepare-objects' || section === 'prepare-object' || section === 'plan-objects' || section === 'objects-plan') return 'prepare-objects';
  if (section === 'create-objects' || section === 'create' || section === 'objects') return 'create-objects';
  if (section === 'help' || section === 'docs') return 'help';
  if (section === 'about' || section === 'about-program') return 'about';
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
    .type-table tr.error-row td{background:#fff7f5;color:var(--danger)}.type-table tr.warning-row td{background:#fffaf0}.class-assignment.error-block{border-color:#f0b8b0}.class-assignment.error-block>summary{background:#fff7f5;color:var(--danger)}.mix-warning{display:inline-block;margin-left:6px;color:#8a5a00;font-weight:bold}.expr-suggest{position:absolute;z-index:10000;min-width:260px;max-width:520px;max-height:240px;overflow:auto;border:1px solid #9fb3c8;background:#fff;box-shadow:0 8px 18px rgba(15,23,42,.16);font-size:12px}.expr-suggest button{display:block;width:100%;border:0;border-radius:0;background:#fff;text-align:left;padding:6px 8px}.expr-suggest button.active,.expr-suggest button:hover{background:var(--accent-soft);color:#07575b}.expr-suggest .muted{display:block;font-size:11px}
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
        <button class="primary" type="button" data-action="choose-shared-vsdx">Загрузить шаблон/схему</button>
        <button type="button" data-action="choose-checksum">Загрузить файл контрольной суммы</button>
        <button type="button" data-action="save-contract">Сохранить контракт</button>
        <button type="button" data-action="save-template">Сохранить шаблон</button>
        <span id="shared-file-status" class="file-name">Файл не выбран</span>
        <span id="checksum-status" class="checksum-status error">Контрольная сумма не проверялась</span>
        <span id="contract-version-status" class="file-name">Версия не выбрана</span>
        <span id="plan-readiness-status" class="checksum-status">План не строился</span>
        <input id="shared-vsdx-file" class="file-input" type="file" accept=".vsdx,.sum,.sha,.sha1,.sha2,.sha3,.sha256,.sha512" multiple>
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
      <a href="${UI_PREFIX}/prepare-objects" data-section="prepare-objects">Подготовить объекты</a>
      <a href="${UI_PREFIX}/prepare-verification" data-section="prepare-verification">Подготовить правила верификации</a>
      <a href="${UI_PREFIX}/verify" data-section="verify">Верификация</a>
      <a href="${UI_PREFIX}/create-objects" data-section="create-objects">Создать объекты</a>
      <a href="${UI_PREFIX}/help" data-section="help">Помощь</a>
      <div class="nav-group bottom">
        <div class="nav-title">Настройки</div>
        <a class="child" href="${UI_PREFIX}/settings" data-section="settings">Общие</a>
        <a class="child" href="${UI_PREFIX}/types" data-section="types">Типы</a>
        <a class="child" href="${UI_PREFIX}/schema" data-section="schema">Схема</a>
      </div>
      <a href="${UI_PREFIX}/about" data-section="about">О программе</a>
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
  var currentSection = boot.section || 'prepare-template';
  var labels = {
    schema: 'Схема',
    contracts: 'Контракты',
    settings: 'Общие',
    types: 'Типы',
    'prepare-template': 'Подготовить шаблон',
    'check-template': 'Проверить шаблон',
    'prepare-objects': 'Подготовить объекты',
    'prepare-verification': 'Подготовить правила верификации',
    verify: 'Верификация',
    'create-objects': 'Создать объекты',
    help: 'Помощь',
    about: 'О программе'
  };
  var defaultSettings = {
    checksumExtension: 'sha256',
    verifyChecksumOnPrepare: true,
    checkCmdbValidatorsInSystem: true,
    referenceFixedListLimit: 50,
    verificationInputContractClass: 'BAAVerificationInputContract',
    verificationOutputContractClass: 'BAAVerificationOutputContract',
    verificationEndpointClass: 'BAAVerificationEndpoint'
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
    versions: [],
    verificationInputs: [],
    verificationOutputs: [],
    verificationEndpoints: []
  };
  function readSettings() {
    var settings = Object.assign({}, defaultSettings);
    try {
      var raw = window.localStorage && window.localStorage.getItem('cmdbaa.settings');
      if (raw) settings = Object.assign(settings, JSON.parse(raw));
    } catch (error) {}
    settings.checksumExtension = String(settings.checksumExtension || 'sha256').trim().replace(/^\\.+/, '') || 'sha256';
    settings.verifyChecksumOnPrepare = settings.verifyChecksumOnPrepare !== false;
    settings.checkCmdbValidatorsInSystem = settings.checkCmdbValidatorsInSystem !== false;
    settings.referenceFixedListLimit = Math.max(1, Number.parseInt(String(settings.referenceFixedListLimit || '50'), 10) || 50);
    settings.verificationInputContractClass = String(settings.verificationInputContractClass || 'BAAVerificationInputContract').trim() || 'BAAVerificationInputContract';
    settings.verificationOutputContractClass = String(settings.verificationOutputContractClass || 'BAAVerificationOutputContract').trim() || 'BAAVerificationOutputContract';
    settings.verificationEndpointClass = String(settings.verificationEndpointClass || 'BAAVerificationEndpoint').trim() || 'BAAVerificationEndpoint';
    return settings;
  }
  function writeSettings(settings) {
    var next = Object.assign({}, defaultSettings, settings || {});
    next.checksumExtension = String(next.checksumExtension || 'sha256').trim().replace(/^\\.+/, '') || 'sha256';
    next.verifyChecksumOnPrepare = next.verifyChecksumOnPrepare !== false;
    next.checkCmdbValidatorsInSystem = next.checkCmdbValidatorsInSystem !== false;
    next.referenceFixedListLimit = Math.max(1, Number.parseInt(String(next.referenceFixedListLimit || '50'), 10) || 50);
    next.verificationInputContractClass = String(next.verificationInputContractClass || 'BAAVerificationInputContract').trim() || 'BAAVerificationInputContract';
    next.verificationOutputContractClass = String(next.verificationOutputContractClass || 'BAAVerificationOutputContract').trim() || 'BAAVerificationOutputContract';
    next.verificationEndpointClass = String(next.verificationEndpointClass || 'BAAVerificationEndpoint').trim() || 'BAAVerificationEndpoint';
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
    currentSection = section || 'prepare-template';
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
      '</div><p class="muted">Будут проверены и созданы классы BAA, BAAConversionContract, BAAConversionContractVersion, BAAVerificationInputContract, BAAVerificationOutputContract и BAAVerificationEndpoint.</p></section>',
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
      '<label>Класс input contracts<input id="settings-verification-input-class" value="' + escapeHtml(settings.verificationInputContractClass) + '"></label>',
      '<label>Класс output contracts<input id="settings-verification-output-class" value="' + escapeHtml(settings.verificationOutputContractClass) + '"></label>',
      '<label>Класс endpoint definitions<input id="settings-verification-endpoint-class" value="' + escapeHtml(settings.verificationEndpointClass) + '"></label>',
      '<label class="check-label"><input id="settings-verify-checksum" type="checkbox"' + (settings.verifyChecksumOnPrepare ? ' checked' : '') + '>Проверять контрольную сумму при подготовке шаблона</label>',
      '<label class="check-label"><input id="settings-check-cmdb-validators" type="checkbox"' + (settings.checkCmdbValidatorsInSystem ? ' checked' : '') + '>Проверить валидатором CMDB внутри системы</label>',
      '<div class="notice">Если проверка валидаторов CMDB дает ошибки в тестовой модели, отключите эту настройку. При отключении поля с CMDB validation будут подсвечены красным в дозаполнении.</div>',
      '</div></section>',
      '<section class="section"><h3>Результат</h3><pre id="status">Настройки загружены.</pre></section>'
    ].join('');
  }
  function renderAbout() {
    app.innerHTML = [
      '<section class="section"><h2>О программе</h2>',
      '<p>Спроектировано и овеществлено Игорем Ляпиным email:igor.lyapin@gmail.com 2026</p>',
      '<p>Под лицензией GNU GPLv3.</p>',
      '</section>'
    ].join('');
  }
  function renderHelp() {
    app.innerHTML = [
      '<section class="section"><h2>Помощь</h2>',
      '<p>CMDB BAA подготавливает VSDX-шаблон, проверяет его и строит план создания объектов CMDBuild.</p>',
      '<h3>Основные блоки</h3>',
      '<ul><li><strong>Контракты</strong> - объект договора конвертации и его версии.</li><li><strong>Подготовить шаблон</strong> - назначение классов, атрибутов, параметров и правил связи.</li><li><strong>Проверить шаблон</strong> - техническая проверка BAA metadata.</li><li><strong>Подготовить объекты</strong> - dry-run план и дозаполнение.</li><li><strong>Подготовить правила верификации</strong> - endpoint, contracts, params и интерпретация результата.</li><li><strong>Верификация</strong> - запуск сохраненного endpoint для бизнес-проверки.</li><li><strong>Создать объекты</strong> - запись подготовленного плана в CMDB.</li></ul>',
      '<h3>Контракт</h3>',
      '<p>Контракт хранит правила распознавания Visio-типов, маппинг классов и атрибутов, параметры контракта и правила связи. Пользователь выбирает контракт, версии создаются автоматически при расширении правил.</p>',
      '<h3>Объект маппинга</h3>',
      '<p>Для обычной фигуры объект маппинга - сама фигура. Для линии объект маппинга состоит из <span class="type-key">source</span>, <span class="type-key">destination</span> и <span class="type-key">relation</span>. Это не произвольные объекты схемы, а роли текущей связи.</p>',
      '<h3>Выражения</h3>',
      '<div class="type-key">$' + '{visioparam.name}<br>$' + '{source.visioparam.name}<br>$' + '{destination.visioparam.name}<br>$' + '{relation.visioparam.name}<br>$' + '{contractparam.name}</div>',
      '<p>В полях дозаполнения начните вводить <span class="type-key">$</span> или <span class="type-key">$' + '{visi</span>, чтобы открыть подсказки. Для <span class="type-key">Code</span> и <span class="type-key">Description</span> подсказки работают как конструктор строки по текущему объекту маппинга, например <span class="type-key">$' + '{source.visioparam.ipaddress}-$' + '{destination.visioparam.ipaddress}</span>.</p>',
      '<h3>Висящие связи</h3>',
      '<p>BAA не удаляет неполные связи молча. Связи со статусом <span class="type-key">partial</span> или <span class="type-key">unbound</span> показываются в проверках и блокируют создание, если по ним нельзя собрать обязательные значения.</p>',
      '<h3>Внешняя верификация</h3>',
      '<p>BAA публикует input/output contracts в CMDBuild, администратор cmdbcustompages реализует endpoint под эти contracts, правила сохраняются в <strong>Подготовить правила верификации</strong>, затем endpoint вызывается из меню <strong>Верификация</strong>.</p>',
      '<h3>Документация</h3>',
      '<p>Подробная пользовательская помощь: <span class="type-key">docs/user-help.md</span>. Verification contracts: <span class="type-key">docs/verification-contracts.md</span>. Инструкция администратора: <span class="type-key">docs/admin-guide.md</span>. Архитектурные артефакты: <span class="type-key">docs/architecture/</span>.</p>',
      '</section>'
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
  function verificationContractsWorkspaceHtml() {
    var settings = readSettings();
    return [
      '<section class="section"><div class="toolbar"><h3>Контракты верификации</h3><button type="button" data-action="generate-verification-contracts">Сформировать по готовым объектам</button><button class="primary" type="button" data-action="publish-verification-contracts">Опубликовать готовые объекты в CMDBuild</button></div>',
      '<p class="muted">BAA формирует input/output contracts только по объектам плана, которые технически готовы к созданию: обязательные значения заполнены, а по объекту нет блокирующих ошибок. Логика проверки реализуется заранее в cmdbcustompages.</p>',
      '<div class="grid">',
      '<label>Версия verification contracts<input id="verification-contract-version" value="1"></label>',
      '<label>Input class<input value="' + escapeHtml(settings.verificationInputContractClass) + '" disabled></label>',
      '<label>Output class<input value="' + escapeHtml(settings.verificationOutputContractClass) + '" disabled></label>',
      '</div><div id="verification-contract-status" class="notice">Контракты верификации еще не формировались.</div></section>',
      '<section class="section"><div class="toolbar"><h3>Опубликованные input/output contracts</h3><button type="button" data-action="reload-verification-contracts">Обновить</button></div><div class="grid"><div><h4>Input contracts</h4><div id="verification-input-contracts-list" class="notice">Список еще не загружался.</div></div><div><h4>Output contracts</h4><div id="verification-output-contracts-list" class="notice">Список еще не загружался.</div></div></div></section>'
    ].join('');
  }
  function verificationContractsTableHtml(items) {
    if (!items || !items.length) return '<div class="notice">Контракты еще не опубликованы.</div>';
    return '<div class="table-wrap"><table class="type-table"><thead><tr><th>Код</th><th>Версия</th><th>Статус</th><th>BAA version</th><th>Checksum</th></tr></thead><tbody>' +
      items.map(function (item) {
        var rowClass = item.status === 'Active' ? '' : item.status === 'Archived' ? ' class="warning-row"' : '';
        return '<tr' + rowClass + '><td><strong>' + escapeHtml(item.code || '') + '</strong></td><td>' + escapeHtml(item.version || '') + '</td><td>' + escapeHtml(item.status || '') + '</td><td>' + escapeHtml(item.baaContractVersionCode || '') + '</td><td class="type-key">' + escapeHtml(item.schemaChecksum || '') + '</td></tr>';
      }).join('') + '</tbody></table></div>';
  }
  function verificationContractOptionsHtml(items) {
    if (!items || !items.length) return '<option value="">Нет опубликованных контрактов</option>';
    return items.map(function (item) {
      var label = item.code + ' / ' + item.version + ' / ' + item.status;
      return '<option value="' + escapeHtml(item.code || '') + '"' +
        ' data-code="' + escapeHtml(item.code || '') + '"' +
        ' data-version="' + escapeHtml(item.version || '') + '"' +
        ' data-status="' + escapeHtml(item.status || '') + '"' +
        ' data-checksum="' + escapeHtml(item.schemaChecksum || '') + '">' + escapeHtml(label) + '</option>';
    }).join('');
  }
  function verificationEndpointOptionsHtml(items) {
    if (!items || !items.length) return '<option value="">Нет сохраненных endpoint</option>';
    return items.map(function (item) {
      var label = item.code + ' / ' + item.status + ' / ' + item.endpointUrl;
      return '<option value="' + escapeHtml(item.code || '') + '"' +
        ' data-code="' + escapeHtml(item.code || '') + '"' +
        ' data-url="' + escapeHtml(item.endpointUrl || '') + '"' +
        ' data-method="' + escapeHtml(item.method || 'POST') + '"' +
        ' data-input-code="' + escapeHtml(item.inputContractCode || '') + '"' +
        ' data-input-version="' + escapeHtml(item.inputContractVersion || '') + '"' +
        ' data-output-code="' + escapeHtml(item.outputContractCode || '') + '"' +
        ' data-output-version="' + escapeHtml(item.outputContractVersion || '') + '"' +
        ' data-params-json="' + escapeHtml(item.paramsJson || '{}') + '"' +
        ' data-result-interpretation-json="' + escapeHtml(item.resultInterpretationJson || '{}') + '"' +
        ' data-status="' + escapeHtml(item.status || '') + '">' + escapeHtml(label) + '</option>';
    }).join('');
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
	        (prepareState.contractVersionCode && version.code === prepareState.contractVersionCode) ||
	        (prepareState.contractMetadata && prepareState.contractMetadata.contractVersionCode && version.code === prepareState.contractMetadata.contractVersionCode);
    }).sort(function (left, right) {
      return Number(right.version || 0) - Number(left.version || 0);
    });
	    if (versions.length) {
	      prepareState.contractVersionId = versions[0].id || '';
	      prepareState.contractVersionCode = versions[0].code || '';
      prepareState.contractId = versions[0].contractId || prepareState.contractId || '';
      prepareState.contractCode = versions[0].contractCode || prepareState.contractCode || '';
      applyContractRulesFromVersion(versions[0], false);
	    }
    updatePrepareContractVersionSummary();
  }
  function updatePrepareContractVersionSummary() {
    var target = document.getElementById('contract-version-status');
    if (!target) return;
    var contract = selectedPrepareContract();
    var version = selectedPrepareContractVersion();
    var fileVersionCode = prepareState.contractMetadata && (prepareState.contractMetadata.contractVersionCode || prepareState.contractMetadata.contractVersionId) || '';
    var currentVersionCode = version && (version.code || version.id) || prepareState.contractVersionCode || prepareState.contractVersionId || '';
    var currentContractCode = version && version.contractCode || prepareState.contractCode || '';
    var versionNumber = version && version.version || '';
    var versionLabel = currentVersionCode
      ? [currentContractCode, versionNumber ? ('v' + versionNumber) : '', currentVersionCode].filter(Boolean).join(' / ')
      : '';
    if (currentVersionCode && fileVersionCode && currentVersionCode !== fileVersionCode) {
      target.className = 'checksum-status error';
      target.textContent = 'Версия CMDB: ' + versionLabel + '. В VSDX: ' + fileVersionCode + '. Сохраните шаблон, чтобы записать новую версию в файл.';
      return;
    }
    if (version) {
      target.className = 'checksum-status ok';
      target.textContent = 'Версия: ' + version.contractCode + ' / v' + version.version + ' / ' + version.code;
      return;
    }
    if (fileVersionCode) {
      target.className = 'checksum-status';
      target.textContent = 'Версия из VSDX: ' + fileVersionCode + '. Загружаю данные контракта из CMDB.';
      return;
    }
    if (contract && (contract.code || contract.id)) {
      target.className = 'checksum-status';
      target.textContent = 'Контракт выбран: ' + (contract.code || contract.id) + '. Версия будет создана при обогащении.';
      return;
    }
    target.className = 'checksum-status error';
    target.textContent = 'Версия не выбрана';
  }
  function updatePlanReadinessStatus(value) {
    var target = document.getElementById('plan-readiness-status');
    if (!target) return;
    if (!value || typeof value.canExecute === 'undefined') {
      target.className = 'checksum-status';
      target.textContent = 'План не строился';
      return;
    }
    var ready = Boolean(value.canExecute);
    var errors = value.summary && value.summary.blockingIssues || 0;
    var missing = value.summary && value.summary.missing || 0;
    target.className = 'checksum-status ' + (ready ? 'ok' : 'error');
    target.textContent = ready ? 'План готов к созданию' : ('План не готов: ошибок ' + errors + ' / не заполнено ' + missing);
  }
  function selectedPrepareContractVersion() {
    var select = document.getElementById('prepare-contract-version');
	    if (!select) {
	      var selected = (contractsState.versions || []).filter(function (version) {
	        return (prepareState.contractVersionId && version.id === prepareState.contractVersionId) ||
	          (prepareState.contractVersionCode && version.code === prepareState.contractVersionCode);
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
	    prepareState.contractVersionCode = option.getAttribute('data-code') || prepareState.contractVersionCode || '';
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
    return '<div class="column-toggles contract-selector"><label>Контракт<select id="prepare-contract">' + options + '</select></label><button type="button" data-action="assign-prepare-contract">Выбрать контракт</button><button type="button" data-action="reload-contracts">Обновить контракты</button></div>';
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
  function updateVerificationContractSelects() {
    var inputSelect = document.getElementById('verification-input-contract');
    var outputSelect = document.getElementById('verification-output-contract');
    if (inputSelect) inputSelect.innerHTML = verificationContractOptionsHtml(contractsState.verificationInputs);
    if (outputSelect) outputSelect.innerHTML = verificationContractOptionsHtml(contractsState.verificationOutputs);
  }
  function updateVerificationEndpointSelect() {
    var endpointSelect = document.getElementById('verification-endpoint-select');
    if (endpointSelect) endpointSelect.innerHTML = verificationEndpointOptionsHtml(contractsState.verificationEndpoints);
  }
  function loadVerificationContracts() {
    var inputTarget = document.getElementById('verification-input-contracts-list');
    var outputTarget = document.getElementById('verification-output-contracts-list');
    if (inputTarget) inputTarget.innerHTML = '<div class="notice">Загружаю input contracts...</div>';
    if (outputTarget) outputTarget.innerHTML = '<div class="notice">Загружаю output contracts...</div>';
    return api('/verification/contracts/list', {
      method: 'POST',
      headers: { Accept: 'application/json', 'content-type': 'application/json' },
      body: JSON.stringify({ settings: readSettings() })
    }).then(function (result) {
      contractsState.verificationInputs = result.response.ok ? (result.json.input && result.json.input.data || []) : [];
      contractsState.verificationOutputs = result.response.ok ? (result.json.output && result.json.output.data || []) : [];
      if (inputTarget) inputTarget.innerHTML = result.response.ok ? verificationContractsTableHtml(contractsState.verificationInputs) : '<div class="notice error">' + escapeHtml(result.json.message || 'Не удалось загрузить input contracts.') + '</div>';
      if (outputTarget) outputTarget.innerHTML = result.response.ok ? verificationContractsTableHtml(contractsState.verificationOutputs) : '<div class="notice error">' + escapeHtml(result.json.message || 'Не удалось загрузить output contracts.') + '</div>';
      updateVerificationContractSelects();
    }).catch(function (error) {
      var text = error && error.message ? error.message : String(error);
      if (inputTarget) inputTarget.innerHTML = '<div class="notice error">' + escapeHtml(text) + '</div>';
      if (outputTarget) outputTarget.innerHTML = '<div class="notice error">' + escapeHtml(text) + '</div>';
    });
  }
  function loadVerificationEndpoints() {
    var target = document.getElementById('verification-endpoints-list');
    if (target) target.innerHTML = '<div class="notice">Загружаю endpoint definitions...</div>';
    return api('/verification/endpoints/list', {
      method: 'POST',
      headers: { Accept: 'application/json', 'content-type': 'application/json' },
      body: JSON.stringify({ settings: readSettings() })
    }).then(function (result) {
      contractsState.verificationEndpoints = result.response.ok ? (result.json.data || []) : [];
      updateVerificationEndpointSelect();
      if (target) target.innerHTML = result.response.ok ? verificationEndpointsTableHtml(contractsState.verificationEndpoints) : '<div class="notice error">' + escapeHtml(result.json.message || 'Не удалось загрузить endpoint definitions.') + '</div>';
    }).catch(function (error) {
      var text = error && error.message ? error.message : String(error);
      if (target) target.innerHTML = '<div class="notice error">' + escapeHtml(text) + '</div>';
    });
  }
  function verificationEndpointsTableHtml(items) {
    if (!items || !items.length) return '<div class="notice">Endpoint definitions еще не созданы.</div>';
    return '<div class="table-wrap"><table class="type-table"><thead><tr><th>Код</th><th>Статус</th><th>URL</th><th>Input</th><th>Output</th><th>Интерпретация</th></tr></thead><tbody>' +
      items.map(function (item) {
        var rowClass = item.status === 'Active' ? '' : item.status === 'Archived' ? ' class="warning-row"' : '';
        var interpretation = {};
        try { interpretation = JSON.parse(item.resultInterpretationJson || '{}'); } catch (error) {}
        return '<tr' + rowClass + '><td><strong>' + escapeHtml(item.code || '') + '</strong></td><td>' + escapeHtml(item.status || '') + '</td><td class="type-key">' + escapeHtml(item.endpointUrl || '') + '</td><td>' + escapeHtml([item.inputContractCode, item.inputContractVersion].filter(Boolean).join(' / ')) + '</td><td>' + escapeHtml([item.outputContractCode, item.outputContractVersion].filter(Boolean).join(' / ')) + '</td><td>' + escapeHtml(interpretation.mode || '') + '</td></tr>';
      }).join('') + '</tbody></table></div>';
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
      verificationContractsWorkspaceHtml(),
      '<section class="section"><h3>Список</h3><div id="contracts-list" class="notice">Контракты еще не загружались.</div></section>',
      '<section class="section"><div class="toolbar"><h3>Версии</h3><button type="button" data-action="reload-contract-versions">Обновить версии</button></div><p class="muted">Версии создаются автоматически при обогащении шаблона, если расширился набор Visio-типов.</p><div id="versions-list" class="notice">Версии еще не загружались.</div></section>'
    ].join('');
    loadContracts().then(loadContractVersions);
    loadVerificationContracts();
    loadCmdbClassesForPrepare();
  }
  function renderPrepare() {
    function tabButton(tab, label) {
      return '<button' + (prepareState.activeTab === tab ? ' class="active"' : '') + ' type="button" data-action="prepare-tab" data-tab="' + tab + '">' + label + '</button>';
    }
    app.innerHTML = [
      '<section class="section"><div class="toolbar"><div class="tabs">' + tabButton('types', 'Типы') + tabButton('shapes', 'Фигуры') + tabButton('enrich', 'Обогатить') + tabButton('relation-map', 'Отразить на связь') + tabButton('contract-params', 'Параметры контракта') + '</div></div><div id="prepare-view" class="notice">Загрузите .vsdx для извлечения типов фигур.</div></section>'
    ].join('');
    updatePrepareContractVersionSummary();
    loadContracts().then(loadContractVersions);
    loadCmdbClassesForPrepare();
    renderChecksumStatus(prepareState.checksum);
    renderPrepareData();
  }
  function verificationInterpretationControlsHtml() {
    var interpretationModes = [
      ['rows_present_is_error', 'строки есть = ошибка'],
      ['rows_absent_is_error', 'строк нет = ошибка'],
      ['rows_present_is_warning', 'строки есть = предупреждение'],
      ['rows_absent_is_warning', 'строк нет = предупреждение'],
      ['manual_review', 'ручной анализ'],
      ['technical_only', 'только технический статус']
    ].map(function (item) {
      return '<option value="' + escapeHtml(item[0]) + '">' + escapeHtml(item[1]) + '</option>';
    }).join('');
    return '<details class="aggregate-summary" open><summary><strong>Интерпретация результата</strong></summary><div class="grid">' +
      '<label>Режим<select id="verification-interpretation-mode">' + interpretationModes + '</select></label>' +
      '<label>Цель<select id="verification-interpretation-scope"><option value="all_tables">Все таблицы</option><option value="table">Таблица по code</option></select></label>' +
      '<label>Table code<input id="verification-interpretation-table-code" placeholder="destination_networks"></label>' +
      '<label>Severity<select id="verification-interpretation-severity"><option value="error">error</option><option value="warning">warning</option><option value="info">info</option></select></label>' +
      '<label>Сообщение если условие сработало<input id="verification-interpretation-message-matched" value="Найдены данные, требующие внимания"></label>' +
      '<label>Сообщение если условие не сработало<input id="verification-interpretation-message-not-matched" value="Данные не найдены"></label>' +
      '<label class="check-label"><input type="checkbox" id="verification-interpretation-show-matched" checked>Показывать таблицы при срабатывании</label>' +
      '<label class="check-label"><input type="checkbox" id="verification-interpretation-show-not-matched">Показывать таблицы если не сработало</label>' +
      '</div></details>';
  }
  function renderPrepareVerification() {
    var settings = readSettings();
    app.innerHTML = [
      '<div class="toolbar"><button class="primary" type="button" data-action="save-verification-endpoint">Сохранить endpoint</button><button type="button" data-action="reload-verification-endpoints">Обновить endpoint</button><button type="button" data-action="check-session">Проверить сессию</button></div>',
      '<section class="section"><h2>Подготовить правила верификации</h2><p class="muted">Здесь сохраняются endpoint definition, input/output contracts, параметры вызова и правило интерпретации найденных данных.</p></section>',
      verificationContractsWorkspaceHtml(),
      '<section class="section"><h3>Endpoint cmdbcustompages</h3><div class="grid">',
      '<label>Сохраненный endpoint<select id="verification-endpoint-select">' + verificationEndpointOptionsHtml(contractsState.verificationEndpoints) + '</select></label>',
      '<label>Код endpoint<input id="verification-endpoint-code" value="default-verification"></label>',
      '<label>URL endpoint<input id="verification-endpoint-url" placeholder="/cmdbuild/custompage/api/verify"></label>',
      '<label>Input contract<select id="verification-input-contract">' + verificationContractOptionsHtml(contractsState.verificationInputs) + '</select></label>',
      '<label>Output contract<select id="verification-output-contract">' + verificationContractOptionsHtml(contractsState.verificationOutputs) + '</select></label>',
      '<label>Статус endpoint<select id="verification-endpoint-status"><option value="Active" selected>Active</option><option value="Draft">Draft</option><option value="Archived">Archived</option></select></label>',
      '<label>Endpoint class<input value="' + escapeHtml(settings.verificationEndpointClass) + '" disabled></label>',
      '</div><label>Params JSON<textarea id="verification-params-json" rows="5">{}</textarea></label><p class="muted">Параметры поддерживают $' + '{contractparam.name}, $' + '{session.username}, $' + '{session.requestId}.</p>',
      verificationInterpretationControlsHtml() + '<div id="verification-endpoints-list" class="notice">Endpoint definitions еще не загружались.</div></section>',
      '<section class="section"><h3>Статус</h3><div id="status" class="notice">Правила верификации еще не сохранялись.</div></section>'
    ].join('');
    loadVerificationContracts();
    loadVerificationEndpoints();
  }
  function renderVerify() {
    app.innerHTML = [
      '<div class="toolbar"><button class="primary" type="button" data-action="run-external-verification">Отправить готовые объекты на верификацию</button><button type="button" data-action="check-session">Проверить сессию</button></div>',
      '<section class="section"><h2>Верификация</h2><p class="muted">Используется общий загруженный файл: ' + escapeHtml(prepareState.fileName || 'файл не выбран') + '.</p><p class="muted">Endpoint, contracts и интерпретация настраиваются в меню "Подготовить правила верификации".</p><div class="grid">',
      '<label>Сохраненный endpoint<select id="verification-endpoint-select">' + verificationEndpointOptionsHtml(contractsState.verificationEndpoints) + '</select></label>',
      '</div></section>',
      '<div id="status" class="notice">Верификация еще не запускалась.</div>'
    ].join('');
    loadVerificationEndpoints();
    if (createState.externalVerification) showVerificationResult(createState.externalVerification, createState.externalVerificationOk);
  }
  function renderCheckTemplate() {
    app.innerHTML = [
      '<div class="toolbar"><button class="primary" type="button" data-action="check-current-template">Проверить шаблон</button><button type="button" data-action="check-session">Проверить сессию</button></div>',
      '<section class="section"><h2>Проверить шаблон</h2><p class="muted">Используется общий загруженный файл: ' + escapeHtml(prepareState.fileName || 'файл не выбран') + '.</p><p class="muted">Техническая проверка файла: наличие версии контракта, объекта контракта, служебных _baa_* полей, назначений template_Class и состояния привязки связей. Бизнес-обязательность атрибутов здесь не проверяется.</p></section>',
      '<section class="section"><h3>Результат</h3><div id="status" class="notice">Проверка еще не запускалась.</div></section>'
    ].join('');
  }
  function renderPrepareObjects() {
    syncCreateFileFromPrepare();
    var fileLine = createState.fileName ? 'Файл: ' + createState.fileName : 'Файл не выбран';
    var hasPlan = Boolean(createState.lastResult && createState.lastResult.plan);
    var mainButton = hasPlan ? 'План объектов' : 'Сформировать план';
    var mainAction = hasPlan ? 'show-create-plan' : 'build-create-plan';
    app.innerHTML = [
      '<div class="toolbar"><button class="primary" type="button" data-action="' + mainAction + '">' + escapeHtml(mainButton) + '</button><button type="button" data-action="fill-create-contract">Дозаполнить через контракт</button><button type="button" data-action="fill-create-manual">Дозаполнить руками</button><button type="button" data-action="rebuild-create-plan">Перестроить план</button><button type="button" data-action="check-session">Проверить сессию</button></div>',
      '<section class="section"><h2>Подготовить объекты</h2><p class="muted">' + escapeHtml(fileLine) + '</p><p class="muted">Сначала строится план. Недостающие обязательные значения можно дозаполнить ниже, перестроить план и затем перейти к созданию объектов.</p></section>',
      '<section class="section"><h3>Результат</h3><div id="status" class="notice">План еще не строился.</div></section>'
    ].join('');
    if (createState.lastResult) showCreateResult(createState.lastResult, createState.lastOk);
  }
  function renderCreateObjects() {
    syncCreateFileFromPrepare();
    if (createState.resultView === 'contract' || createState.resultView === 'manual') createState.resultView = 'plan';
    var hasPlan = Boolean(createState.lastResult && createState.lastResult.plan);
    var checksumOk = Boolean(prepareState.checksumFileName && prepareState.checksumText);
    app.innerHTML = [
      '<div class="toolbar"><button type="button" data-action="check-session">Проверить сессию</button></div>',
      '<section class="section"><h2>Создать объекты</h2><p class="muted">Создание выполняется по последнему подготовленному плану. Исполнитель выбирает полноту запуска: по классам или по конкретным объектам.</p>' + (checksumOk ? '<div class="notice ok">Файл контрольной суммы загружен.</div>' : '<div class="notice error">Файл контрольной суммы не загружен. Объекты не будут созданы.</div>') + createExecutionSelectorHtml() + '</section>',
      '<section class="section"><h3>Результат</h3><div id="status" class="notice">' + (hasPlan ? 'План подготовлен. Для просмотра откройте меню "Подготовить объекты".' : 'Сначала подготовьте план в меню "Подготовить объекты".') + '</div></section>'
    ].join('');
    if (createState.lastResult) showCreateResult(createState.lastResult, createState.lastOk);
  }
  function renderObjectWorkflow() {
    if (currentSection === 'create-objects') renderCreateObjects();
    else renderPrepareObjects();
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
      var rowClass = item.mandatory && !item.valuePresent ? ' class="error-row"' : '';
      return '<tr' + rowClass + '><td>' + escapeHtml([item.targetClass, item.targetAttribute].filter(Boolean).join('.')) + '</td><td>' + escapeHtml(source) + '</td><td>' + escapeHtml(item.sourcePageShapeKey || '') + '</td><td>' + escapeHtml(item.mandatory ? 'да' : '') + '</td><td>' + escapeHtml(item.valuePresent ? 'есть' : 'пусто') + '</td></tr>';
    }).join('') + '</tbody></table></div>';
  }
  function createOverrideKey(item) {
    return String(Number(item.planIndex || 0)) + '::' + String(item.attribute || item.targetAttribute || '');
  }
  function createOverrideInputHtml(key, currentValue, className, attribute, planIndex) {
    var value = Object.prototype.hasOwnProperty.call(createState.valueOverrides, key) ? createState.valueOverrides[key] : '';
    var placeholder = currentValue || '$' + '{visioparam.name}';
    return '<input data-create-override-key="' + escapeHtml(key) + '" data-expression-class="' + escapeHtml(className || '') + '" data-expression-attribute="' + escapeHtml(attribute || '') + '" data-expression-plan-index="' + escapeHtml(typeof planIndex === 'undefined' ? '' : planIndex) + '" value="' + escapeHtml(value) + '" placeholder="' + escapeHtml(placeholder) + '">';
  }
  function createClassRuleInputHtml(key, currentValue, className, attribute) {
    var value = Object.prototype.hasOwnProperty.call(createState.classValueRules, key) ? createState.classValueRules[key] : currentValue || '';
    var placeholder = currentValue || '$' + '{visioparam.name}';
    return '<input data-create-class-rule-key="' + escapeHtml(key) + '" data-expression-class="' + escapeHtml(className || '') + '" data-expression-attribute="' + escapeHtml(attribute || '') + '" value="' + escapeHtml(value) + '" placeholder="' + escapeHtml(placeholder) + '">';
  }
  var expressionSuggestState = {
    input: null,
    token: null,
    items: [],
    activeIndex: 0,
    element: null
  };
  function normalizedVisioExpressionName(name) {
    var value = String(name || '').trim();
    return value.indexOf('template_') === 0 ? value.slice('template_'.length) : value;
  }
  function recognizedContractRuleValue(source) {
    if (!source) return '';
    if (source.expression) return source.expression;
    var role = source.sourceRole || 'self';
    var attribute = normalizedVisioExpressionName(source.overrideAttribute || source.sourceAttribute || source.targetAttribute || '');
    if (!attribute) return '';
    if (role === 'self' || role === 'override') return '$' + '{visioparam.' + attribute + '}';
    if (role === 'source') return '$' + '{source.visioparam.' + attribute + '}';
    if (role === 'destination') return '$' + '{destination.visioparam.' + attribute + '}';
    if (role === 'relation') return '$' + '{relation.visioparam.' + attribute + '}';
    return '';
  }
  function manualOverrideForClassAttribute(objects, className, attribute) {
    var matches = [];
    (objects || []).forEach(function (object, planIndex) {
      if (object.className !== className) return;
      var key = String(planIndex) + '::' + attribute;
      if (!Object.prototype.hasOwnProperty.call(createState.valueOverrides, key)) return;
      var value = createState.valueOverrides[key];
      if (String(value || '').trim()) matches.push({ planIndex: planIndex, value: value });
    });
    return matches;
  }
  function expressionTokenAtCursor(input) {
    var cursor = input && typeof input.selectionStart === 'number' ? input.selectionStart : 0;
    var value = input && input.value || '';
    var start = value.lastIndexOf('$' + '{', cursor);
    if (start === -1) start = value.lastIndexOf('$', cursor);
    if (start === -1) return null;
    var beforeCursor = value.slice(start, cursor);
    if (beforeCursor.indexOf('}') !== -1 || !/^\\$\\{?[A-Za-z0-9_.-]*$/.test(beforeCursor)) return null;
    return {
      start: start,
      end: cursor,
      raw: beforeCursor,
      query: beforeCursor.replace(/^\\$\\{?/, '').toLowerCase()
    };
  }
  function pushExpressionSuggestion(items, seen, value, label, source, className, attribute) {
    value = String(value || '').trim();
    if (!value || seen[value]) return;
    seen[value] = true;
    items.push({ value: value, label: label || value, source: source || '', className: className || '', attribute: attribute || '' });
  }
  function compactExpressionLabel(expression) {
    var text = String(expression || '').replace(/^\\$\\{/, '').replace(/\\}$/, '');
    if (text.indexOf('source.visioparam.') === 0) return 'source: ' + text.slice('source.visioparam.'.length);
    if (text.indexOf('destination.visioparam.') === 0) return 'dest: ' + text.slice('destination.visioparam.'.length);
    if (text.indexOf('relation.visioparam.') === 0) return 'relation: ' + text.slice('relation.visioparam.'.length);
    if (text.indexOf('visioparam.') === 0) return text.slice('visioparam.'.length);
    if (text.indexOf('contractparam.') === 0) return 'contract: ' + text.slice('contractparam.'.length);
    return text;
  }
  function collectExpressionSuggestions(input) {
    var items = [];
    var seen = {};
    var plan = createState.lastResult && createState.lastResult.plan || {};
    var filterClass = input && input.getAttribute('data-expression-class') || '';
    var filterAttribute = input && input.getAttribute('data-expression-attribute') || '';
    var filterPlanIndex = input && input.getAttribute('data-expression-plan-index') || '';
    var constructorMode = filterAttribute === 'Code' || filterAttribute === 'Description';
    (plan.objects || []).forEach(function (object) {
      var objectIndex = String((plan.objects || []).indexOf(object));
      if (filterPlanIndex && objectIndex !== filterPlanIndex) return;
      if (filterClass && object.className !== filterClass) return;
      (object.attributeSources || []).forEach(function (source) {
        var targetAttribute = source.targetAttribute || '';
        if (!constructorMode && filterAttribute && targetAttribute !== filterAttribute) return;
        var attr = normalizedVisioExpressionName(source.sourceAttribute || source.targetAttribute || '');
        var role = source.sourceRole || 'self';
        if (role === 'system' && constructorMode) return;
        if (source.expression) pushExpressionSuggestion(items, seen, source.expression, compactExpressionLabel(source.expression), source.expression, object.className || '', targetAttribute);
        else if (attr && (role === 'source' || role === 'destination' || role === 'relation')) {
          var roleExpression = '$' + '{' + role + '.visioparam.' + attr + '}';
          var roleLabel = role === 'source' ? 'src' : role === 'destination' ? 'dst' : 'rel';
          pushExpressionSuggestion(items, seen, roleExpression, roleLabel + ' ' + attr, roleExpression, object.className || '', targetAttribute);
        } else if (attr) {
          var selfExpression = '$' + '{visioparam.' + attr + '}';
          pushExpressionSuggestion(items, seen, selfExpression, 'self ' + attr, selfExpression, object.className || '', targetAttribute);
        }
      });
    });
    if (!items.length && filterAttribute) {
      var fallbackAttr = normalizedVisioExpressionName(filterAttribute);
      var fallbackExpression = '$' + '{visioparam.' + fallbackAttr + '}';
      pushExpressionSuggestion(items, seen, fallbackExpression, fallbackAttr, fallbackExpression, filterClass, filterAttribute);
    }
    (prepareState.contractParams || []).forEach(function (param) {
      if (param && param.name) {
        var contractExpression = '$' + '{contractparam.' + param.name + '}';
        pushExpressionSuggestion(items, seen, contractExpression, 'contract: ' + param.name, contractExpression);
      }
    });
    return items.sort(function (left, right) { return left.value.localeCompare(right.value); });
  }
  function closeExpressionSuggestions() {
    if (expressionSuggestState.element) expressionSuggestState.element.remove();
    expressionSuggestState.input = null;
    expressionSuggestState.token = null;
    expressionSuggestState.items = [];
    expressionSuggestState.activeIndex = 0;
    expressionSuggestState.element = null;
  }
  function applyExpressionSuggestion(index) {
    var input = expressionSuggestState.input;
    var token = expressionSuggestState.token;
    var item = expressionSuggestState.items[index || 0];
    if (!input || !token || !item) return;
    var value = input.value || '';
    var next = value.slice(0, token.start) + item.value + value.slice(token.end);
    input.value = next;
    var cursor = token.start + item.value.length;
    input.focus();
    input.setSelectionRange(cursor, cursor);
    input.dispatchEvent(new Event('change', { bubbles: true }));
    closeExpressionSuggestions();
  }
  function renderExpressionSuggestions(input) {
    var token = expressionTokenAtCursor(input);
    if (!token) {
      closeExpressionSuggestions();
      return;
    }
    var query = token.query;
    var items = collectExpressionSuggestions(input).filter(function (item) {
      return item.value.toLowerCase().indexOf(query) !== -1 || item.label.toLowerCase().indexOf(query) !== -1;
    }).slice(0, 30);
    if (!items.length) {
      closeExpressionSuggestions();
      return;
    }
    if (expressionSuggestState.element) expressionSuggestState.element.remove();
    var box = document.createElement('div');
    box.className = 'expr-suggest';
    var rect = input.getBoundingClientRect();
    box.style.left = String(window.scrollX + rect.left) + 'px';
    box.style.top = String(window.scrollY + rect.bottom + 4) + 'px';
    items.forEach(function (item, index) {
      var button = document.createElement('button');
      button.type = 'button';
      button.className = index === 0 ? 'active' : '';
      button.setAttribute('data-expression-suggestion-index', String(index));
      button.innerHTML = escapeHtml(item.label) + (item.source ? '<span class="muted">' + escapeHtml(item.source) + '</span>' : '');
      box.appendChild(button);
    });
    document.body.appendChild(box);
    expressionSuggestState.input = input;
    expressionSuggestState.token = token;
    expressionSuggestState.items = items;
    expressionSuggestState.activeIndex = 0;
    expressionSuggestState.element = box;
  }
  function moveExpressionSuggestion(delta) {
    if (!expressionSuggestState.element || !expressionSuggestState.items.length) return;
    expressionSuggestState.activeIndex = (expressionSuggestState.activeIndex + delta + expressionSuggestState.items.length) % expressionSuggestState.items.length;
    Array.prototype.forEach.call(expressionSuggestState.element.querySelectorAll('button'), function (button, index) {
      button.className = index === expressionSuggestState.activeIndex ? 'active' : '';
    });
  }
  function missingAttributesHtml(missing) {
    if (!missing || !missing.length) return '<div class="notice ok">Обязательные атрибуты заполнены.</div>';
    return '<div class="notice"><strong>Есть незаполненные обязательные атрибуты: ' + escapeHtml(missing.length) + '</strong></div><div class="table-wrap"><table class="type-table"><thead><tr><th>План</th><th>Фигура</th><th>Класс</th><th>Атрибут</th><th>Источник</th><th>Дозаполнить</th></tr></thead><tbody>' + missing.map(function (item) {
      var source = item.expression || [item.sourceRole, item.sourceAttribute].filter(Boolean).join(' / ');
      var key = createOverrideKey(item);
      return '<tr class="error-row"><td>' + escapeHtml(Number(item.planIndex || 0) + 1) + '</td><td>' + escapeHtml(item.pageShapeKey || '') + '</td><td>' + escapeHtml(item.className || '') + '</td><td>' + escapeHtml(item.attribute || '') + '</td><td>' + escapeHtml(source) + '</td><td>' + createOverrideInputHtml(key, '', item.className || '', item.attribute || '', Number(item.planIndex || 0)) + '</td></tr>';
    }).join('') + '</tbody></table></div>';
  }
  function createManualPlanEditHtml(plan) {
    var settings = readSettings();
    var objects = plan && plan.objects || [];
    if (objects.length && (createState.selectedPlanIndex < 0 || createState.selectedPlanIndex >= objects.length)) createState.selectedPlanIndex = 0;
    var selector = '<label>Объект плана<select id="create-selected-plan-index">' + objects.map(function (object, index) {
      return '<option value="' + escapeHtml(index) + '"' + (index === createState.selectedPlanIndex ? ' selected' : '') + '>' + escapeHtml(String(index + 1) + '. ' + (object.className || '') + ' / ' + (object.pageShapeKey || '')) + '</option>';
    }).join('') + '</select></label>';
    var rows = [];
    objects.forEach(function (object, planIndex) {
      if (planIndex !== createState.selectedPlanIndex) return;
      (object.attributeSources || []).forEach(function (source) {
        var attribute = source.targetAttribute || '';
        if (!attribute) return;
        var key = String(planIndex) + '::' + attribute;
        var currentValue = object.payload && Object.prototype.hasOwnProperty.call(object.payload, attribute) ? object.payload[attribute] : '';
        var sourceText = source.expression || [source.sourceRole, source.sourceClass && source.sourceAttribute ? source.sourceClass + '.' + source.sourceAttribute : source.sourceAttribute].filter(Boolean).join(' / ');
        var validationWarning = !settings.checkCmdbValidatorsInSystem && source.validation ? '<div class="notice error">Поле валидируется внутри CMDB. Локальная проверка отключена.</div>' : '';
        var overrideValue = Object.prototype.hasOwnProperty.call(createState.valueOverrides, key) ? createState.valueOverrides[key] : '';
        var rowClass = source.mandatory && !String(currentValue || '').trim() && !String(overrideValue || '').trim() ? ' class="error-row"' : '';
        rows.push('<tr' + rowClass + '><td>' + escapeHtml(planIndex + 1) + '</td><td>' + escapeHtml(object.pageShapeKey || '') + '</td><td>' + escapeHtml(object.className || '') + '</td><td>' + validationWarning + escapeHtml(attribute) + '</td><td>' + escapeHtml(sourceText) + '</td><td>' + escapeHtml(currentValue || '') + '</td><td>' + createOverrideInputHtml(key, currentValue, object.className || '', attribute, planIndex) + '</td></tr>');
      });
    });
    if (!rows.length) return '<div class="notice">Нет атрибутов для редактирования.</div>';
    var hint = 'константы или выражения ' + '$' + '{visioparam.*}, ' + '$' + '{source.visioparam.*}, ' + '$' + '{destination.visioparam.*}, ' + '$' + '{contractparam.*}';
    return '<details class="object-row" open><summary><strong>Дозаполнить руками</strong> <span class="muted">' + escapeHtml(hint) + '</span></summary><div class="toolbar compact-toolbar">' + selector + '</div><div class="table-wrap"><table class="type-table"><thead><tr><th>План</th><th>Фигура</th><th>Класс</th><th>Атрибут</th><th>Источник</th><th>Текущее значение</th><th>Переопределить</th></tr></thead><tbody>' + rows.join('') + '</tbody></table></div></details>';
  }
  function createContractRuleEditHtml(plan) {
    var settings = readSettings();
    var objects = plan && plan.objects || [];
    var byKey = {};
    objects.forEach(function (object) {
      (object.attributeSources || []).forEach(function (source) {
        var className = source.targetClass || object.className || '';
        var attribute = source.targetAttribute || '';
        if (!className || !attribute) return;
        var key = className + '::' + attribute;
        if (!byKey[key]) byKey[key] = {
          className: className,
          attribute: attribute,
          parameterType: source.type || source.attributeType || '',
          mandatory: source.mandatory,
          inherited: source.inherited,
          validation: source.validation || '',
          source: source,
          example: object.payload && object.payload[attribute] || '',
          ruleCandidate: recognizedContractRuleValue(source)
        };
      });
    });
    var grouped = {};
    Object.keys(byKey).sort().forEach(function (key) {
      var item = byKey[key];
      if (!grouped[item.className]) grouped[item.className] = { own: [], inherited: [], missingRules: 0 };
      var source = item.source.expression || [item.source.sourceRole, item.source.sourceClass && item.source.sourceAttribute ? item.source.sourceClass + '.' + item.source.sourceAttribute : item.source.sourceAttribute].filter(Boolean).join(' / ');
      var validationWarning = !settings.checkCmdbValidatorsInSystem && item.validation ? '<div class="notice error">Поле валидируется внутри CMDB. Локальная проверка отключена.</div>' : '';
      var ruleValue = Object.prototype.hasOwnProperty.call(createState.classValueRules, key) ? createState.classValueRules[key] : '';
      var effectiveRuleValue = String(ruleValue || '').trim() ? ruleValue : item.ruleCandidate || '';
      if (!Object.prototype.hasOwnProperty.call(createState.classValueRules, key) && effectiveRuleValue) createState.classValueRules[key] = effectiveRuleValue;
      var manualOverrides = manualOverrideForClassAttribute(objects, item.className, item.attribute);
      var mixedWarning = manualOverrides.length && String(effectiveRuleValue || '').trim() ? '<span class="mix-warning" title="Есть ручное переопределение в текущей сессии и правило контракта">! частично ручное / контрактное</span>' : '';
      var missingRule = item.mandatory && !String(effectiveRuleValue || '').trim();
      if (missingRule) grouped[item.className].missingRules += 1;
      var rowClass = missingRule ? ' class="error-row"' : manualOverrides.length && String(effectiveRuleValue || '').trim() ? ' class="warning-row"' : '';
      var row = '<tr' + rowClass + '><td>' + validationWarning + escapeHtml(item.attribute) + mixedWarning + '</td><td>' + escapeHtml(item.parameterType || '') + '</td><td>' + escapeHtml(item.mandatory ? 'да' : '') + '</td><td>' + escapeHtml(source) + '</td><td>' + escapeHtml(item.example || '') + '</td><td>' + createClassRuleInputHtml(key, effectiveRuleValue, item.className, item.attribute) + '</td></tr>';
      grouped[item.className][item.inherited ? 'inherited' : 'own'].push(row);
    });
    var classBlocks = Object.keys(grouped).sort().map(function (className) {
      var ownRows = grouped[className].own.join('') || '<tr><td colspan="6" class="muted">нет собственных атрибутов</td></tr>';
      var inheritedRows = grouped[className].inherited.join('') || '<tr><td colspan="6" class="muted">нет унаследованных атрибутов</td></tr>';
      var tableHead = '<thead><tr><th>Атрибут</th><th>Тип параметра</th><th>Обяз.</th><th>Текущий источник</th><th>Пример значения</th><th>Новое правило</th></tr></thead>';
      var blockClass = grouped[className].missingRules ? 'class-assignment error-block' : 'class-assignment';
      var missingText = grouped[className].missingRules ? ' / обязательных без правила: ' + grouped[className].missingRules : '';
      return '<details class="' + blockClass + '"><summary><strong>' + escapeHtml(className) + '</strong><span class="muted"> собственные: ' + escapeHtml(grouped[className].own.length) + ' / унаследованные: ' + escapeHtml(grouped[className].inherited.length) + escapeHtml(missingText) + '</span></summary><div class="class-assignment-body"><h3>Атрибуты класса</h3><div class="table-wrap"><table class="type-table">' + tableHead + '<tbody>' + ownRows + '</tbody></table></div><details class="attribute-group"><summary><strong>Унаследованные атрибуты</strong><span class="muted"> ' + escapeHtml(grouped[className].inherited.length) + '</span></summary><div class="attribute-group-body"><div class="table-wrap"><table class="type-table">' + tableHead + '<tbody>' + inheritedRows + '</tbody></table></div></div></details></div></details>';
    });
    if (!classBlocks.length) return '<div class="notice">Нет атрибутов для правил контракта.</div>';
    var hint = 'правило применяется ко всем объектам класса и сохраняется новой версией контракта';
    var expressionHelp = [
      '<div class="notice"><strong>Доступные выражения</strong><div class="type-key">',
      '$' + '{visioparam.name} - Shape Data текущего объекта / самого класса в плане<br>',
      '$' + '{source.visioparam.name} - Shape Data source-объекта связи<br>',
      '$' + '{destination.visioparam.name} - Shape Data destination-объекта связи<br>',
      '$' + '{relation.visioparam.name} - Shape Data самой связи<br>',
      '$' + '{contractparam.name} - параметр версии контракта',
      '</div><div class="muted">Вместо name указывайте имя Shape Data без префикса template_; например: ',
      '<span class="type-key">$' + '{visioparam.ipaddress}</span>.</div></div>'
    ].join('');
    return '<details class="object-row" open><summary><strong>Дозаполнить через контракт</strong> <span class="muted">' + escapeHtml(hint) + '</span></summary>' + expressionHelp + classBlocks.join('') + '</details>';
  }
  function createPlanEditHtml(plan) {
    return createState.fillMode === 'manual' ? createManualPlanEditHtml(plan) : createContractRuleEditHtml(plan);
  }
  function createPlanValidationHtml(value) {
    var plan = value && value.plan || {};
    var issues = value && value.verification && value.verification.issues || [];
    var contractUpdate = value && value.contractRulesUpdate || {};
    var contractLine = contractUpdate.applied && contractUpdate.applied.length
      ? '<div class="notice ok">Правила дозаполнения класса применены к контракту: ' + escapeHtml(contractUpdate.applied.length) + (contractUpdate.changed ? ' / создана новая версия.' : ' / изменений версии не потребовалось.') + '</div>'
      : '';
    var issueRows = issues.map(function (issue) {
      var rowClass = issue.level === 'error' ? ' class="error-row"' : issue.level === 'warning' ? ' class="warning-row"' : '';
      return '<tr' + rowClass + '><td>' + escapeHtml(issue.level || '') + '</td><td>' + escapeHtml(issue.code || '') + '</td><td>' + escapeHtml(issue.pageShapeKey || '') + '</td><td>' + escapeHtml([issue.className, issue.attribute].filter(Boolean).join('.')) + '</td><td>' + escapeHtml(issue.message || '') + '</td></tr>';
    }).join('');
    return '<section class="section"><h3>Проверка плана</h3>' + contractLine + '<h4>Ошибки и предупреждения</h4><div class="table-wrap"><table class="type-table"><thead><tr><th>Уровень</th><th>Код</th><th>Фигура</th><th>Атрибут</th><th>Сообщение</th></tr></thead><tbody>' + (issueRows || '<tr><td colspan="5" class="muted">нет ошибок</td></tr>') + '</tbody></table></div></section>';
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
  function planClassCounts(plan) {
    var counts = {};
    (plan && plan.objects || []).forEach(function (item) {
      var className = item.className || '';
      if (!className) return;
      counts[className] = (counts[className] || 0) + 1;
    });
    return counts;
  }
  function createSelectionPayload() {
    var plan = createState.lastResult && createState.lastResult.plan || {};
    var objects = plan.objects || [];
    var classCounts = planClassCounts(plan);
    var allClasses = Object.keys(classCounts);
    var classKeys = Object.keys(createState.selectedClasses || {});
    var objectKeys = Object.keys(createState.selectedPlanIndexes || {});
    var selectedClasses = classKeys.filter(function (className) { return createState.selectedClasses[className]; });
    var selectedIndexes = objectKeys.filter(function (index) { return createState.selectedPlanIndexes[index]; }).map(function (index) { return Number(index); });
    if (createState.selectionMode === 'objects') {
      return { mode: 'objects', explicit: Boolean(objectKeys.length), planIndexes: objectKeys.length ? selectedIndexes : objects.map(function (_, index) { return index; }), classes: [] };
    }
    return { mode: 'classes', explicit: Boolean(classKeys.length), classes: classKeys.length ? selectedClasses : allClasses, planIndexes: [] };
  }
  function createExecutionSelectorHtml() {
    var plan = createState.lastResult && createState.lastResult.plan || {};
    var objects = plan.objects || [];
    if (!objects.length) return '<div class="notice">План еще не построен. Вернитесь в "Подготовить объекты" и сформируйте план.</div>';
    var mode = createState.selectionMode === 'objects' ? 'objects' : 'classes';
    var classCounts = planClassCounts(plan);
    var classRows = Object.keys(classCounts).sort().map(function (className) {
      var checked = !Object.keys(createState.selectedClasses || {}).length || createState.selectedClasses[className] !== false;
      return '<label class="check-label"><input type="checkbox" data-create-class-select="' + escapeHtml(className) + '"' + (checked ? ' checked' : '') + '> ' + escapeHtml(className) + ' <span class="muted">(' + escapeHtml(classCounts[className]) + ')</span></label>';
    }).join('');
    var objectRows = objects.map(function (item, index) {
      var checked = !Object.keys(createState.selectedPlanIndexes || {}).length || createState.selectedPlanIndexes[index] !== false;
      var missingMark = item.missingAttributes && item.missingAttributes.length ? ' / не заполнено: ' + item.missingAttributes.length : '';
      return '<label class="check-label"><input type="checkbox" data-create-object-select="' + escapeHtml(index) + '"' + (checked ? ' checked' : '') + '> ' + escapeHtml(String(index + 1) + '. ' + (item.className || '') + ' / ' + (item.pageShapeKey || '') + missingMark) + '</label>';
    }).join('');
    var verification = createState.externalVerification || null;
    var verificationLine = verification
      ? externalVerificationBlocksCreation(verification)
        ? '<div class="notice error">Последняя внешняя верификация содержит ошибки. Создание заблокировано до успешной проверки.</div>'
        : verification.interpretation && verification.interpretation.status === 'manual_review'
          ? '<div class="notice">Последняя внешняя верификация требует ручного анализа. Создание не блокируется.</div>'
          : '<div class="notice ok">Последняя внешняя верификация успешна.</div>'
      : '<div class="notice">Внешняя верификация в этой сессии еще не запускалась.</div>';
    return '<div class="assignment-panel">' + verificationLine + '<div class="toolbar compact-toolbar"><div class="tabs"><button type="button" data-action="create-selection-mode" data-mode="classes"' + (mode === 'classes' ? ' class="active"' : '') + '>Выбрать классы</button><button type="button" data-action="create-selection-mode" data-mode="objects"' + (mode === 'objects' ? ' class="active"' : '') + '>Выбрать объекты</button></div><button class="primary" type="button" data-action="execute-create-objects">Создать</button></div>' + (mode === 'objects' ? '<div class="attribute-list">' + objectRows + '</div>' : '<div class="attribute-list">' + classRows + '</div>') + '</div>';
  }
  function createResultsTableHtml(results) {
    if (!results || !results.length) return '<span class="muted">создание не выполнялось</span>';
    return '<div class="table-wrap"><table class="type-table"><thead><tr><th>Класс</th><th>Тип</th><th>Фигура</th><th>Статус</th><th>ID</th><th>Сообщение</th></tr></thead><tbody>' + results.map(function (item) {
      return '<tr><td>' + escapeHtml(item.className || '') + '</td><td>' + escapeHtml(item.kind || 'object') + '</td><td>' + escapeHtml(item.pageShapeKey || '') + '</td><td>' + escapeHtml(item.success ? 'создано' : 'ошибка') + '</td><td>' + escapeHtml(item.id || '') + '</td><td>' + escapeHtml(item.message || '') + '</td></tr>';
    }).join('') + '</tbody></table></div>';
  }
  function createExecutionResultHtml(value) {
    if (!value || typeof value !== 'object') return escapeHtml(String(value || ''));
    var summary = value.summary || {};
    var title = value.executed ? 'Создание объектов' : 'План подготовлен';
    var hint = value.executed ? '' : '<div class="notice">План объектов здесь не выводится. Для просмотра откройте меню "Подготовить объекты".</div>';
    var issues = value.verification && value.verification.issues || [];
    var blocking = issues.filter(function (issue) { return issue && issue.level === 'error'; });
    var issueBlock = blocking.length ? '<div class="notice error">Блокирующих ошибок: ' + escapeHtml(blocking.length) + '</div>' : '';
    return '<div class="toolbar compact-toolbar"><strong>' + escapeHtml(title) + '</strong><span class="muted">Запланировано: ' + escapeHtml(summary.planned || 0) + ' / не заполнено: ' + escapeHtml(summary.missing || 0) + ' / блокирующих ошибок: ' + escapeHtml(summary.blockingIssues || 0) + ' / создано: ' + escapeHtml(summary.created || 0) + ' / ошибок: ' + escapeHtml(summary.failed || 0) + '</span></div>' + hint + issueBlock + '<h4>Результаты выполнения</h4>' + createResultsTableHtml(value.results || []);
  }
  function showCreateResult(value, ok) {
    var target = document.getElementById('status');
    if (!target) return;
    var planReady = value && typeof value.canExecute !== 'undefined' ? Boolean(value.canExecute) : ok !== false;
    updatePlanReadinessStatus(value);
    target.className = value && value.executed && !planReady ? 'notice error' : 'notice';
    if (!value || typeof value !== 'object') {
      target.textContent = String(value || '');
      return;
    }
    if (currentSection === 'create-objects') {
      target.innerHTML = createExecutionResultHtml(value);
      return;
    }
    var view = createState.resultView || 'plan';
    var body = createPlanValidationHtml(value);
    if (view === 'contract') {
      body += createContractRuleEditHtml(value.plan || {});
    } else if (view === 'manual') {
      body += missingAttributesHtml(value.plan && value.plan.missingAttributes || []) + createManualPlanEditHtml(value.plan || {});
    } else {
      body += missingAttributesHtml(value.plan && value.plan.missingAttributes || []) + createPlanHtml(value.plan || {});
    }
    target.innerHTML = '<div class="toolbar compact-toolbar"><strong>' + escapeHtml(value.executed ? 'Создание объектов' : view === 'manual' ? 'Дозаполнить руками' : view === 'contract' ? 'Дозаполнить через контракт' : 'План объектов') + '</strong><span class="muted">Запланировано: ' + escapeHtml(value.summary && value.summary.planned || 0) + ' / пропущено: ' + escapeHtml(value.summary && value.summary.skipped || 0) + ' / не заполнено: ' + escapeHtml(value.summary && value.summary.missing || 0) + ' / блокирующих ошибок: ' + escapeHtml(value.summary && value.summary.blockingIssues || 0) + ' / создано: ' + escapeHtml(value.summary && value.summary.created || 0) + ' / ошибок: ' + escapeHtml(value.summary && value.summary.failed || 0) + '</span></div>' + body + '<h4>Результаты выполнения</h4>' + createResultsTableHtml(value.results || []);
  }
  var createState = {
    fileName: '',
    fileBase64: '',
    fillMode: 'contract',
    resultView: 'plan',
    selectedPlanIndex: 0,
    selectionMode: 'classes',
    selectedClasses: {},
    selectedPlanIndexes: {},
    classValueRules: {},
    valueOverrides: {},
    lastResult: null,
    lastOk: null,
    externalVerification: null,
    externalVerificationOk: null
  };
  function persistCreateState() {
    try {
      if (!window.sessionStorage) return;
      window.sessionStorage.setItem('cmdbaa.createState', JSON.stringify({
        fileName: createState.fileName,
        fileBase64: createState.fileBase64,
        fillMode: createState.fillMode,
        resultView: createState.resultView,
        selectedPlanIndex: createState.selectedPlanIndex,
        selectionMode: createState.selectionMode,
        selectedClasses: createState.selectedClasses,
        selectedPlanIndexes: createState.selectedPlanIndexes,
        classValueRules: createState.classValueRules,
        valueOverrides: createState.valueOverrides,
        lastResult: createState.lastResult,
        lastOk: createState.lastOk,
        externalVerification: createState.externalVerification,
        externalVerificationOk: createState.externalVerificationOk
      }));
    } catch (error) {}
  }
  function hydrateCreateState() {
    try {
      var raw = window.sessionStorage && window.sessionStorage.getItem('cmdbaa.createState');
      if (!raw) return;
      var stored = JSON.parse(raw);
      createState.fileName = stored.fileName || '';
      createState.fileBase64 = stored.fileBase64 || '';
      createState.fillMode = stored.fillMode === 'manual' ? 'manual' : 'contract';
      createState.resultView = stored.resultView || 'plan';
      createState.selectedPlanIndex = Number(stored.selectedPlanIndex || 0);
      createState.selectionMode = stored.selectionMode === 'objects' ? 'objects' : 'classes';
      createState.selectedClasses = stored.selectedClasses || {};
      createState.selectedPlanIndexes = stored.selectedPlanIndexes || {};
      createState.classValueRules = stored.classValueRules || {};
      createState.valueOverrides = stored.valueOverrides || {};
      createState.lastResult = stored.lastResult || null;
      createState.lastOk = stored.lastOk;
      createState.externalVerification = stored.externalVerification || null;
      createState.externalVerificationOk = stored.externalVerificationOk;
    } catch (error) {}
  }
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
    contractVersionCode: '',
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
    contractRulesAppliedVersionCode: '',
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
        contractVersionCode: prepareState.contractVersionCode,
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
        contractRulesAppliedVersionCode: prepareState.contractRulesAppliedVersionCode,
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
      prepareState.contractVersionCode = stored.contractVersionCode || '';
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
      prepareState.contractRulesAppliedVersionCode = stored.contractRulesAppliedVersionCode || '';
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
  function uniqueSortedValues(values) {
    var seen = {};
    (values || []).forEach(function (value) {
      var normalized = String(value || '').trim();
      if (normalized) seen[normalized] = true;
    });
    return Object.keys(seen).sort(function (left, right) { return left.localeCompare(right); });
  }
  function classValuesFromRule(value) {
    if (Array.isArray(value)) return uniqueSortedValues(value);
    return uniqueSortedValues(String(value || '').split(','));
  }
  function applyContractRulesFromVersion(version, force) {
    if (!version || !version.rulesJson) return false;
    var versionCode = version.code || version.id || '';
    if (!force && versionCode && prepareState.contractRulesAppliedVersionCode === versionCode) return false;
    var rules = {};
    try {
      rules = JSON.parse(version.rulesJson || '{}');
    } catch (error) {
      return false;
    }
    (Array.isArray(rules.knownMappings) ? rules.knownMappings : []).forEach(function (mapping) {
      var key = String(mapping && mapping.key || '').trim();
      if (!key) return;
      var classes = classValuesFromRule(mapping.classes || []);
      if (classes.length) prepareState.classAssignments[key] = classes;
      var attributesByClass = mapping && mapping.attributesByClass && typeof mapping.attributesByClass === 'object' ? mapping.attributesByClass : {};
      Object.keys(attributesByClass).forEach(function (className) {
        var attrKey = key + '::' + className;
        var attrs = attributesByClass[className] || [];
        var names = [];
        attrs.forEach(function (attr) {
          var attrName = String(attr && (attr.name || attr.attrName) || '').trim();
          if (!attrName) return;
          names.push(attrName);
          if (attr.listMode) prepareState.attributeListModes[attrKey + '::' + attrName] = String(attr.listMode);
          if (attr.sourceRule) prepareState.attributeSourceRules[attrKey + '::' + attrName] = attr.sourceRule;
        });
        if (names.length) prepareState.attributeAssignments[attrKey] = uniqueSortedValues(names);
      });
    });
    if (rules.relationEndpointMappings && typeof rules.relationEndpointMappings === 'object' && !Array.isArray(rules.relationEndpointMappings)) {
      prepareState.relationEndpointMappings = rules.relationEndpointMappings;
    }
    if (Array.isArray(rules.contractParams)) prepareState.contractParams = rules.contractParams;
    prepareState.contractRulesAppliedVersionCode = versionCode;
    persistPrepareState();
    return true;
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
  function syncCreateFileFromPrepare() {
    if (!prepareState.fileBase64) return;
    if (createState.fileBase64 === prepareState.fileBase64 && createState.fileName === prepareState.fileName) return;
    createState.fileName = prepareState.fileName || 'template.vsdx';
    createState.fileBase64 = prepareState.fileBase64;
  }
  function resetCreatePlanForNewFile() {
    createState.fileName = prepareState.fileName || '';
    createState.fileBase64 = prepareState.fileBase64 || '';
    createState.valueOverrides = {};
    createState.classValueRules = {};
    createState.selectedPlanIndex = 0;
    createState.selectionMode = 'classes';
    createState.selectedClasses = {};
    createState.selectedPlanIndexes = {};
    createState.resultView = 'plan';
    createState.lastResult = null;
    createState.lastOk = null;
    persistCreateState();
    updatePlanReadinessStatus(null);
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
    var target = document.getElementById('shared-file-status');
    if (target) target.textContent = prepareState.fileName ? ('Файл: ' + prepareState.fileName) : 'Файл не выбран';
    syncCreateFileFromPrepare();
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
          prepareState.contractRulesAppliedVersionCode = '';
          resetCreatePlanForNewFile();
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
      prepareState.contractVersionCode = prepareState.contractMetadata && prepareState.contractMetadata.contractVersionCode || '';
      prepareState.contractRulesAppliedVersionCode = '';
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
      loadContracts().then(loadContractVersions);
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
  function enrichmentPayload(base64, file, contractOnly) {
    return {
      filename: prepareState.fileName || file && file.name || 'template.vsdx',
      fileBase64: base64,
      contractOnly: Boolean(contractOnly),
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
      checksumFilename: prepareState.checksumFileName || '',
      decomposeAggregates: prepareState.decomposeAggregates,
      schema: readSchemaSettings(),
      typeRules: readTypeRules(),
      preparedBy: boot.session && boot.session.username || ''
    };
  }
  function savePrepareContractOnly() {
    syncVisibleAttributeAssignmentsFromDom();
    syncPrepareDecomposeFromRules();
    var file = selectedFile();
    if (!file && !prepareState.fileBase64) {
      renderNotice('Выберите .vsdx файл.', false);
      return;
    }
    renderNotice('Сохраняю контракт...', null);
    return (prepareState.fileBase64 ? Promise.resolve(prepareState.fileBase64) : fileToBase64(file).then(function (base64) {
      prepareState.fileBase64 = base64;
      return base64;
    })).then(function (base64) {
      return api('/vsdx/enrich', {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'content-type': 'application/json'
        },
        body: JSON.stringify(enrichmentPayload(base64, file, true))
      });
    }).then(function (result) {
      if (!result.response.ok) {
        renderNotice(result.json, false);
        return;
      }
      prepareState.contractVersionId = result.json.contractVersion && result.json.contractVersion.id || prepareState.contractVersionId;
      prepareState.contractVersionCode = result.json.contractVersion && result.json.contractVersion.code || prepareState.contractVersionCode;
      loadContractVersions();
      persistPrepareState();
      updatePrepareContractVersionSummary();
      renderNotice('Контракт сохранен. Версия: ' + (result.json.contractVersion && result.json.contractVersion.code || '') + '. VSDX еще ссылается на старую версию: нажмите "Сохранить шаблон", чтобы записать новую версию в файл.', true);
    }).catch(function (error) {
      renderNotice(error && error.message ? error.message : String(error), false);
    });
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
        body: JSON.stringify(enrichmentPayload(base64, file, false))
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
      prepareState.contractVersionCode = result.json.contractVersion && result.json.contractVersion.code || prepareState.contractVersionCode;
      if (result.json.fixedMetadata) {
        prepareState.contractMetadata = Object.assign({}, prepareState.contractMetadata || {}, result.json.fixedMetadata);
      }
      loadContractVersions();
      persistPrepareState();
      updatePrepareContractVersionSummary();
      renderNotice('Контракт сохранен, VSDX и файл контрольной суммы загружены. Версия: ' + (result.json.contractVersion && result.json.contractVersion.code || ''), true);
    }).catch(function (error) {
      renderNotice(error && error.message ? error.message : String(error), false);
    });
  }
  function verifyVsdxFile(file) {
    if (!file && !prepareState.fileBase64) {
      showStatus('Выберите .vsdx файл.', false);
      return;
    }
    showStatus('Проверяю VSDX...', null);
    return (file ? fileToBase64(file).then(function (base64) {
      prepareState.file = file;
      prepareState.fileName = file.name || 'template.vsdx';
      prepareState.fileBase64 = base64;
      resetCreatePlanForNewFile();
      syncFileStatus();
      persistPrepareState();
      return base64;
    }) : Promise.resolve(prepareState.fileBase64)).then(function (base64) {
      return api('/vsdx/verify', {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'content-type': 'application/json'
        },
        body: JSON.stringify({
          filename: prepareState.fileName || file && file.name || 'template.vsdx',
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
    if (!file && !prepareState.fileBase64) {
      showStatus('Выберите .vsdx файл.', false);
      return;
    }
    showStatus('Проверяю техническую целостность шаблона...', null);
    (file ? fileToBase64(file).then(function (base64) {
      prepareState.file = file;
      prepareState.fileName = file.name || 'template.vsdx';
      prepareState.fileBase64 = base64;
      resetCreatePlanForNewFile();
      syncFileStatus();
      persistPrepareState();
      return base64;
    }) : Promise.resolve(prepareState.fileBase64)).then(function (base64) {
      return api('/vsdx/check-template', {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'content-type': 'application/json'
        },
        body: JSON.stringify({
          filename: prepareState.fileName || file && file.name || 'template.vsdx',
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
  function collectCreateClassRules() {
    Array.prototype.forEach.call(document.querySelectorAll('[data-create-class-rule-key]'), function (input) {
      var key = input.getAttribute('data-create-class-rule-key') || '';
      if (!key) return;
      createState.classValueRules[key] = input.value || '';
    });
  }
  function collectCreateSelection() {
    var classInputs = document.querySelectorAll('[data-create-class-select]');
    if (classInputs.length) {
      var classes = {};
      Array.prototype.forEach.call(classInputs, function (input) {
        classes[input.getAttribute('data-create-class-select') || ''] = Boolean(input.checked);
      });
      createState.selectedClasses = classes;
    }
    var objectInputs = document.querySelectorAll('[data-create-object-select]');
    if (objectInputs.length) {
      var indexes = {};
      Array.prototype.forEach.call(objectInputs, function (input) {
        indexes[input.getAttribute('data-create-object-select') || ''] = Boolean(input.checked);
      });
      createState.selectedPlanIndexes = indexes;
    }
  }
  function currentPrepareContractVersionCode() {
    return prepareState.contractVersionCode || prepareState.contractMetadata && prepareState.contractMetadata.contractVersionCode || '';
  }
  function rememberCreateContractVersion(result) {
    var version = result && result.verification && result.verification.contractVersion || result && result.contractVersion || null;
    if (!version) return;
    prepareState.contractVersionId = version.id || prepareState.contractVersionId || '';
    prepareState.contractVersionCode = version.code || prepareState.contractVersionCode || '';
    updatePrepareContractVersionSummary();
    renderNotice('Для планирования используется новая версия контракта ' + (version.code || '') + '. Если продолжите работать с этим VSDX, нажмите "Сохранить шаблон", чтобы записать новую версию в файл.', null);
    persistPrepareState();
  }
  function submitCreateObjects(execute) {
    syncCreateFileFromPrepare();
    if (!createState.fileBase64) {
      showStatus('Выберите .vsdx файл.', false);
      return;
    }
    collectCreateOverrides();
    collectCreateClassRules();
    collectCreateSelection();
    if (!execute) {
      createState.externalVerification = null;
      createState.externalVerificationOk = null;
    }
    if (execute && (!prepareState.checksumFileName || !prepareState.checksumText)) {
      showStatus('Создание невозможно: загрузите файл контрольной суммы.', false);
      return;
    }
    if (!createState.resultView || createState.resultView === 'empty') createState.resultView = 'plan';
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
        contractVersionId: prepareState.contractVersionId || '',
        contractVersionCode: currentPrepareContractVersionCode(),
        execute: Boolean(execute),
        valueOverrides: createState.fillMode === 'manual' ? createState.valueOverrides : {},
        classValueRules: createState.fillMode === 'contract' ? createState.classValueRules : {},
        saveClassValueRules: createState.fillMode === 'contract',
        createSelection: createSelectionPayload(),
        checksumFilename: prepareState.checksumFileName || '',
        checksumText: prepareState.checksumText || '',
        settings: readSettings()
      })
    }).then(function (result) {
      createState.lastResult = result.json;
      createState.lastOk = result.response.ok;
      rememberCreateContractVersion(result.json);
      persistCreateState();
      renderObjectWorkflow();
    }).catch(function (error) {
      showStatus(error && error.message ? error.message : String(error), false);
    });
  }
  function createObjectsFromVsdxFile(file) {
    if (!file && !prepareState.fileBase64) {
      showStatus('Выберите .vsdx файл.', false);
      return;
    }
    showStatus('Читаю VSDX и строю план создания...', null);
    (file ? fileToBase64(file).then(function (base64) {
      prepareState.file = file;
      prepareState.fileName = file.name || 'template.vsdx';
      prepareState.fileBase64 = base64;
      persistPrepareState();
      syncFileStatus();
      return base64;
    }) : Promise.resolve(prepareState.fileBase64)).then(function (base64) {
      createState.fileName = prepareState.fileName || file && file.name || 'template.vsdx';
      createState.fileBase64 = base64;
      createState.valueOverrides = {};
      createState.classValueRules = {};
      createState.selectedPlanIndex = 0;
      createState.selectionMode = 'classes';
      createState.selectedClasses = {};
      createState.selectedPlanIndexes = {};
      createState.resultView = 'plan';
      createState.lastResult = null;
      createState.lastOk = null;
      createState.externalVerification = null;
      createState.externalVerificationOk = null;
      persistCreateState();
      return api('/vsdx/create-objects', {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'content-type': 'application/json'
        },
        body: JSON.stringify({
          filename: createState.fileName,
          fileBase64: base64,
          contractVersionId: prepareState.contractVersionId || '',
          contractVersionCode: currentPrepareContractVersionCode(),
          execute: false,
          valueOverrides: {},
          classValueRules: {},
          saveClassValueRules: false,
          createSelection: { mode: 'classes', classes: [], planIndexes: [] },
          settings: readSettings()
        })
      });
    }).then(function (result) {
      createState.lastResult = result.json;
      createState.lastOk = result.response.ok;
      rememberCreateContractVersion(result.json);
      persistCreateState();
      renderObjectWorkflow();
    }).catch(function (error) {
      showStatus(error && error.message ? error.message : String(error), false);
    });
  }
  function verificationBasePayload(extra) {
    syncCreateFileFromPrepare();
    return Object.assign({
      filename: createState.fileName || prepareState.fileName || 'template.vsdx',
      fileBase64: createState.fileBase64 || prepareState.fileBase64 || '',
      contractVersionId: prepareState.contractVersionId || '',
      contractVersionCode: currentPrepareContractVersionCode(),
      valueOverrides: createState.valueOverrides || {},
      settings: readSettings(),
      createdBy: boot.session && boot.session.username || ''
    }, extra || {});
  }
  function showVerificationContractStatus(value, ok) {
    var target = document.getElementById('verification-contract-status');
    if (!target) return;
    target.className = ok === false ? 'notice error' : ok === true ? 'notice ok' : 'notice';
    if (!value || typeof value !== 'object') {
      target.textContent = String(value || '');
      return;
    }
    var inputContract = value.inputContract || value.generated && value.generated.inputContract || {};
    var outputContract = value.outputContract || value.generated && value.generated.outputContract || {};
    var summary = value.summary || value.generated && value.generated.summary || {};
    var classRows = (inputContract.classes || []).map(function (item) {
      return '<tr><td><strong>' + escapeHtml(item.name || '') + '</strong></td><td>' + escapeHtml((item.attributes || []).length) + '</td><td>' + escapeHtml((item.attributes || []).map(function (attr) { return attr.name || ''; }).filter(Boolean).join(', ')) + '</td></tr>';
    }).join('');
    var relationRows = (inputContract.relations || []).map(function (item) {
      return '<tr><td>' + escapeHtml(item.className || '') + '</td><td>' + escapeHtml(item.sourceClass || '') + '</td><td>' + escapeHtml(item.destinationClass || '') + '</td><td>' + escapeHtml(item.relationBindingStatus || '') + '</td></tr>';
    }).join('');
    var paramRows = (inputContract.contractParams || []).map(function (item) {
      var listText = item.listMode && item.listMode !== 'none'
        ? item.listMode + (item.values && item.values.length ? ': ' + item.values.join(', ') : '')
        : '';
      return '<tr><td><strong>' + escapeHtml(item.name || '') + '</strong></td><td>' + escapeHtml(item.description || '') + '</td><td>' + escapeHtml(item.type || '') + '</td><td>' + escapeHtml(item.required ? 'да' : 'нет') + '</td><td>' + escapeHtml(item.defaultValue || '') + '</td><td>' + escapeHtml(listText) + '</td></tr>';
    }).join('');
    var excluded = summary.excludedObjects ? '<span class="muted"> / исключено: ' + escapeHtml(summary.excludedObjects) + '</span>' : '';
    var publishLine = value.input || value.output
      ? '<div class="notice ok">Опубликовано: input ' + escapeHtml(value.input && value.input.data && value.input.data.code || '') + ' / output ' + escapeHtml(value.output && value.output.data && value.output.data.code || '') + '</div>'
      : '';
    target.innerHTML = publishLine +
      '<div class="toolbar compact-toolbar"><strong>' + escapeHtml(ok === false ? 'Контракты не сформированы' : 'Контракты по готовым объектам') + '</strong><span class="muted"> объектов: ' + escapeHtml(summary.objects || 0) + ' / классов: ' + escapeHtml(summary.classes || 0) + ' / связей: ' + escapeHtml(summary.relations || 0) + excluded + '</span></div>' +
      '<h4>Переменные контракта</h4><div class="table-wrap"><table class="type-table"><thead><tr><th>Имя</th><th>Описание</th><th>Тип</th><th>Обязательный</th><th>По умолчанию</th><th>Список</th></tr></thead><tbody>' + (paramRows || '<tr><td colspan="6" class="muted">переменные контракта не заданы</td></tr>') + '</tbody></table></div>' +
      '<h4>Классы input contract</h4><div class="table-wrap"><table class="type-table"><thead><tr><th>Класс</th><th>Атрибутов</th><th>Атрибуты</th></tr></thead><tbody>' + (classRows || '<tr><td colspan="3" class="muted">нет готовых классов</td></tr>') + '</tbody></table></div>' +
      '<h4>Связи input contract</h4><div class="table-wrap"><table class="type-table"><thead><tr><th>Класс связи</th><th>Source</th><th>Destination</th><th>Статус</th></tr></thead><tbody>' + (relationRows || '<tr><td colspan="4" class="muted">нет готовых связей</td></tr>') + '</tbody></table></div>' +
      '<details><summary>Техническая часть</summary><pre>' + escapeHtml(JSON.stringify(value, null, 2)) + '</pre></details>';
  }
  function generateVerificationContracts() {
    if (!prepareState.fileBase64 && !createState.fileBase64) {
      showVerificationContractStatus('Сначала загрузите VSDX и подготовьте план.', false);
      return;
    }
    showVerificationContractStatus('Формирую input/output contracts по готовым объектам...', null);
    api('/verification/contracts/generate', {
      method: 'POST',
      headers: { Accept: 'application/json', 'content-type': 'application/json' },
      body: JSON.stringify(verificationBasePayload({ verificationContractVersion: document.getElementById('verification-contract-version') && document.getElementById('verification-contract-version').value || '1' }))
    }).then(function (result) {
      showVerificationContractStatus(result.json, result.response.ok);
    }).catch(function (error) {
      showVerificationContractStatus(error && error.message ? error.message : String(error), false);
    });
  }
  function publishVerificationContracts() {
    if (!prepareState.fileBase64 && !createState.fileBase64) {
      showVerificationContractStatus('Сначала загрузите VSDX и подготовьте план.', false);
      return;
    }
    showVerificationContractStatus('Публикую input/output contracts по готовым объектам в CMDBuild...', null);
    api('/verification/contracts/publish', {
      method: 'POST',
      headers: { Accept: 'application/json', 'content-type': 'application/json' },
      body: JSON.stringify(verificationBasePayload({ verificationContractVersion: document.getElementById('verification-contract-version') && document.getElementById('verification-contract-version').value || '1' }))
    }).then(function (result) {
      showVerificationContractStatus(result.json, result.response.ok);
      loadVerificationContracts();
    }).catch(function (error) {
      showVerificationContractStatus(error && error.message ? error.message : String(error), false);
    });
  }
  function selectedVerificationContract(selectId) {
    var select = document.getElementById(selectId);
    if (!select || !select.value) return null;
    var option = select.options[select.selectedIndex];
    return {
      code: option && option.getAttribute('data-code') || select.value || '',
      version: option && option.getAttribute('data-version') || '',
      status: option && option.getAttribute('data-status') || '',
      checksum: option && option.getAttribute('data-checksum') || ''
    };
  }
  function defaultUiResultInterpretation() {
    return {
      mode: 'rows_present_is_error',
      target: { scope: 'all_tables', tableCode: '' },
      severity: 'error',
      messageIfMatched: 'Найдены данные, требующие внимания',
      messageIfNotMatched: 'Данные не найдены',
      showTablesOnMatched: true,
      showTablesOnNotMatched: false
    };
  }
  function setResultInterpretationControls(value) {
    var parsed = defaultUiResultInterpretation();
    try {
      parsed = Object.assign(parsed, JSON.parse(value || '{}'));
      parsed.target = Object.assign(defaultUiResultInterpretation().target, parsed.target || {});
    } catch (error) {}
    var mode = document.getElementById('verification-interpretation-mode');
    var scope = document.getElementById('verification-interpretation-scope');
    var tableCode = document.getElementById('verification-interpretation-table-code');
    var severity = document.getElementById('verification-interpretation-severity');
    var matched = document.getElementById('verification-interpretation-message-matched');
    var notMatched = document.getElementById('verification-interpretation-message-not-matched');
    var showMatched = document.getElementById('verification-interpretation-show-matched');
    var showNotMatched = document.getElementById('verification-interpretation-show-not-matched');
    if (mode) mode.value = parsed.mode || 'rows_present_is_error';
    if (scope) scope.value = parsed.target && parsed.target.scope || 'all_tables';
    if (tableCode) tableCode.value = parsed.target && parsed.target.tableCode || '';
    if (severity) severity.value = parsed.severity || 'error';
    if (matched) matched.value = parsed.messageIfMatched || '';
    if (notMatched) notMatched.value = parsed.messageIfNotMatched || '';
    if (showMatched) showMatched.checked = parsed.showTablesOnMatched !== false;
    if (showNotMatched) showNotMatched.checked = Boolean(parsed.showTablesOnNotMatched);
  }
  function resultInterpretationJsonFromControls() {
    var payload = {
      mode: document.getElementById('verification-interpretation-mode') && document.getElementById('verification-interpretation-mode').value || 'rows_present_is_error',
      target: {
        scope: document.getElementById('verification-interpretation-scope') && document.getElementById('verification-interpretation-scope').value || 'all_tables',
        tableCode: document.getElementById('verification-interpretation-table-code') && document.getElementById('verification-interpretation-table-code').value || ''
      },
      severity: document.getElementById('verification-interpretation-severity') && document.getElementById('verification-interpretation-severity').value || 'error',
      messageIfMatched: document.getElementById('verification-interpretation-message-matched') && document.getElementById('verification-interpretation-message-matched').value || 'Найдены данные, требующие внимания',
      messageIfNotMatched: document.getElementById('verification-interpretation-message-not-matched') && document.getElementById('verification-interpretation-message-not-matched').value || 'Данные не найдены',
      showTablesOnMatched: Boolean(document.getElementById('verification-interpretation-show-matched') && document.getElementById('verification-interpretation-show-matched').checked),
      showTablesOnNotMatched: Boolean(document.getElementById('verification-interpretation-show-not-matched') && document.getElementById('verification-interpretation-show-not-matched').checked)
    };
    return JSON.stringify(payload, null, 2);
  }
  function verificationEndpointFormPayload(statusFallback) {
    var selected = selectedVerificationContractsOrShowError();
    if (!selected) return null;
    return {
      code: document.getElementById('verification-endpoint-code') && document.getElementById('verification-endpoint-code').value || '',
      endpointUrl: document.getElementById('verification-endpoint-url') && document.getElementById('verification-endpoint-url').value || '',
      inputContractCode: selected.input.code,
      inputContractVersion: selected.input.version,
      outputContractCode: selected.output.code,
      outputContractVersion: selected.output.version,
      paramsJson: document.getElementById('verification-params-json') && document.getElementById('verification-params-json').value || '{}',
      resultInterpretationJson: resultInterpretationJsonFromControls(),
      status: document.getElementById('verification-endpoint-status') && document.getElementById('verification-endpoint-status').value || statusFallback || 'Active'
    };
  }
  function selectVerificationContractByCodeVersion(selectId, code, version) {
    var select = document.getElementById(selectId);
    if (!select) return;
    for (var index = 0; index < select.options.length; index += 1) {
      var option = select.options[index];
      if ((option.getAttribute('data-code') || '') === code && (!version || (option.getAttribute('data-version') || '') === version)) {
        select.selectedIndex = index;
        return;
      }
    }
  }
  function selectedVerificationContractsOrShowError() {
    var inputContract = selectedVerificationContract('verification-input-contract');
    var outputContract = selectedVerificationContract('verification-output-contract');
    if (!inputContract || !outputContract) {
      showStatus('Выберите опубликованные input и output contracts.', false);
      return null;
    }
    if (inputContract.status !== 'Active' || outputContract.status !== 'Active') {
      showStatus('Для запуска внешней верификации нужны Active input/output contracts.', false);
      return null;
    }
    return { input: inputContract, output: outputContract };
  }
  function selectedVerificationEndpoint() {
    var select = document.getElementById('verification-endpoint-select');
    if (!select || !select.value) return null;
    var option = select.options[select.selectedIndex];
    if (!option) return null;
    return {
      code: option.getAttribute('data-code') || select.value || '',
      endpointUrl: option.getAttribute('data-url') || '',
      method: option.getAttribute('data-method') || 'POST',
      inputContractCode: option.getAttribute('data-input-code') || '',
      inputContractVersion: option.getAttribute('data-input-version') || '',
      outputContractCode: option.getAttribute('data-output-code') || '',
      outputContractVersion: option.getAttribute('data-output-version') || '',
      paramsJson: option.getAttribute('data-params-json') || '{}',
      resultInterpretationJson: option.getAttribute('data-result-interpretation-json') || '{}',
      status: option.getAttribute('data-status') || ''
    };
  }
  function verificationIssueRowsHtml(items) {
    var rows = (items || []).map(function (item) {
      var rowClass = item.level === 'error' ? ' class="error-row"' : item.level === 'warning' ? ' class="warning-row"' : '';
      return '<tr' + rowClass + '><td>' + escapeHtml(item.level || '') + '</td><td>' + escapeHtml(item.code || '') + '</td><td>' + escapeHtml(item.className || '') + '</td><td>' + escapeHtml(item.attribute || '') + '</td><td>' + escapeHtml(item.pageShapeKey || '') + '</td><td>' + escapeHtml(item.message || '') + '</td></tr>';
    }).join('');
    return '<div class="table-wrap"><table class="type-table"><thead><tr><th>Уровень</th><th>Код</th><th>Класс</th><th>Атрибут</th><th>Фигура</th><th>Сообщение</th></tr></thead><tbody>' + (rows || '<tr><td colspan="6" class="muted">замечаний нет</td></tr>') + '</tbody></table></div>';
  }
  function verificationResultTablesHtml(value) {
    var response = value && value.response || {};
    var interpretation = value && value.interpretation || {};
    var tables = Array.isArray(response.tables) ? response.tables : [];
    if (!tables.length || !interpretation.showTables) return '';
    var target = interpretation.interpretation && interpretation.interpretation.target || {};
    var visibleTables = target.scope === 'table' && target.tableCode
      ? tables.filter(function (table) { return String(table && table.code || '') === target.tableCode; })
      : tables;
    if (!visibleTables.length) return '<div class="notice">Таблица результата по выбранному code не найдена.</div>';
    return visibleTables.map(function (table) {
      var columns = Array.isArray(table.columns) ? table.columns : [];
      var rows = Array.isArray(table.rows) ? table.rows : [];
      var columnNames = columns.length
        ? columns.map(function (column) { return String(column && column.name || ''); }).filter(Boolean)
        : Object.keys(rows[0] || {});
      var header = columnNames.map(function (name) {
        var column = columns.filter(function (item) { return String(item && item.name || '') === name; })[0] || {};
        return '<th>' + escapeHtml(column.title || name) + '</th>';
      }).join('');
      var body = rows.map(function (row) {
        return '<tr>' + columnNames.map(function (name) {
          var value = row && Object.prototype.hasOwnProperty.call(row, name) ? row[name] : '';
          return '<td>' + escapeHtml(value && typeof value === 'object' ? JSON.stringify(value) : String(value == null ? '' : value)) + '</td>';
        }).join('') + '</tr>';
      }).join('');
      return '<details class="object-row" open><summary><strong>' + escapeHtml(table.title || table.code || 'Таблица результата') + '</strong> <span class="muted">' + escapeHtml(table.code || '') + ' / строк: ' + escapeHtml(rows.length) + '</span></summary><div class="table-wrap"><table class="type-table"><thead><tr>' + (header || '<th>Данные</th>') + '</tr></thead><tbody>' + (body || '<tr><td class="muted" colspan="' + escapeHtml(Math.max(columnNames.length, 1)) + '">строк нет</td></tr>') + '</tbody></table></div></details>';
    }).join('');
  }
  function externalVerificationBlocksCreation(value) {
    if (!value) return false;
    var status = value.interpretation && value.interpretation.status || '';
    return status === 'failed' || status === 'technical_error' || value.success === false || Number(value.summary && value.summary.errors || 0) > 0;
  }
  function showVerificationResult(value, ok) {
    var target = document.getElementById('status');
    if (!target) return;
    if (!value || typeof value !== 'object') {
      showStatus(value || '', ok);
      return;
    }
    var summary = value.summary || {};
    var hasErrors = externalVerificationBlocksCreation(value);
    target.className = hasErrors ? 'notice error' : 'notice ok';
    var endpoint = value.endpoint || {};
    var inputContract = value.inputContract || {};
    var outputContract = value.outputContract || {};
    var statusText = hasErrors ? 'Верификация не пройдена' : 'Верификация пройдена';
    var interpretation = value.interpretation || {};
    var interpretationLine = interpretation.status
      ? '<div class="notice"><strong>Интерпретация BAA:</strong> ' + escapeHtml(interpretation.status) + ' / строк: ' + escapeHtml(interpretation.rowCount || 0) + ' / ' + escapeHtml(interpretation.message || '') + '</div>'
      : '';
    target.innerHTML = '<div class="toolbar compact-toolbar"><strong>' + escapeHtml(statusText) + '</strong><span class="muted">Ошибки: ' + escapeHtml(summary.errors || 0) + ' / предупреждения: ' + escapeHtml(summary.warnings || 0) + ' / info: ' + escapeHtml(summary.infos || 0) + '</span></div>' +
      '<div class="grid"><div><strong>Endpoint</strong><div class="type-key">' + escapeHtml([endpoint.code, endpoint.endpointUrl].filter(Boolean).join(' / ')) + '</div></div>' +
      '<div><strong>Input contract</strong><div class="type-key">' + escapeHtml([inputContract.code, inputContract.version].filter(Boolean).join(' / ')) + '</div></div>' +
      '<div><strong>Output contract</strong><div class="type-key">' + escapeHtml([outputContract.code, outputContract.version].filter(Boolean).join(' / ')) + '</div></div></div>' +
      interpretationLine + verificationIssueRowsHtml(value.items || []) + verificationResultTablesHtml(value);
  }
  function render(section) {
    setActive(section);
    if (section === 'schema') renderSchema();
    else if (section === 'contracts') renderContracts();
    else if (section === 'settings') renderSettings();
    else if (section === 'types') renderTypesSettings();
    else if (section === 'check-template') renderCheckTemplate();
    else if (section === 'prepare-verification') renderPrepareVerification();
    else if (section === 'verify') renderVerify();
    else if (section === 'prepare-objects') renderObjectWorkflow();
    else if (section === 'create-objects') renderObjectWorkflow();
    else if (section === 'help') renderHelp();
    else if (section === 'about') renderAbout();
    else renderPrepare();
    if (section !== 'contracts' && section !== 'prepare-template') loadContractVersions();
  }
  document.addEventListener('click', function (event) {
    var navLink = event.target && event.target.closest && event.target.closest('a[data-section]');
    if (navLink) {
      event.preventDefault();
      collectCreateOverrides();
      collectCreateClassRules();
      collectCreateSelection();
      persistCreateState();
      currentSection = navLink.getAttribute('data-section') || 'prepare-template';
      if (window.history && window.history.pushState) window.history.pushState({ section: currentSection }, '', navLink.href);
      render(currentSection);
      return;
    }
    var button = event.target.closest('button[data-action],button[data-expression-suggestion-index]');
    if (!button) return;
    var action = button.getAttribute('data-action');
    if (button.hasAttribute('data-expression-suggestion-index')) {
      applyExpressionSuggestion(Number(button.getAttribute('data-expression-suggestion-index') || 0));
      return;
    }
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
        checkCmdbValidatorsInSystem: Boolean(document.getElementById('settings-check-cmdb-validators') && document.getElementById('settings-check-cmdb-validators').checked),
        referenceFixedListLimit: document.getElementById('settings-reference-limit') && document.getElementById('settings-reference-limit').value || 50,
        verificationInputContractClass: document.getElementById('settings-verification-input-class') && document.getElementById('settings-verification-input-class').value || 'BAAVerificationInputContract',
        verificationOutputContractClass: document.getElementById('settings-verification-output-class') && document.getElementById('settings-verification-output-class').value || 'BAAVerificationOutputContract',
        verificationEndpointClass: document.getElementById('settings-verification-endpoint-class') && document.getElementById('settings-verification-endpoint-class').value || 'BAAVerificationEndpoint'
      });
      showStatus({
        success: true,
        checksumExtension: settings.checksumExtension,
        verifyChecksumOnPrepare: settings.verifyChecksumOnPrepare,
        checkCmdbValidatorsInSystem: settings.checkCmdbValidatorsInSystem,
        referenceFixedListLimit: settings.referenceFixedListLimit,
        verificationInputContractClass: settings.verificationInputContractClass,
        verificationOutputContractClass: settings.verificationOutputContractClass,
        verificationEndpointClass: settings.verificationEndpointClass
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
        prepareState.contractVersionCode = '';
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
    if (action === 'reload-verification-contracts') {
      loadVerificationContracts();
      return;
    }
    if (action === 'reload-verification-endpoints') {
      loadVerificationEndpoints();
      return;
    }
    if (action === 'generate-verification-contracts') {
      generateVerificationContracts();
      return;
    }
    if (action === 'publish-verification-contracts') {
      publishVerificationContracts();
      return;
    }
    if (action === 'save-verification-endpoint') {
      var endpointForm = verificationEndpointFormPayload('Active');
      if (!endpointForm) return;
      var endpointPayload = verificationBasePayload({
        endpoint: endpointForm
      });
      showStatus('Сохраняю endpoint...', null);
      api('/verification/endpoints', {
        method: 'POST',
        headers: { Accept: 'application/json', 'content-type': 'application/json' },
        body: JSON.stringify(endpointPayload)
      }).then(function (result) {
        showStatus(result.json, result.response.ok);
        if (result.response.ok) {
          loadVerificationEndpoints().then(function () {
            var select = document.getElementById('verification-endpoint-select');
            if (!select) return;
            for (var index = 0; index < select.options.length; index += 1) {
              if ((select.options[index].getAttribute('data-code') || '') === endpointForm.code) {
                select.selectedIndex = index;
                break;
              }
            }
          });
        }
      }).catch(function (error) { showStatus(error && error.message ? error.message : String(error), false); });
      return;
    }
    if (action === 'run-external-verification') {
      var selectedEndpoint = selectedVerificationEndpoint();
      if (!selectedEndpoint) {
        showStatus('Выберите сохраненный Active endpoint. Правила настраиваются в меню "Подготовить правила верификации".', false);
        return;
      }
      if (selectedEndpoint && selectedEndpoint.status !== 'Active') {
        showStatus('Для запуска внешней верификации нужен Active endpoint.', false);
        return;
      }
      var selectedForRun = {
        input: { code: selectedEndpoint.inputContractCode, version: selectedEndpoint.inputContractVersion, status: 'Active' },
        output: { code: selectedEndpoint.outputContractCode, version: selectedEndpoint.outputContractVersion, status: 'Active' }
      };
      var runPayload = verificationBasePayload({
        endpoint: selectedEndpoint || {
          code: document.getElementById('verification-endpoint-code') && document.getElementById('verification-endpoint-code').value || '',
          endpointUrl: document.getElementById('verification-endpoint-url') && document.getElementById('verification-endpoint-url').value || '',
          inputContractCode: selectedForRun.input.code,
          inputContractVersion: selectedForRun.input.version,
          outputContractCode: selectedForRun.output.code,
          outputContractVersion: selectedForRun.output.version,
          paramsJson: document.getElementById('verification-params-json') && document.getElementById('verification-params-json').value || '{}',
          resultInterpretationJson: resultInterpretationJsonFromControls(),
          status: 'Active'
        }
      });
      showStatus('Запускаю внешнюю верификацию...', null);
      api('/verification/run', {
        method: 'POST',
        headers: { Accept: 'application/json', 'content-type': 'application/json' },
        body: JSON.stringify(runPayload)
      }).then(function (result) {
        createState.externalVerification = result.json;
        createState.externalVerificationOk = result.response.ok;
        persistCreateState();
        showVerificationResult(result.json, result.response.ok);
      }).catch(function (error) { showStatus(error && error.message ? error.message : String(error), false); });
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
      verifyVsdxFile(null);
      return;
    }
    if (action === 'create-objects' || action === 'execute-create-objects') {
      if (externalVerificationBlocksCreation(createState.externalVerification)) {
        showStatus('Последняя внешняя верификация содержит ошибки. Повторите верификацию успешно перед созданием объектов.', false);
        return;
      }
      submitCreateObjects(true);
      return;
    }
    if (action === 'rebuild-create-plan') {
      submitCreateObjects(false);
      return;
    }
    if (action === 'save-contract') {
      if (currentSection === 'prepare-objects') {
        createState.fillMode = 'contract';
        createState.resultView = 'contract';
        submitCreateObjects(false);
        return;
      }
      savePrepareContractOnly();
      return;
    }
    if (action === 'save-template') {
      enrichVsdx();
      return;
    }
    if (action === 'apply-create-contract') {
      createState.fillMode = 'contract';
      createState.resultView = 'contract';
      submitCreateObjects(false);
      return;
    }
    if (action === 'apply-create-manual') {
      createState.fillMode = 'manual';
      createState.resultView = 'manual';
      submitCreateObjects(false);
      return;
    }
    if (action === 'show-create-plan') {
      collectCreateOverrides();
      collectCreateClassRules();
      collectCreateSelection();
      persistCreateState();
      createState.resultView = 'plan';
      renderObjectWorkflow();
      return;
    }
    if (action === 'create-selection-mode') {
      collectCreateSelection();
      createState.selectionMode = button.getAttribute('data-mode') === 'objects' ? 'objects' : 'classes';
      persistCreateState();
      renderObjectWorkflow();
      return;
    }
    if (action === 'fill-create-contract') {
      collectCreateOverrides();
      collectCreateClassRules();
      createState.fillMode = 'contract';
      createState.resultView = 'contract';
      persistCreateState();
      if (createState.lastResult) renderObjectWorkflow();
      else {
        var contractPlan = createObjectsFromVsdxFile(null);
        if (contractPlan && contractPlan.then) contractPlan.then(function () {
          createState.resultView = 'contract';
          renderObjectWorkflow();
        });
      }
      return;
    }
    if (action === 'fill-create-manual') {
      collectCreateOverrides();
      collectCreateClassRules();
      createState.fillMode = 'manual';
      createState.resultView = 'manual';
      persistCreateState();
      if (createState.lastResult) renderObjectWorkflow();
      else {
        var manualPlan = createObjectsFromVsdxFile(null);
        if (manualPlan && manualPlan.then) manualPlan.then(function () {
          createState.resultView = 'manual';
          renderObjectWorkflow();
        });
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
    if (action === 'choose-shared-vsdx') {
      var sharedInput = document.getElementById('shared-vsdx-file');
      if (sharedInput) sharedInput.click();
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
    if (action === 'check-current-template') {
      checkTemplateVsdxFile(null);
      return;
    }
    if (action === 'verify-current-vsdx') {
      verifyVsdxFile(null);
      return;
    }
    if (action === 'build-create-plan') {
      createState.resultView = 'plan';
      createObjectsFromVsdxFile(null);
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
  document.addEventListener('input', function (event) {
    if (!event.target || !(event.target.getAttribute('data-create-override-key') || event.target.getAttribute('data-create-class-rule-key'))) return;
    renderExpressionSuggestions(event.target);
  });
  document.addEventListener('keydown', function (event) {
    if (!expressionSuggestState.element || event.target !== expressionSuggestState.input) return;
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      moveExpressionSuggestion(1);
      return;
    }
    if (event.key === 'ArrowUp') {
      event.preventDefault();
      moveExpressionSuggestion(-1);
      return;
    }
    if (event.key === 'Enter' || event.key === 'Tab') {
      event.preventDefault();
      applyExpressionSuggestion(expressionSuggestState.activeIndex);
      return;
    }
    if (event.key === 'Escape') {
      event.preventDefault();
      closeExpressionSuggestions();
    }
  });
  document.addEventListener('focusin', function (event) {
    if (!event.target) return;
    if (event.target.getAttribute('data-create-override-key') || event.target.getAttribute('data-create-class-rule-key')) return;
    if (event.target.closest && event.target.closest('.expr-suggest')) return;
    closeExpressionSuggestions();
  });
  window.addEventListener('popstate', function () {
    var section = normalizeSection((window.location.pathname || '').slice(UI_PREFIX.length + 1));
    currentSection = section || 'prepare-template';
    render(currentSection);
  });
  document.addEventListener('change', function (event) {
    if (event.target && (event.target.id === 'vsdx-file' || event.target.id === 'checksum-file' || event.target.id === 'shared-vsdx-file')) {
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
      persistCreateState();
      return;
    }
    if (event.target && event.target.getAttribute('data-create-class-rule-key')) {
      createState.classValueRules[event.target.getAttribute('data-create-class-rule-key') || ''] = event.target.value || '';
      persistCreateState();
      return;
    }
    if (event.target && event.target.id === 'create-fill-mode') {
      collectCreateOverrides();
      collectCreateClassRules();
      createState.fillMode = event.target.value === 'manual' ? 'manual' : 'contract';
      renderObjectWorkflow();
      return;
    }
    if (event.target && event.target.id === 'create-selected-plan-index') {
      collectCreateOverrides();
      createState.selectedPlanIndex = Number(event.target.value || 0);
      renderObjectWorkflow();
      return;
    }
    if (event.target && event.target.getAttribute('data-create-class-select')) {
      createState.selectedClasses[event.target.getAttribute('data-create-class-select') || ''] = Boolean(event.target.checked);
      persistCreateState();
      return;
    }
    if (event.target && event.target.getAttribute('data-create-object-select')) {
      createState.selectedPlanIndexes[event.target.getAttribute('data-create-object-select') || ''] = Boolean(event.target.checked);
      persistCreateState();
      return;
    }
    if (event.target && event.target.id === 'verification-endpoint-select') {
      var endpointOption = event.target.options[event.target.selectedIndex];
      if (endpointOption && endpointOption.value) {
        var endpointCode = document.getElementById('verification-endpoint-code');
        var endpointUrl = document.getElementById('verification-endpoint-url');
        var paramsJson = document.getElementById('verification-params-json');
        var endpointStatus = document.getElementById('verification-endpoint-status');
        if (endpointCode) endpointCode.value = endpointOption.getAttribute('data-code') || '';
        if (endpointUrl) endpointUrl.value = endpointOption.getAttribute('data-url') || '';
        if (paramsJson) paramsJson.value = endpointOption.getAttribute('data-params-json') || '{}';
        if (endpointStatus) endpointStatus.value = endpointOption.getAttribute('data-status') || 'Active';
        setResultInterpretationControls(endpointOption.getAttribute('data-result-interpretation-json') || '{}');
        selectVerificationContractByCodeVersion('verification-input-contract', endpointOption.getAttribute('data-input-code') || '', endpointOption.getAttribute('data-input-version') || '');
        selectVerificationContractByCodeVersion('verification-output-contract', endpointOption.getAttribute('data-output-code') || '', endpointOption.getAttribute('data-output-version') || '');
      }
      return;
    }
    if (event.target && (event.target.id === 'settings-checksum-extension' || event.target.id === 'settings-verify-checksum' || event.target.id === 'settings-check-cmdb-validators' || event.target.id === 'settings-reference-limit' || event.target.id === 'settings-verification-input-class' || event.target.id === 'settings-verification-output-class' || event.target.id === 'settings-verification-endpoint-class')) {
      writeSettings({
        checksumExtension: document.getElementById('settings-checksum-extension') && document.getElementById('settings-checksum-extension').value || 'sha256',
        verifyChecksumOnPrepare: Boolean(document.getElementById('settings-verify-checksum') && document.getElementById('settings-verify-checksum').checked),
        checkCmdbValidatorsInSystem: Boolean(document.getElementById('settings-check-cmdb-validators') && document.getElementById('settings-check-cmdb-validators').checked),
        referenceFixedListLimit: document.getElementById('settings-reference-limit') && document.getElementById('settings-reference-limit').value || 50,
        verificationInputContractClass: document.getElementById('settings-verification-input-class') && document.getElementById('settings-verification-input-class').value || 'BAAVerificationInputContract',
        verificationOutputContractClass: document.getElementById('settings-verification-output-class') && document.getElementById('settings-verification-output-class').value || 'BAAVerificationOutputContract',
        verificationEndpointClass: document.getElementById('settings-verification-endpoint-class') && document.getElementById('settings-verification-endpoint-class').value || 'BAAVerificationEndpoint'
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
  hydrateCreateState();
  syncFileStatus();
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
          validation: typeof validation === 'string' ? validation : JSON.stringify(validation || ''),
          rawSource: {
            lookupType: String(item.lookupType || item.lookup || item.lookupName || item._lookupType || ''),
            targetClass: String(item.targetClass || item.target || item.referenceClass || item.destination || ''),
            domain: String(item.domain || item.domainName || item._domain || ''),
            validation
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
  if (requestUrl.pathname === `${API_PREFIX}/verification/contracts/generate`) {
    if (!methodAllowed(req, res, 'POST')) return;
    try {
      const body = await readJsonBody(req);
      const result = await generateVerificationContracts(authToken, body);
      sendJson(res, result.success ? 200 : 422, result);
    } catch (error) {
      sendJson(res, 400, { success: false, message: error && error.message ? error.message : String(error) });
    }
    return;
  }
  if (requestUrl.pathname === `${API_PREFIX}/verification/contracts/list`) {
    if (!methodAllowed(req, res, 'POST')) return;
    try {
      const body = await readJsonBody(req);
      const classes = verificationClassNames(body.settings || {});
      const input = await listVerificationContracts(authToken, classes.input);
      const output = await listVerificationContracts(authToken, classes.output);
      sendJson(res, input.success && output.success ? 200 : 502, {
        success: Boolean(input.success && output.success),
        classes,
        input,
        output
      });
    } catch (error) {
      sendJson(res, 400, { success: false, message: error && error.message ? error.message : String(error) });
    }
    return;
  }
  if (requestUrl.pathname === `${API_PREFIX}/verification/contracts/publish`) {
    if (!methodAllowed(req, res, 'POST')) return;
    try {
      const body = await readJsonBody(req);
      const result = await publishVerificationContracts(authToken, body);
      sendJson(res, result.success ? 200 : 422, result);
    } catch (error) {
      sendJson(res, 400, { success: false, message: error && error.message ? error.message : String(error) });
    }
    return;
  }
  if (requestUrl.pathname === `${API_PREFIX}/verification/endpoints`) {
    if (req.method === 'GET') {
      try {
        const classes = verificationClassNames({});
        const result = await listVerificationEndpoints(authToken, classes.endpoint);
        sendJson(res, result.success ? 200 : 502, result);
      } catch (error) {
        sendJson(res, 400, { success: false, message: error && error.message ? error.message : String(error) });
      }
      return;
    }
    if (!methodAllowed(req, res, 'POST')) return;
    try {
      const body = await readJsonBody(req);
      const classes = verificationClassNames(body.settings || {});
      const endpoint = body.endpoint && typeof body.endpoint === 'object' ? body.endpoint : body;
      const result = await createVerificationEndpoint(authToken, classes.endpoint, { ...endpoint, createdBy: body.createdBy || '' });
      sendJson(res, result.success ? 200 : 422, result);
    } catch (error) {
      sendJson(res, 400, { success: false, message: error && error.message ? error.message : String(error) });
    }
    return;
  }
  if (requestUrl.pathname === `${API_PREFIX}/verification/endpoints/list`) {
    if (!methodAllowed(req, res, 'POST')) return;
    try {
      const body = await readJsonBody(req);
      const classes = verificationClassNames(body.settings || {});
      const result = await listVerificationEndpoints(authToken, classes.endpoint);
      sendJson(res, result.success ? 200 : 502, {
        ...result,
        className: classes.endpoint
      });
    } catch (error) {
      sendJson(res, 400, { success: false, message: error && error.message ? error.message : String(error) });
    }
    return;
  }
  if (requestUrl.pathname === `${API_PREFIX}/verification/run`) {
    if (!methodAllowed(req, res, 'POST')) return;
    try {
      const body = await readJsonBody(req);
      const result = await runExternalVerification(authToken, body);
      sendJson(res, result.success ? 200 : 422, result);
    } catch (error) {
      sendJson(res, 400, { success: false, message: error && error.message ? error.message : String(error) });
    }
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
    const contractOnly = Boolean(body.contractOnly);
    const preparedAt = new Date().toISOString();
    const preparedBy = String(body.preparedBy || '').trim();
    if (!contractOnly && !contractAnchorKey) {
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
      const conversionSchema = conversionSchemaReadiness(schema);
      if (!conversionSchema.ready) {
        sendJson(res, 502, {
          success: false,
          message: 'BAA conversion schema is not ready. Open Settings / Schema and run bootstrap explicitly.',
          schema,
          conversionSchema
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
    if (contractOnly) {
      sendJson(res, 200, {
        success: true,
        contractVersion: publicContractVersion(versionResolution.version),
        versionAction: versionResolution.action,
        addedTypes: versionResolution.addedTypes,
        addedAggregates: versionResolution.addedAggregates,
        addedMappings: versionResolution.addedMappings,
        contractParams: versionResolution.contractParams,
        warnings: listResolution.warnings,
        summary: {
          versionAction: versionResolution.action,
          addedTypes: versionResolution.addedTypes.length,
          knownTypes: versionResolution.knownTypes.length,
          addedAggregates: versionResolution.addedAggregates.length,
          knownAggregates: versionResolution.knownAggregates.length,
          addedMappings: versionResolution.addedMappings.length,
          knownMappings: versionResolution.knownMappings.length,
          contractParams: versionResolution.contractParams.length,
          listWarnings: listResolution.warnings.length
        }
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
    const sourceFilename = String(body.filename || 'template.vsdx').split(/[\\/]/).pop() || 'template.vsdx';
    const filename = /\.vsdx$/i.test(sourceFilename) ? sourceFilename : `${sourceFilename}.vsdx`;
    const checksumExtension = String(settings.checksumExtension || 'sha256').trim().replace(/^\.+/, '') || 'sha256';
    const checksumAlgorithm = checksumAlgorithmFromExtension(checksumExtension);
    const outputChecksum = digestHex(checksumAlgorithm, enriched.buffer);
    const providedChecksumFilename = String(body.checksumFilename || '').split(/[\\/]/).pop();
    const checksumFilename = providedChecksumFilename || `${filename}.${checksumExtension}`;
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
    'function normalize(v){v=String(v||"").toLowerCase();if(v==="schema"||v==="cmdb-schema")return"schema";if(v==="contracts"||v==="contract"||v==="conversion-contracts")return"contracts";if(v==="settings"||v==="config"||v==="configuration")return"settings";if(v==="types"||v==="type-settings"||v==="visio-types")return"types";if(v==="check-template"||v==="template-check"||v==="technical-check")return"check-template";if(v==="prepare-verification"||v==="verification-rules"||v==="verification-prepare")return"prepare-verification";if(v==="verify"||v==="verification")return"verify";if(v==="prepare-objects"||v==="plan-objects"||v==="objects-plan")return"prepare-objects";if(v==="create-objects"||v==="create"||v==="objects")return"create-objects";return"prepare-template";}',
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
