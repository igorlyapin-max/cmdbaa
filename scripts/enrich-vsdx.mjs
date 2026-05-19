import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const fieldsByKind = {
  object: [
    textField('BAA_TypeKey', 'BAA type key', ''),
    textField('BAA_ObjectType', 'BAA object type', ''),
    textField('BAA_ObjectId', 'Existing CMDB object id', ''),
    fixedListField('BAA_Action', 'Action', 'create', ['create', 'update', 'skip']),
    fixedListField('BAA_MatchStatus', 'Match status', 'not_checked', ['not_checked', 'matched', 'not_found', 'ambiguous', 'error']),
    textField('BAA_InstanceKey', 'Instance key', ''),
    textField('CMDB_Class', 'CMDB class', ''),
    textField('CMDB_Name', 'Name', ''),
    fixedListField('CMDB_Location', 'Location', 'MSK', ['', 'MSK', 'SPB', 'NOC']),
    fixedListField('CMDB_LocationFixed', 'Location fixed list', 'MSK', ['', 'MSK', 'SPB', 'NOC']),
    variableListField('CMDB_LocationVariable', 'Location variable list', 'MSK', ['', 'MSK', 'SPB', 'NOC'])
  ],
  connector: [
    textField('BAA_TypeKey', 'BAA type key', ''),
    textField('BAA_ObjectType', 'BAA object type', 'Relation'),
    fixedListField('BAA_Action', 'Action', 'create', ['create', 'update', 'skip']),
    fixedListField('BAA_MatchStatus', 'Match status', 'not_checked', ['not_checked', 'matched', 'not_found', 'ambiguous', 'error']),
    textField('BAA_InstanceKey', 'Instance key', ''),
    textField('BAA_SourceShapeId', 'Source Visio shape id', ''),
    textField('BAA_SourceKind', 'Source shape kind', ''),
    textField('BAA_DestinationShapeId', 'Destination Visio shape id', ''),
    textField('BAA_DestinationKind', 'Destination shape kind', ''),
    fixedListField('BAA_RelationBindingStatus', 'Relation binding status', 'unbound', ['bound', 'unbound', 'partial', 'invalid_endpoint']),
    textField('BAA_ValidationIssue', 'BAA validation issue', ''),
    textField('CMDB_RelationType', 'Relation type', ''),
    textField('CMDB_FromObject', 'From object', ''),
    textField('CMDB_ToObject', 'To object', '')
  ],
  container: [
    textField('BAA_TypeKey', 'BAA type key', ''),
    textField('BAA_ObjectType', 'BAA object type', 'Container'),
    textField('BAA_ObjectId', 'Existing CMDB object id', ''),
    fixedListField('BAA_Action', 'Action', 'create', ['create', 'update', 'skip']),
    fixedListField('BAA_MatchStatus', 'Match status', 'not_checked', ['not_checked', 'matched', 'not_found', 'ambiguous', 'error']),
    textField('BAA_InstanceKey', 'Instance key', ''),
    textField('CMDB_Class', 'CMDB class', ''),
    textField('CMDB_Name', 'Name', ''),
    fixedListField('CMDB_Location', 'Location', 'MSK', ['', 'MSK', 'SPB', 'NOC']),
    fixedListField('CMDB_LocationFixed', 'Location fixed list', 'MSK', ['', 'MSK', 'SPB', 'NOC']),
    variableListField('CMDB_LocationVariable', 'Location variable list', 'MSK', ['', 'MSK', 'SPB', 'NOC'])
  ],
  group: [
    textField('BAA_TypeKey', 'BAA type key', ''),
    textField('BAA_ObjectType', 'BAA object type', 'Visual group'),
    textField('BAA_EligibleForCmdb', 'BAA eligible for CMDB', 'false'),
    textField('BAA_ValidationIssue', 'BAA validation issue', 'group_not_cmdb_object')
  ]
};

const visualContextFields = {
  group: fieldsByKind.group,
  container: [
    textField('BAA_TypeKey', 'BAA type key', ''),
    textField('BAA_ObjectType', 'BAA object type', 'Visual container'),
    textField('BAA_EligibleForCmdb', 'BAA eligible for CMDB', 'false'),
    textField('BAA_ValidationIssue', 'BAA validation issue', 'container_not_enabled_by_contract')
  ]
};

function textField(name, label, value) {
  return { name, label, value, type: '0', format: '' };
}

function fixedListField(name, label, value, values) {
  return { name, label, value, type: '1', format: values.join(';') };
}

function variableListField(name, label, value, values) {
  return { name, label, value, type: '4', format: values.join(';') };
}

function contractMetadataFields(options = {}) {
  const version = options.contractVersion || {};
  if (!version.id || !version.code || !version.rulesChecksum) return [];
  return [
    textField('BAA_TemplatePrepared', 'BAA template prepared', 'true'),
    textField('BAA_ContractVersionId', 'BAA contract version id', version.id),
    textField('BAA_ContractVersionCode', 'BAA contract version code', version.code),
    textField('BAA_ContractVersionChecksum', 'BAA contract version checksum', version.rulesChecksum),
    textField('BAA_PreparedAt', 'BAA prepared at', options.preparedAt || ''),
    textField('BAA_PreparedBy', 'BAA prepared by', options.preparedBy || '')
  ];
}

function xmlAttr(value) {
  return String(value === undefined || value === null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/'/g, '&apos;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function shapeKind(openTag) {
  if (/\bType=['"]Group['"]/.test(openTag)) return 'group';
  if (/\bNameU=['"]Dynamic connector['"]/.test(openTag)) return 'connector';
  return 'object';
}

function attrValue(openTag, name) {
  const match = openTag.match(new RegExp(`\\b${name}=(['"])(.*?)\\1`));
  return match ? match[2] : '';
}

function directShapeText(inner) {
  const nestedShapes = inner.indexOf('<Shapes>');
  const searchArea = nestedShapes === -1 ? inner : inner.slice(0, nestedShapes);
  const textStart = searchArea.indexOf('<Text>');
  if (textStart === -1) return '';
  const textEnd = searchArea.indexOf('</Text>', textStart);
  if (textEnd === -1) return '';
  return decodeXmlText(searchArea.slice(textStart + '<Text>'.length, textEnd)).replace(/\s+/g, ' ').trim();
}

function decodeXmlText(value) {
  return String(value || '')
    .replace(/<[^>]*>/g, '')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&');
}

function typeDetectionRules(options = {}) {
  const rules = options.typeDetection || options.rules && options.rules.typeDetection || options.rules || {};
  const presentation = options.presentation || options.rules && options.rules.presentation || {};
  return {
    useVisibleTextAsTypeFactor: rules.useVisibleTextAsTypeFactor !== false,
    treatGroupsAsTypes: rules.treatGroupsAsTypes !== false,
    groupNameDifferentiatesType: rules.groupNameDifferentiatesType !== false,
    groupCompositionDifferentiatesType: Boolean(rules.groupCompositionDifferentiatesType),
    treatContainersAsTypes: rules.treatContainersAsTypes !== false,
    containerIncludesContent: Boolean(rules.containerIncludesContent),
    keepDecorativeShapesUnchanged: presentation.keepDecorativeShapesUnchanged !== false
  };
}

function shapeObjectName(openTag, masterById = {}, kind = shapeKind(openTag)) {
  const masterId = attrValue(openTag, 'Master');
  const master = masterById[masterId] || {};
  return master.nameU || attrValue(openTag, 'NameU') || kind;
}

function connectorBindingForShape(openTag, options = {}) {
  const shapeId = attrValue(openTag, 'ID');
  const binding = options.connectionsByShapeId && options.connectionsByShapeId[shapeId] || {};
  const shapeIndex = options.shapeIndexById || {};
  const source = binding.sourceShapeId || '';
  const destination = binding.destinationShapeId || '';
  const sourceShape = source ? shapeIndex[source] : null;
  const destinationShape = destination ? shapeIndex[destination] : null;
  const sourceInvalid = Boolean(source && (!sourceShape || !sourceShape.eligibleForCmdb));
  const destinationInvalid = Boolean(destination && (!destinationShape || !destinationShape.eligibleForCmdb));
  let status = 'bound';
  let issue = '';
  if (!source && !destination) {
    status = 'unbound';
    issue = 'relation_not_connected';
  } else if (!source || !destination) {
    status = 'partial';
    issue = !source ? 'relation_source_missing' : 'relation_destination_missing';
  } else if (sourceInvalid || destinationInvalid) {
    status = 'invalid_endpoint';
    issue = sourceInvalid && destinationInvalid
      ? 'relation_endpoints_not_cmdb_objects'
      : sourceInvalid ? 'relation_source_not_cmdb_object' : 'relation_destination_not_cmdb_object';
  }
  return {
    sourceShapeId: source,
    sourceKind: sourceShape && sourceShape.kind || '',
    destinationShapeId: destination,
    destinationKind: destinationShape && destinationShape.kind || '',
    status,
    issue
  };
}

function childCompositionSignature(inner, masterById = {}, rules = {}, depth = 0) {
  if (!inner || depth > 10) return '';
  const signatures = [];
  let cursor = 0;
  while (cursor < inner.length) {
    const start = inner.indexOf('<Shape ', cursor);
    if (start === -1) break;
    const end = findShapeEnd(inner, start);
    if (end === -1) break;
    const block = inner.slice(start, end);
    const openEnd = block.indexOf('>');
    const openTag = openEnd === -1 ? block : block.slice(0, openEnd + 1);
    const shapeInner = block.slice(openEnd + 1, -'</Shape>'.length);
    const visibleText = directShapeText(shapeInner);
    if (shapeKind(openTag) === 'object' && !attrValue(openTag, 'Master') && !attrValue(openTag, 'NameU')) {
      cursor = end;
      continue;
    }
    if (!(rules.keepDecorativeShapesUnchanged && attrValue(openTag, 'MasterShape') && !visibleText)) {
      const type = displayShapeType(openTag, masterById, visibleText, {
        rules,
        inner: shapeInner,
        compositionDepth: depth + 1
      });
      signatures.push(type.typeKey);
    }
    cursor = end;
  }
  return signatures.sort().join(',');
}

function displayShapeType(openTag, masterById = {}, visibleText = '', options = {}) {
  const rules = typeDetectionRules(options);
  const rawKind = shapeKind(openTag);
  const masterId = attrValue(openTag, 'Master');
  const master = masterById[masterId] || {};
  const isContainer = Boolean(master.isContainer);
  const kind = master.isConnector ? 'connector' : isContainer ? 'container' : rawKind;
  const objectName = shapeObjectName(openTag, masterById, kind);
  const shapeName = attrValue(openTag, 'Name') || '';
  const name = rules.useVisibleTextAsTypeFactor && (kind !== 'group' || rules.groupNameDifferentiatesType) ? visibleText || '' : '';
  const parts = [
    kind,
    `master:${masterId || objectName}`,
    `object:${objectName}`,
    `name:${name}`
  ];
  if ((kind === 'group' && rules.groupCompositionDifferentiatesType) || (isContainer && rules.containerIncludesContent)) {
    parts.push(`composition:${childCompositionSignature(options.inner || '', masterById, rules, options.compositionDepth || 0)}`);
  }
  return {
    kind,
    masterId,
    masterNameU: master.nameU || '',
    masterName: master.name || '',
    shapeNameU: objectName,
    shapeName: name,
    visioName: shapeName,
    text: visibleText,
    isContainer,
    eligibleForCmdb: kind === 'container' ? rules.treatContainersAsTypes : kind !== 'group',
    visualRole: kind === 'group' ? 'group' : kind === 'container' && !rules.treatContainersAsTypes ? 'container' : '',
    typeKey: parts.join('|'),
    label: name ? `${objectName} / ${name}` : objectName
  };
}

function fieldsForShape(openTag, options = {}) {
  const type = displayShapeType(openTag, options.masterById || {}, options.visibleText || '', options);
  const shapeId = attrValue(openTag, 'ID') || '';
  const pageShapeKey = options.pageName && shapeId ? `${options.pageName}:${shapeId}` : '';
  const cmdbClass =
    pageShapeKey && options.classByPageShapeId && options.classByPageShapeId[pageShapeKey] ||
    options.classByTypeKey && options.classByTypeKey[type.typeKey] ||
    '';
  const binding = type.kind === 'connector' ? connectorBindingForShape(openTag, options) : null;
  const baseFields = type.eligibleForCmdb ? fieldsByKind[type.kind] : visualContextFields[type.kind] || fieldsByKind[type.kind];
  const shapeFields = baseFields.map((field) => {
    if (field.name === 'BAA_TypeKey') return { ...field, value: type.typeKey };
    if (field.name === 'BAA_ObjectType') return { ...field, value: field.value || type.label };
    if (field.name === 'CMDB_Class') return { ...field, value: cmdbClass };
    if (binding && field.name === 'BAA_SourceShapeId') return { ...field, value: binding.sourceShapeId };
    if (binding && field.name === 'BAA_SourceKind') return { ...field, value: binding.sourceKind };
    if (binding && field.name === 'BAA_DestinationShapeId') return { ...field, value: binding.destinationShapeId };
    if (binding && field.name === 'BAA_DestinationKind') return { ...field, value: binding.destinationKind };
    if (binding && field.name === 'BAA_RelationBindingStatus') return { ...field, value: binding.status };
    if (binding && field.name === 'BAA_ValidationIssue') return { ...field, value: binding.issue };
    if (binding && field.name === 'CMDB_FromObject') return { ...field, value: binding.sourceShapeId };
    if (binding && field.name === 'CMDB_ToObject') return { ...field, value: binding.destinationShapeId };
    return field;
  });
  return shapeFields.concat(contractMetadataFields(options));
}

function rowXml(field) {
  return `<Row N='${xmlAttr(field.name)}'><Cell N='Value' V='${xmlAttr(field.value)}' U='STR'/><Cell N='Prompt' V='' U='STR'/><Cell N='Label' V='${xmlAttr(field.label)}' U='STR'/><Cell N='Format' V='${xmlAttr(field.format)}' U='STR'/><Cell N='SortKey' V='' U='STR'/><Cell N='Type' V='${xmlAttr(field.type)}'/><Cell N='Invisible' V='0'/><Cell N='Verify' V='0'/><Cell N='DataLinked' V='0'/><Cell N='LangID' V='ru-RU' U='STR'/><Cell N='Calendar' V='0'/></Row>`;
}

function propertySectionXml(fields) {
  return `<Section N='Property'>${fields.map(rowXml).join('')}</Section>`;
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function mergePropertySection(existing, fields) {
  let result = existing;
  for (const field of fields) {
    const rowPattern = new RegExp(`<Row\\s+N=['"]${escapeRegExp(field.name)}['"][\\s\\S]*?</Row>`);
    if (rowPattern.test(result)) {
      result = result.replace(rowPattern, rowXml(field));
    } else {
      result = result.replace('</Section>', `${rowXml(field)}</Section>`);
    }
  }
  return result;
}

function cellValue(rowXmlText, name) {
  const cellMatch = rowXmlText.match(new RegExp(`<Cell\\s+N=['"]${escapeRegExp(name)}['"][^>]*>`));
  if (!cellMatch) return '';
  return attrValue(cellMatch[0], 'V');
}

function decodeXmlAttr(value) {
  return String(value || '')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&');
}

function directPropertyRows(inner) {
  const split = splitLeadingShapeContent(inner);
  const propertyStart = split.leading.indexOf("<Section N='Property'");
  if (propertyStart === -1) return [];
  const startTagEnd = split.leading.indexOf('>', propertyStart);
  const propertyEnd = split.leading.indexOf('</Section>', startTagEnd);
  if (propertyEnd === -1) return [];
  const section = split.leading.slice(startTagEnd + 1, propertyEnd);
  return Array.from(section.matchAll(/<Row\b[^>]*>[\s\S]*?<\/Row>/g)).map((match) => {
    const row = match[0];
    const openEnd = row.indexOf('>');
    const openTag = openEnd === -1 ? row : row.slice(0, openEnd + 1);
    return {
      name: decodeXmlAttr(attrValue(openTag, 'N') || attrValue(openTag, 'IX')),
      label: decodeXmlAttr(cellValue(row, 'Label')),
      value: decodeXmlAttr(cellValue(row, 'Value')),
      type: decodeXmlAttr(cellValue(row, 'Type')),
      format: decodeXmlAttr(cellValue(row, 'Format'))
    };
  }).filter((item) => item.name);
}

function findShapeEnd(xml, start) {
  let depth = 0;
  let cursor = start;
  while (cursor < xml.length) {
    const nextOpen = xml.indexOf('<Shape ', cursor);
    const nextClose = xml.indexOf('</Shape>', cursor);
    if (nextClose === -1) return -1;
    if (nextOpen !== -1 && nextOpen < nextClose) {
      depth += 1;
      cursor = xml.indexOf('>', nextOpen);
      if (cursor === -1) return -1;
      cursor += 1;
      continue;
    }
    depth -= 1;
    cursor = nextClose + '</Shape>'.length;
    if (depth === 0) return cursor;
  }
  return -1;
}

function forEachShape(xml, fn) {
  let cursor = 0;
  while (cursor < xml.length) {
    const start = xml.indexOf('<Shape ', cursor);
    if (start === -1) break;
    const end = findShapeEnd(xml, start);
    if (end === -1) break;
    const block = xml.slice(start, end);
    const openEnd = block.indexOf('>');
    const openTag = openEnd === -1 ? block : block.slice(0, openEnd + 1);
    const inner = block.slice(openEnd + 1, -'</Shape>'.length);
    fn({ block, openTag, inner, start, end });
    cursor = end;
  }
}

function parsePageConnections(xml) {
  const result = {};
  const section = xml.match(/<Connects>[\s\S]*?<\/Connects>/);
  if (!section) return result;
  for (const match of section[0].matchAll(/<Connect\b[^>]*\/>/g)) {
    const tag = match[0];
    const fromSheet = attrValue(tag, 'FromSheet');
    const toSheet = attrValue(tag, 'ToSheet');
    const fromCell = attrValue(tag, 'FromCell');
    if (!fromSheet || !toSheet) continue;
    const item = result[fromSheet] || {};
    if (/^Begin/i.test(fromCell)) item.sourceShapeId = toSheet;
    else if (/^End/i.test(fromCell)) item.destinationShapeId = toSheet;
    result[fromSheet] = item;
  }
  return result;
}

function collectShapeIndex(xml, masterById, context = {}) {
  const result = {};
  let cursor = 0;
  while (cursor < xml.length) {
    const start = xml.indexOf('<Shape ', cursor);
    if (start === -1) break;
    const end = findShapeEnd(xml, start);
    if (end === -1) break;
    const block = xml.slice(start, end);
    const openEnd = block.indexOf('>');
    const openTag = openEnd === -1 ? block : block.slice(0, openEnd + 1);
    const inner = block.slice(openEnd + 1, -'</Shape>'.length);
    const shapeId = attrValue(openTag, 'ID');
    const visibleText = directShapeText(inner);
    if (shapeId) {
      const type = displayShapeType(openTag, masterById, visibleText, {
        ...context,
        inner
      });
      result[shapeId] = {
        shapeId,
        kind: type.kind,
        label: type.label,
        typeKey: type.typeKey,
        eligibleForCmdb: type.eligibleForCmdb
      };
    }
    Object.assign(result, collectShapeIndex(inner, masterById, context));
    cursor = end;
  }
  return result;
}

function atomRoleKey(atom, index) {
  return [
    `label:${atom.label || ''}`,
    `kind:${atom.kind || ''}`,
    `master:${atom.masterId || atom.shapeNameU || ''}`,
    `index:${index}`
  ].join('|');
}

function collectAtomicShapes(xml, masterById, pageName, context = {}) {
  const atoms = [];
  const rules = typeDetectionRules(context);
  forEachShape(xml, ({ block, openTag, inner }) => {
    const visibleText = directShapeText(inner);
    const type = displayShapeType(openTag, masterById, visibleText, {
      ...context,
      rules,
      inner
    });
    if (type.kind === 'group' || type.kind === 'container') {
      atoms.push(...collectAtomicShapes(inner, masterById, pageName, context));
      return;
    }
    if (type.kind === 'connector') return;
    const shapeId = attrValue(openTag, 'ID') || '';
    const label = visibleText || type.shapeName || type.masterName || type.shapeNameU || shapeId;
    if (!label) return;
    atoms.push({
      page: pageName,
      shapeId,
      label,
      text: visibleText,
      kind: type.kind,
      masterId: type.masterId,
      masterName: type.masterName,
      masterNameU: type.masterNameU,
      shapeNameU: type.shapeNameU,
      typeKey: type.typeKey,
      shapeData: directPropertyRows(block.slice(openTag.length, -'</Shape>'.length))
    });
  });
  return atoms.map((atom, index) => ({
    ...atom,
    roleKey: atomRoleKey(atom, index)
  }));
}

function aggregateLabelFor(atoms, fallback) {
  const labels = atoms.map((atom) => atom.label).filter(Boolean);
  return labels.length ? labels.join(' / ') : fallback;
}

function aggregateTypeKeyFor(kind, typeKey, atoms) {
  return [
    `aggregate:${kind}`,
    typeKey,
    `atoms:${atoms.map((atom) => atom.roleKey).join(';')}`
  ].join('|');
}

function addAggregate(result, aggregate, instance) {
  const existing = result.get(aggregate.aggregateTypeKey) || {
    aggregateTypeKey: aggregate.aggregateTypeKey,
    kind: aggregate.kind,
    label: aggregate.label,
    typeKey: aggregate.typeKey,
    atomRoles: aggregate.atomRoles,
    instances: []
  };
  existing.instances.push(instance);
  result.set(aggregate.aggregateTypeKey, existing);
}

function inspectAggregatesInXml(xml, masterById, pageName, result, context = {}) {
  const rules = typeDetectionRules(context);
  forEachShape(xml, ({ openTag, inner }) => {
    const visibleText = directShapeText(inner);
    const type = displayShapeType(openTag, masterById, visibleText, {
      ...context,
      rules,
      inner
    });
    const shapeId = attrValue(openTag, 'ID') || '';
    if (type.kind === 'group' || type.kind === 'container') {
      const atoms = collectAtomicShapes(inner, masterById, pageName, context);
      if (atoms.length) {
        const aggregateTypeKey = aggregateTypeKeyFor(type.kind, type.typeKey, atoms);
        addAggregate(result, {
          aggregateTypeKey,
          kind: type.kind,
          label: aggregateLabelFor(atoms, type.label),
          typeKey: type.typeKey,
          atomRoles: atoms.map((atom) => ({
            roleKey: atom.roleKey,
            label: atom.label,
            kind: atom.kind,
            typeKey: atom.typeKey,
            masterId: atom.masterId,
            shapeNameU: atom.shapeNameU
          }))
        }, {
          page: pageName,
          aggregateShapeId: shapeId,
          label: type.label,
          atoms
        });
      }
      inspectAggregatesInXml(inner, masterById, pageName, result, {
        ...context,
        insideAggregate: true
      });
      return;
    }
    if (context.insideAggregate || type.kind === 'connector') return;
    const atoms = collectAtomicShapes(`${openTag}${inner}</Shape>`, masterById, pageName, context);
    if (!atoms.length) return;
    const aggregateTypeKey = aggregateTypeKeyFor('single', atoms[0].typeKey, atoms);
    addAggregate(result, {
      aggregateTypeKey,
      kind: 'single',
      label: atoms[0].label,
      typeKey: atoms[0].typeKey,
      atomRoles: atoms.map((atom) => ({
        roleKey: atom.roleKey,
        label: atom.label,
        kind: atom.kind,
        typeKey: atom.typeKey,
        masterId: atom.masterId,
        shapeNameU: atom.shapeNameU
      }))
    }, {
      page: pageName,
      aggregateShapeId: shapeId,
      label: atoms[0].label,
      atoms
    });
  });
}

function enrichShapes(xml, options = {}) {
  let outputXml = '';
  let cursor = 0;
  while (cursor < xml.length) {
    const start = xml.indexOf('<Shape ', cursor);
    if (start === -1) {
      outputXml += xml.slice(cursor);
      break;
    }
    outputXml += xml.slice(cursor, start);
    const end = findShapeEnd(xml, start);
    if (end === -1) {
      outputXml += xml.slice(start);
      break;
    }
    outputXml += enrichShapeBlock(xml.slice(start, end), options);
    cursor = end;
  }
  return outputXml;
}

function splitLeadingShapeContent(inner) {
  const nestedShapes = inner.indexOf('<Shapes>');
  const text = inner.indexOf('<Text>');
  const data = inner.indexOf('<Data');
  const options = [nestedShapes, text, data].filter((value) => value !== -1);
  const splitAt = options.length ? Math.min(...options) : inner.length;
  return {
    leading: inner.slice(0, splitAt),
    rest: inner.slice(splitAt)
  };
}

function enrichLeadingProperty(leading, fields) {
  const propertyStart = leading.indexOf("<Section N='Property'");
  if (propertyStart === -1) return `${leading}${propertySectionXml(fields)}`;
  const startTagEnd = leading.indexOf('>', propertyStart);
  const propertyEnd = leading.indexOf('</Section>', startTagEnd);
  if (propertyEnd === -1) return `${leading}${propertySectionXml(fields)}`;
  const end = propertyEnd + '</Section>'.length;
  return `${leading.slice(0, propertyStart)}${mergePropertySection(leading.slice(propertyStart, end), fields)}${leading.slice(end)}`;
}

function enrichShapeBlock(block, options = {}) {
  const openEnd = block.indexOf('>');
  if (openEnd === -1) return block;
  const openTag = block.slice(0, openEnd + 1);
  const inner = block.slice(openEnd + 1, -'</Shape>'.length);
  const fields = fieldsForShape(openTag, {
    ...options,
    visibleText: directShapeText(inner),
    inner
  });
  const split = splitLeadingShapeContent(inner);
  return `${openTag}${enrichLeadingProperty(split.leading, fields)}${enrichShapes(split.rest, options)}</Shape>`;
}

function parseMastersXml(xml) {
  const masters = {};
  for (const match of xml.matchAll(/<Master\b[^>]*>[\s\S]*?<\/Master>/g)) {
    const block = match[0];
    const tagEnd = block.indexOf('>');
    const tag = tagEnd === -1 ? block : block.slice(0, tagEnd + 1);
    const id = attrValue(tag, 'ID');
    if (!id) continue;
    masters[id] = {
      id,
      nameU: attrValue(tag, 'NameU'),
      name: attrValue(tag, 'Name'),
      masterType: attrValue(tag, 'MasterType'),
      isContainer: attrValue(tag, 'MasterType') === '34' || /NameUniv=['"]Container['"]/.test(block),
      isConnector: attrValue(tag, 'MasterType') === '541' || attrValue(tag, 'MasterType') === '8197' || /NameUniv=['"]Connector['"]/.test(block)
    };
  }
  return masters;
}

function inspectShapes(xml, masterById, pageName, result, context = {}) {
  const rules = typeDetectionRules(context);
  let cursor = 0;
  while (cursor < xml.length) {
    const start = xml.indexOf('<Shape ', cursor);
    if (start === -1) break;
    const end = findShapeEnd(xml, start);
    if (end === -1) break;
    const block = xml.slice(start, end);
    const openEnd = block.indexOf('>');
    const openTag = openEnd === -1 ? block : block.slice(0, openEnd + 1);
    const inner = block.slice(openEnd + 1, -'</Shape>'.length);
    const visibleText = directShapeText(inner);
    const master = masterById[attrValue(openTag, 'Master')] || {};
    const isContainerRoot = Boolean(master.isContainer);
    const parentIsContainerRoot = Boolean(context.insideContainerRoot);
    if (rules.keepDecorativeShapesUnchanged && attrValue(openTag, 'MasterShape') && !visibleText) {
      inspectShapes(inner, masterById, pageName, result, {
        ...context,
        insideContainerRoot: parentIsContainerRoot || isContainerRoot
      });
      cursor = end;
      continue;
    }
    if (rules.keepDecorativeShapesUnchanged && parentIsContainerRoot && attrValue(openTag, 'MasterShape') && !visibleText) {
      inspectShapes(inner, masterById, pageName, result, {
        ...context,
        insideContainerRoot: true
      });
      cursor = end;
      continue;
    }
    if (shapeKind(openTag) === 'object' && !attrValue(openTag, 'Master') && !attrValue(openTag, 'NameU')) {
      inspectShapes(inner, masterById, pageName, result, {
        ...context,
        insideContainerRoot: parentIsContainerRoot || isContainerRoot
      });
      cursor = end;
      continue;
    }
    const type = displayShapeType(openTag, masterById, visibleText, {
      ...context,
      rules,
      inner
    });
    const connection = type.kind === 'connector' ? connectorBindingForShape(openTag, context) : null;
    const shapeContextPath = context.contextPath || [];
    const includeType = type.kind !== 'group' || rules.treatGroupsAsTypes;
    if (includeType) {
      const existing = result.get(type.typeKey) || {
        ...type,
        count: 0,
        pages: new Set(),
        examples: []
      };
      existing.count += 1;
      existing.pages.add(pageName);
      existing.examples.push({
        page: pageName,
        shapeId: attrValue(openTag, 'ID'),
        nameU: attrValue(openTag, 'NameU') || '',
        name: attrValue(openTag, 'Name') || '',
        text: visibleText,
        kind: type.kind,
        eligibleForCmdb: type.eligibleForCmdb,
        visualRole: type.visualRole,
        contextPath: shapeContextPath,
        connection,
        shapeData: directPropertyRows(block.slice(openEnd + 1, -'</Shape>'.length))
      });
      for (const row of directPropertyRows(block.slice(openEnd + 1, -'</Shape>'.length))) {
        existing.shapeData = existing.shapeData || [];
        if (!existing.shapeData.some((item) => item.name === row.name)) existing.shapeData.push(row);
      }
      result.set(type.typeKey, existing);
    }
    inspectShapes(inner, masterById, pageName, result, {
      ...context,
      insideContainerRoot: parentIsContainerRoot || isContainerRoot,
      contextPath: (type.kind === 'group' || type.kind === 'container')
        ? shapeContextPath.concat([{
          kind: type.kind,
          shapeId: attrValue(openTag, 'ID') || '',
          label: type.label,
          typeKey: type.typeKey
        }])
        : shapeContextPath
    });
    cursor = end;
  }
}

function withUnpackedVsdx(inputFile, fn) {
  const workRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'cmdbaa-vsdx-'));
  try {
    execFileSync('unzip', ['-q', path.resolve(inputFile), '-d', workRoot], { stdio: 'inherit' });
    return fn(workRoot);
  } finally {
    fs.rmSync(workRoot, { recursive: true, force: true });
  }
}

function pageFilesIn(workRoot) {
  const pagesDir = path.join(workRoot, 'visio', 'pages');
  return fs.readdirSync(pagesDir)
    .filter((name) => /^page\d+\.xml$/i.test(name))
    .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
}

function inspectVsdxFile(inputFile, options = {}) {
  return withUnpackedVsdx(inputFile, (workRoot) => {
    const masterById = parseMastersXml(fs.readFileSync(path.join(workRoot, 'visio', 'masters', 'masters.xml'), 'utf8'));
    const pagesDir = path.join(workRoot, 'visio', 'pages');
    const result = new Map();
    for (const fileName of pageFilesIn(workRoot)) {
      const pageXml = fs.readFileSync(path.join(pagesDir, fileName), 'utf8');
      const rules = options.rules || {};
      inspectShapes(pageXml, masterById, fileName, result, {
        rules,
        connectionsByShapeId: parsePageConnections(pageXml),
        shapeIndexById: collectShapeIndex(pageXml, masterById, { rules })
      });
    }
    return Array.from(result.values()).map((item) => ({
      ...item,
      shapeData: item.shapeData || [],
      pages: Array.from(item.pages).sort()
    })).sort((a, b) => a.label.localeCompare(b.label) || a.typeKey.localeCompare(b.typeKey));
  });
}

function inspectVsdxAggregates(inputFile, options = {}) {
  return withUnpackedVsdx(inputFile, (workRoot) => {
    const masterById = parseMastersXml(fs.readFileSync(path.join(workRoot, 'visio', 'masters', 'masters.xml'), 'utf8'));
    const pagesDir = path.join(workRoot, 'visio', 'pages');
    const result = new Map();
    for (const fileName of pageFilesIn(workRoot)) {
      const pageXml = fs.readFileSync(path.join(pagesDir, fileName), 'utf8');
      const rules = options.rules || {};
      inspectAggregatesInXml(pageXml, masterById, fileName, result, { rules });
    }
    return Array.from(result.values()).sort((a, b) => a.label.localeCompare(b.label) || a.aggregateTypeKey.localeCompare(b.aggregateTypeKey));
  });
}

function inspectVsdxContractMetadata(inputFile) {
  return withUnpackedVsdx(inputFile, (workRoot) => {
    const pagesDir = path.join(workRoot, 'visio', 'pages');
    const metadata = {};
    for (const fileName of pageFilesIn(workRoot)) {
      const xml = fs.readFileSync(path.join(pagesDir, fileName), 'utf8');
      let cursor = 0;
      while (cursor < xml.length) {
        const start = xml.indexOf('<Shape ', cursor);
        if (start === -1) break;
        const end = findShapeEnd(xml, start);
        if (end === -1) break;
        const block = xml.slice(start, end);
        const openEnd = block.indexOf('>');
        for (const row of directPropertyRows(block.slice(openEnd + 1, -'</Shape>'.length))) {
          if (row.name === 'BAA_ContractVersionId' && row.value) metadata.contractVersionId = row.value;
          if (row.name === 'BAA_ContractVersionCode' && row.value) metadata.contractVersionCode = row.value;
          if (row.name === 'BAA_ContractVersionChecksum' && row.value) metadata.contractVersionChecksum = row.value;
          if (row.name === 'BAA_PreparedAt' && row.value) metadata.preparedAt = row.value;
        }
        if (metadata.contractVersionId || metadata.contractVersionCode || metadata.contractVersionChecksum) return metadata;
        cursor = end;
      }
    }
    return metadata;
  });
}

function enrichVsdxFile(inputFile, outputFile, options = {}) {
  return withUnpackedVsdx(inputFile, (workRoot) => {
    const masterById = parseMastersXml(fs.readFileSync(path.join(workRoot, 'visio', 'masters', 'masters.xml'), 'utf8'));
    const pagesDir = path.join(workRoot, 'visio', 'pages');
    const pageFiles = pageFilesIn(workRoot);
  for (const fileName of pageFiles) {
    const filePath = path.join(pagesDir, fileName);
    const original = fs.readFileSync(filePath, 'utf8');
      const rules = options.rules || {};
      const pageContext = {
        masterById,
        pageName: fileName,
        classByTypeKey: options.classByTypeKey || {},
        classByPageShapeId: options.classByPageShapeId || {},
        rules,
        connectionsByShapeId: parsePageConnections(original),
        shapeIndexById: collectShapeIndex(original, masterById, { rules }),
        contractVersion: options.contractVersion || null,
        preparedAt: options.preparedAt || '',
        preparedBy: options.preparedBy || ''
      };
      fs.writeFileSync(filePath, enrichShapes(original, {
        ...pageContext
      }));
  }
    fs.rmSync(path.resolve(outputFile), { force: true });
    execFileSync('zip', ['-qr', path.resolve(outputFile), '.'], { cwd: workRoot, stdio: 'inherit' });
  return pageFiles.length;
  });
}

const isMainModule = process.argv[1] && import.meta.url === new URL(`file://${path.resolve(process.argv[1])}`).href;

if (isMainModule) {
  const input = process.argv[2] || '1.vsdx';
  const output = process.argv[3] || input.replace(/\.vsdx$/i, '.enriched.vsdx');
  const pages = enrichVsdxFile(input, output);
  process.stdout.write(JSON.stringify({
    success: true,
    input,
    output,
    pages,
    enrichedFields: {
      object: fieldsByKind.object.map((field) => field.name),
      connector: fieldsByKind.connector.map((field) => field.name),
      container: fieldsByKind.container.map((field) => field.name),
      group: fieldsByKind.group.map((field) => field.name)
    }
  }, null, 2) + '\n');
}

export {
  enrichVsdxFile,
  inspectVsdxFile,
  inspectVsdxAggregates,
  inspectVsdxContractMetadata
};
