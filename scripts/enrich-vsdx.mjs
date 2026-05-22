import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const fieldsByKind = {
  object: [
    textField('_baa_TypeKey', 'BAA type key', ''),
    textField('_baa_ObjectType', 'BAA object type', ''),
    textField('_baa_ObjectId', 'Existing CMDB object id', ''),
    fixedListField('_baa_Action', 'Action', 'create', ['create', 'update', 'skip']),
    fixedListField('_baa_MatchStatus', 'Match status', 'not_checked', ['not_checked', 'matched', 'not_found', 'ambiguous', 'error']),
    textField('_baa_InstanceKey', 'Instance key', ''),
    textField('_baa_VisualObjectId', 'BAA visual object id', ''),
    textField('_baa_AnchorShapeId', 'BAA anchor shape id', ''),
    textField('_baa_AggregationKind', 'BAA aggregation kind', ''),
    fixedListField('_baa_Decomposed', 'BAA decomposed aggregate', 'false', ['true', 'false']),
    textField('_baa_RoleKey', 'BAA role key', ''),
    textField('_baa_MappingKey', 'BAA mapping key', ''),
    textField('_baa_CmdbEntitySlot', 'BAA CMDB entity slot', ''),
    textField('template_Class', 'CMDB class', ''),
    textField('template_Name', 'Name', ''),
    fixedListField('template_Location', 'Location', 'MSK', ['', 'MSK', 'SPB', 'NOC']),
    fixedListField('template_LocationFixed', 'Location fixed list', 'MSK', ['', 'MSK', 'SPB', 'NOC']),
    variableListField('template_LocationVariable', 'Location variable list', 'MSK', ['', 'MSK', 'SPB', 'NOC'])
  ],
  connector: [
    textField('_baa_TypeKey', 'BAA type key', ''),
    textField('_baa_ObjectType', 'BAA object type', 'Relation'),
    fixedListField('_baa_Action', 'Action', 'create', ['create', 'update', 'skip']),
    fixedListField('_baa_MatchStatus', 'Match status', 'not_checked', ['not_checked', 'matched', 'not_found', 'ambiguous', 'error']),
    textField('_baa_InstanceKey', 'Instance key', ''),
    textField('_baa_VisualObjectId', 'BAA visual object id', ''),
    textField('_baa_AnchorShapeId', 'BAA anchor shape id', ''),
    textField('_baa_AggregationKind', 'BAA aggregation kind', ''),
    fixedListField('_baa_Decomposed', 'BAA decomposed aggregate', 'true', ['true', 'false']),
    textField('_baa_RoleKey', 'BAA role key', ''),
    textField('_baa_MappingKey', 'BAA mapping key', ''),
    textField('_baa_CmdbEntitySlot', 'BAA CMDB entity slot', ''),
    textField('_baa_SourceShapeId', 'Source Visio shape id', ''),
    textField('_baa_SourceKind', 'Source shape kind', ''),
    textField('_baa_SourceText', 'Source user text', ''),
    textField('_baa_SourceObjectType', 'Source object type', ''),
    textField('_baa_DestinationShapeId', 'Destination Visio shape id', ''),
    textField('_baa_DestinationKind', 'Destination shape kind', ''),
    textField('_baa_DestinationText', 'Destination user text', ''),
    textField('_baa_DestinationObjectType', 'Destination object type', ''),
    fixedListField('_baa_RelationBindingStatus', 'Relation binding status', 'unbound', ['bound', 'unbound', 'partial', 'invalid_endpoint']),
    textField('_baa_ValidationIssue', 'BAA validation issue', ''),
    textField('template_Class', 'CMDB class', '')
  ],
  container: [
    textField('_baa_TypeKey', 'BAA type key', ''),
    textField('_baa_ObjectType', 'BAA object type', 'Container'),
    textField('_baa_ObjectId', 'Existing CMDB object id', ''),
    fixedListField('_baa_Action', 'Action', 'create', ['create', 'update', 'skip']),
    fixedListField('_baa_MatchStatus', 'Match status', 'not_checked', ['not_checked', 'matched', 'not_found', 'ambiguous', 'error']),
    textField('_baa_InstanceKey', 'Instance key', ''),
    textField('_baa_VisualObjectId', 'BAA visual object id', ''),
    textField('_baa_AnchorShapeId', 'BAA anchor shape id', ''),
    textField('_baa_AggregationKind', 'BAA aggregation kind', ''),
    fixedListField('_baa_Decomposed', 'BAA decomposed aggregate', 'false', ['true', 'false']),
    textField('_baa_RoleKey', 'BAA role key', ''),
    textField('_baa_MappingKey', 'BAA mapping key', ''),
    textField('_baa_CmdbEntitySlot', 'BAA CMDB entity slot', ''),
    textField('template_Class', 'CMDB class', ''),
    textField('template_Name', 'Name', ''),
    fixedListField('template_Location', 'Location', 'MSK', ['', 'MSK', 'SPB', 'NOC']),
    fixedListField('template_LocationFixed', 'Location fixed list', 'MSK', ['', 'MSK', 'SPB', 'NOC']),
    variableListField('template_LocationVariable', 'Location variable list', 'MSK', ['', 'MSK', 'SPB', 'NOC'])
  ],
  group: [
    textField('_baa_TypeKey', 'BAA type key', ''),
    textField('_baa_ObjectType', 'BAA object type', 'Visual group'),
    textField('_baa_VisualObjectId', 'BAA visual object id', ''),
    textField('_baa_AnchorShapeId', 'BAA anchor shape id', ''),
    textField('_baa_AggregationKind', 'BAA aggregation kind', ''),
    fixedListField('_baa_Decomposed', 'BAA decomposed aggregate', 'false', ['true', 'false']),
    textField('_baa_RoleKey', 'BAA role key', ''),
    textField('_baa_MappingKey', 'BAA mapping key', ''),
    textField('_baa_CmdbEntitySlot', 'BAA CMDB entity slot', ''),
    textField('_baa_EligibleForCmdb', 'BAA eligible for CMDB', 'false'),
    textField('_baa_ValidationIssue', 'BAA validation issue', 'group_not_cmdb_object'),
    textField('template_Class', 'CMDB class', '')
  ]
};

const EMPTY_USER_VALUE_LABEL = '[пустое значение]';

const visualContextFields = {
  group: fieldsByKind.group,
  container: [
    textField('_baa_TypeKey', 'BAA type key', ''),
    textField('_baa_ObjectType', 'BAA object type', 'Visual container'),
    textField('_baa_EligibleForCmdb', 'BAA eligible for CMDB', 'false'),
    textField('_baa_ValidationIssue', 'BAA validation issue', 'container_not_enabled_by_contract')
  ]
};

function textField(name, label, value) {
  return shapeDataField(name, label, value, '0', '');
}

function fixedListField(name, label, value, values) {
  return shapeDataField(name, label, value, '1', values.join(';'));
}

function variableListField(name, label, value, values) {
  return shapeDataField(name, label, value, '4', values.join(';'));
}

function visibleShapeDataLabel(name, label) {
  const rowName = String(name || '');
  if (rowName.startsWith('_baa_')) return rowName;
  if (rowName.startsWith('template_')) {
    const text = String(label || '').trim();
    return text && text !== rowName ? `${rowName} / ${text}` : rowName;
  }
  return label;
}

function shapeDataField(name, label, value, type, format) {
  const rowName = String(name || '');
  return {
    name: rowName,
    label: visibleShapeDataLabel(rowName, label),
    value,
    type,
    format,
    invisible: rowName.startsWith('_baa_')
  };
}

function safeShapeDataRowName(value, fallback = 'Rule') {
  const raw = String(value || fallback);
  const normalized = raw
    .replace(/[^A-Za-z0-9_]/g, '_')
    .replace(/_+/g, '_')
    .slice(0, 120);
  if (/^_baa_/i.test(raw)) return normalized.startsWith('_') ? normalized || fallback : `_${normalized}`.slice(0, 120);
  return normalized.replace(/^_+/, '').slice(0, 120) || fallback;
}

function contractMetadataFields(options = {}) {
  const version = options.contractVersion || {};
  if (!version.id || !version.code || !version.rulesChecksum) return [];
  return [
    textField('_baa_TemplatePrepared', 'BAA template prepared', 'true'),
    textField('_baa_ContractVersionId', 'BAA contract version id', version.id),
    textField('_baa_ContractVersionCode', 'BAA contract version code', version.code),
    textField('_baa_ContractVersionChecksum', 'BAA contract version checksum', version.rulesChecksum),
    textField('_baa_ContractObject', 'BAA contract object', 'true'),
    textField('_baa_PreparedAt', 'BAA prepared at', options.preparedAt || ''),
    textField('_baa_PreparedBy', 'BAA prepared by', options.preparedBy || '')
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
  return directShapeTextInfo(inner).value;
}

function firstNestedShapeText(inner) {
  let cursor = 0;
  while (cursor < inner.length) {
    const start = inner.indexOf('<Text>', cursor);
    if (start === -1) return '';
    const end = inner.indexOf('</Text>', start);
    if (end === -1) return '';
    const value = decodeXmlText(inner.slice(start + '<Text>'.length, end)).replace(/\s+/g, ' ').trim();
    if (value) return value;
    cursor = end + '</Text>'.length;
  }
  return '';
}

function directShapeTextInfo(inner) {
  const nestedShapes = inner.indexOf('<Shapes>');
  const searchArea = nestedShapes === -1 ? inner : inner.slice(0, nestedShapes);
  const textStart = searchArea.indexOf('<Text>');
  if (textStart === -1) {
    return {
      exists: false,
      value: ''
    };
  }
  const textEnd = searchArea.indexOf('</Text>', textStart);
  if (textEnd === -1) {
    return {
      exists: false,
      value: ''
    };
  }
  return {
    exists: true,
    value: decodeXmlText(searchArea.slice(textStart + '<Text>'.length, textEnd)).replace(/\s+/g, ' ').trim()
  };
}

function userValueSource(pageName, shapeId, textInfo, valueName = 'Text') {
  if (!textInfo || !textInfo.exists) return null;
  return {
    name: valueName,
    path: `visio/pages/${pageName} / Shape[@ID='${shapeId}'] / Text`,
    value: textInfo.value
  };
}

function aggregationContextFor(type, pageName, shapeId, textInfo) {
  return {
    kind: type.kind,
    shapeId,
    page: pageName,
    label: type.textExists ? type.text || EMPTY_USER_VALUE_LABEL : type.label,
    text: type.text || '',
    textExists: Boolean(type.textExists),
    typeKey: type.typeKey,
    userValueSource: userValueSource(pageName, shapeId, textInfo)
  };
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
  const sourceInvalid = Boolean(source && !sourceShape);
  const destinationInvalid = Boolean(destination && !destinationShape);
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
    sourceText: sourceShape && (sourceShape.text || sourceShape.label) || '',
    sourceObjectType: sourceShape && sourceShape.label || '',
    destinationShapeId: destination,
    destinationKind: destinationShape && destinationShape.kind || '',
    destinationText: destinationShape && (destinationShape.text || destinationShape.label) || '',
    destinationObjectType: destinationShape && destinationShape.label || '',
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
    const shapeInner = /\/>$/.test(openTag) ? '' : block.slice(openEnd + 1, -'</Shape>'.length);
    const textInfo = directShapeTextInfo(shapeInner);
    const visibleText = textInfo.value;
    if (shapeKind(openTag) === 'object' && !attrValue(openTag, 'Master') && !attrValue(openTag, 'NameU')) {
      cursor = end;
      continue;
    }
    if (!(rules.keepDecorativeShapesUnchanged && attrValue(openTag, 'MasterShape') && !visibleText)) {
      const type = displayShapeType(openTag, masterById, visibleText, {
        rules,
        textExists: textInfo.exists,
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
  const textExists = Object.prototype.hasOwnProperty.call(options, 'textExists') ? Boolean(options.textExists) : Boolean(visibleText);
  const userTypeName = textExists ? visibleText || EMPTY_USER_VALUE_LABEL : '';
  const name = rules.useVisibleTextAsTypeFactor && (kind !== 'group' || rules.groupNameDifferentiatesType) ? userTypeName : '';
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
    textExists,
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
  const metadata = pageShapeKey && options.metadataByPageShapeId && options.metadataByPageShapeId[pageShapeKey] || {};
  const binding = type.kind === 'connector' ? connectorBindingForShape(openTag, options) : null;
  const baseFields = type.eligibleForCmdb ? fieldsByKind[type.kind] : visualContextFields[type.kind] || fieldsByKind[type.kind];
  const shapeFields = baseFields.map((field) => {
    if (field.name === '_baa_TypeKey') return { ...field, value: type.typeKey };
    if (field.name === '_baa_ObjectType') return { ...field, value: field.value || type.label };
    if (field.name === '_baa_VisualObjectId') return { ...field, value: metadata.visualObjectId || '' };
    if (field.name === '_baa_AnchorShapeId') return { ...field, value: metadata.anchorShapeId || '' };
    if (field.name === '_baa_AggregationKind') return { ...field, value: metadata.aggregationKind || '' };
    if (field.name === '_baa_Decomposed') return { ...field, value: metadata.decomposed || field.value || '' };
    if (field.name === '_baa_RoleKey') return { ...field, value: metadata.roleKey || '' };
    if (field.name === '_baa_MappingKey') return { ...field, value: metadata.mappingKey || '' };
    if (field.name === '_baa_CmdbEntitySlot') return { ...field, value: metadata.cmdbEntitySlot || '' };
    if (field.name === 'template_Class') return { ...field, value: cmdbClass };
    if (binding && field.name === '_baa_SourceShapeId') return { ...field, value: binding.sourceShapeId };
    if (binding && field.name === '_baa_SourceKind') return { ...field, value: binding.sourceKind };
    if (binding && field.name === '_baa_SourceText') return { ...field, value: binding.sourceText };
    if (binding && field.name === '_baa_SourceObjectType') return { ...field, value: binding.sourceObjectType };
    if (binding && field.name === '_baa_DestinationShapeId') return { ...field, value: binding.destinationShapeId };
    if (binding && field.name === '_baa_DestinationKind') return { ...field, value: binding.destinationKind };
    if (binding && field.name === '_baa_DestinationText') return { ...field, value: binding.destinationText };
    if (binding && field.name === '_baa_DestinationObjectType') return { ...field, value: binding.destinationObjectType };
    if (binding && field.name === '_baa_RelationBindingStatus') return { ...field, value: binding.status };
    if (binding && field.name === '_baa_ValidationIssue') return { ...field, value: binding.issue };
    return field;
  });
  const contractFields = !options.contractPageShapeKey || options.contractPageShapeKey === pageShapeKey
    ? contractMetadataFields(options)
    : [];
  return shapeFields.concat(cmdbAttributeFields(metadata), contractFields);
}

function cmdbAttributeFields(metadata = {}) {
  const fields = Array.isArray(metadata.cmdbAttributeFields) ? metadata.cmdbAttributeFields : [];
  const result = [];
  for (const field of fields) {
    const values = Array.isArray(field.listValues) ? field.listValues : [];
    const label = field.label || [field.className, field.attrName].filter(Boolean).join(' / ') || 'CMDB attribute';
    const sourceRule = field.sourceRule || {
      targetClass: field.className || '',
      targetAttribute: field.attrName || '',
      sourceRole: 'self',
      sourceAttribute: field.attrName || '',
      mode: 'copy'
    };
    const sourceRole = String(sourceRule.sourceRole || 'self');
    const mode = String(sourceRule.mode || 'copy');
    const ruleRowName = safeShapeDataRowName(`_baa_AttributeRule_${field.className || ''}_${field.attrName || field.rowName || ''}`, '_baa_AttributeRule');
    result.push(textField(ruleRowName, ruleRowName, JSON.stringify({
      targetClass: sourceRule.targetClass || field.className || '',
      targetAttribute: sourceRule.targetAttribute || field.attrName || '',
      sourceRole,
      sourceAttribute: sourceRule.sourceAttribute || field.attrName || '',
      mode,
      constantValue: sourceRule.constantValue || '',
      defaultValue: sourceRule.defaultValue || '',
      overrideAttribute: sourceRule.overrideAttribute || '',
      inherited: Boolean(field.inherited),
      rowName: field.rowName || 'template_Attribute'
    })));
    if (sourceRole === 'source' || sourceRole === 'destination' || mode === 'constant') continue;
    if (field.listMode === 'fixed' && values.length) {
      result.push(fixedListField(field.rowName || 'template_Attribute', label, '', [''].concat(values)));
      continue;
    }
    if (field.listMode === 'variable' && values.length) {
      result.push(variableListField(field.rowName || 'template_Attribute', label, '', [''].concat(values)));
      continue;
    }
    result.push(textField(field.rowName || 'template_Attribute', label, ''));
  }
  return result;
}

function rowXml(field) {
  const invisibleCell = field.invisible ? "<Cell N='Invisible' V='1' F='TRUE'/>" : "<Cell N='Invisible' V='0'/>";
  const value = String(field.value || '');
  const valueFormula = visioStringFormula(value);
  return `<Row N='${xmlAttr(field.name)}'><Cell N='Value' V='${xmlAttr(value)}' F='${xmlAttr(valueFormula)}' U='STR'/><Cell N='Prompt' V='' U='STR'/><Cell N='Label' V='${xmlAttr(field.label)}' U='STR'/><Cell N='Format' V='${xmlAttr(field.format)}' U='STR'/><Cell N='SortKey' V='' U='STR'/><Cell N='Type' V='${xmlAttr(field.type)}'/>${invisibleCell}<Cell N='Verify' V='0'/><Cell N='DataLinked' V='0'/><Cell N='LangID' V='ru-RU' U='STR'/><Cell N='Calendar' V='0'/></Row>`;
}

function propertySectionXml(fields) {
  return `<Section N='Property'>${fields.map(rowXml).join('')}</Section>`;
}

function visioStringFormula(value) {
  return `"${String(value || '').replace(/"/g, '""')}"`;
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function mergePropertySection(existing, fields) {
  let result = existing
    .replace(/<Row\s+N=(['"])_?baa_[\s\S]*?<\/Row>/gi, '')
    .replace(/<Row\s+N=(['"])BAA_[\s\S]*?<\/Row>/g, '')
    .replace(/<Row\s+N=(['"])CMDB_[\s\S]*?<\/Row>/g, '')
    .replace(/<Row\s+N=(['"])template_RelationType\1[\s\S]*?<\/Row>/g, '')
    .replace(/<Row\s+N=(['"])template_FromObject\1[\s\S]*?<\/Row>/g, '')
    .replace(/<Row\s+N=(['"])template_ToObject\1[\s\S]*?<\/Row>/g, '');
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
  const formulaValue = visioFormulaStringValue(attrValue(cellMatch[0], 'F'));
  if (formulaValue !== null) return formulaValue;
  return attrValue(cellMatch[0], 'V');
}

function visioFormulaStringValue(formula) {
  const decoded = decodeXmlAttr(formula || '').trim();
  if (decoded.length < 2 || decoded[0] !== '"' || decoded[decoded.length - 1] !== '"') return null;
  return decoded.slice(1, -1).replace(/""/g, '"');
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
      const tagEnd = xml.indexOf('>', nextOpen);
      if (tagEnd === -1) return -1;
      const openTag = xml.slice(nextOpen, tagEnd + 1);
      if (/\/>$/.test(openTag)) {
        if (depth === 0) return tagEnd + 1;
        cursor = tagEnd + 1;
        continue;
      }
      depth += 1;
      cursor = tagEnd + 1;
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
    const inner = /\/>$/.test(openTag) ? '' : block.slice(openEnd + 1, -'</Shape>'.length);
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
    const inner = /\/>$/.test(openTag) ? '' : block.slice(openEnd + 1, -'</Shape>'.length);
    const shapeId = attrValue(openTag, 'ID');
    const textInfo = directShapeTextInfo(inner);
    const visibleText = textInfo.value;
    if (shapeId) {
      const type = displayShapeType(openTag, masterById, visibleText, {
        ...context,
        textExists: textInfo.exists,
        inner
      });
      result[shapeId] = {
        shapeId,
        kind: type.kind,
        label: type.label,
        text: visibleText || firstNestedShapeText(inner),
        textExists: textInfo.exists,
        typeKey: type.typeKey,
        eligibleForCmdb: type.eligibleForCmdb,
        userValueSource: userValueSource(context.pageName || '', shapeId, textInfo)
      };
    }
    Object.assign(result, collectShapeIndex(inner, masterById, context));
    cursor = end;
  }
  return result;
}

function isUninformativeAtom(atom) {
  return !atom.text && !atom.masterId && (!atom.shapeNameU || atom.shapeNameU === 'object');
}

function atomRoleKey(atom, index) {
  return [
    `label:${isUninformativeAtom(atom) ? `part-${index + 1}` : atom.label || ''}`,
    `kind:${atom.kind || ''}`,
    `master:${atom.masterId || atom.masterShapeId || atom.shapeNameU || ''}`,
    `index:${index}`
  ].join('|');
}

function collectAtomicShapes(xml, masterById, pageName, context = {}) {
  const atoms = [];
  const rules = typeDetectionRules(context);
  forEachShape(xml, ({ block, openTag, inner }) => {
    const textInfo = directShapeTextInfo(inner);
    const visibleText = textInfo.value;
    const type = displayShapeType(openTag, masterById, visibleText, {
      ...context,
      rules,
      textExists: textInfo.exists,
      inner
    });
    if (type.kind === 'group' || type.kind === 'container') {
      const shapeId = attrValue(openTag, 'ID') || '';
      const aggregationPath = (context.aggregationPath || []).concat([aggregationContextFor(type, pageName, shapeId, textInfo)]);
      atoms.push(...collectAtomicShapes(inner, masterById, pageName, {
        ...context,
        aggregationPath
      }));
      return;
    }
    if (type.kind === 'connector') return;
    const shapeId = attrValue(openTag, 'ID') || '';
    const aggregationPath = context.aggregationPath || [];
    const masterShapeId = attrValue(openTag, 'MasterShape') || '';
    const rawLabel = textInfo.exists ? visibleText || EMPTY_USER_VALUE_LABEL : type.shapeName || type.masterName || type.shapeNameU || shapeId;
    const label = rawLabel && rawLabel !== 'object' ? rawLabel : '';
    if (!rawLabel && !shapeId) return;
    atoms.push({
      page: pageName,
      shapeId,
      label,
      rawLabel,
      text: visibleText,
      textExists: textInfo.exists,
      userValueSource: userValueSource(pageName, shapeId, textInfo),
      kind: type.kind,
      masterId: type.masterId,
      masterShapeId,
      masterName: type.masterName,
      masterNameU: type.masterNameU,
      shapeNameU: type.shapeNameU,
      typeKey: type.typeKey,
      aggregationPath,
      lastAggregation: aggregationPath[aggregationPath.length - 1] || null,
      shapeData: directPropertyRows(block.slice(openTag.length, -'</Shape>'.length))
    });
  });
  return atoms.map((atom, index) => ({
    ...atom,
    label: atom.label || `Часть ${index + 1}`,
    anonymous: !atom.label,
    roleKey: atomRoleKey(atom, index)
  }));
}

function connectorAtom(openTag, inner, masterById, pageName, context = {}) {
  const aggregationPath = context.aggregationPath || [];
  const textInfo = directShapeTextInfo(inner);
  const visibleText = textInfo.value;
  const type = displayShapeType(openTag, masterById, visibleText, {
    ...context,
    textExists: textInfo.exists,
    inner
  });
  const shapeId = attrValue(openTag, 'ID') || '';
  const label = textInfo.exists ? visibleText || EMPTY_USER_VALUE_LABEL : type.label || `Соединение ${shapeId}`;
  const atom = {
    page: pageName,
    shapeId,
    label,
    rawLabel: label,
    text: visibleText,
    textExists: textInfo.exists,
    userValueSource: userValueSource(pageName, shapeId, textInfo),
    kind: 'connector',
    masterId: type.masterId,
    masterShapeId: attrValue(openTag, 'MasterShape') || '',
    masterName: type.masterName,
    masterNameU: type.masterNameU,
    shapeNameU: type.shapeNameU,
    typeKey: type.typeKey,
    shapeData: directPropertyRows(inner),
    connection: connectorBindingForShape(openTag, context),
    aggregationPath,
    lastAggregation: aggregationPath[aggregationPath.length - 1] || null
  };
  return {
    ...atom,
    roleKey: atomRoleKey(atom, 0)
  };
}

function selfAtomForShape(openTag, inner, type, textInfo, pageName, context = {}) {
  const shapeId = attrValue(openTag, 'ID') || '';
  const aggregationPath = context.aggregationPath || [];
  const atom = {
    page: pageName,
    shapeId,
    label: textInfo.exists ? textInfo.value || EMPTY_USER_VALUE_LABEL : type.label || shapeId,
    rawLabel: textInfo.exists ? textInfo.value || EMPTY_USER_VALUE_LABEL : type.label || shapeId,
    text: textInfo.value,
    textExists: textInfo.exists,
    userValueSource: userValueSource(pageName, shapeId, textInfo),
    kind: type.kind,
    masterId: type.masterId,
    masterShapeId: attrValue(openTag, 'MasterShape') || '',
    masterName: type.masterName,
    masterNameU: type.masterNameU,
    shapeNameU: type.shapeNameU,
    typeKey: type.typeKey,
    shapeData: directPropertyRows(inner),
    aggregationPath,
    lastAggregation: aggregationPath[aggregationPath.length - 1] || null
  };
  return {
    ...atom,
    anonymous: false,
    roleKey: atomRoleKey(atom, 0)
  };
}

function aggregateLabelFor(atoms, fallback, aggregateType = {}) {
  if (aggregateType.textExists) return `${fallback || EMPTY_USER_VALUE_LABEL}: ${atoms.length} частей`;
  const labels = atoms.filter((atom) => !atom.anonymous).sort((a, b) => {
    const aEmpty = a.userValueSource && a.userValueSource.path && !a.userValueSource.value;
    const bEmpty = b.userValueSource && b.userValueSource.path && !b.userValueSource.value;
    return Number(aEmpty) - Number(bEmpty);
  }).map((atom) => atom.label).filter(Boolean);
  if (labels.length) return labels.join(' / ');
  return `${fallback || 'Агрегат'}: ${atoms.length} частей`;
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
    userValueSource: aggregate.userValueSource || null,
    atomRoles: aggregate.atomRoles,
    instances: []
  };
  existing.instances.push(instance);
  result.set(aggregate.aggregateTypeKey, existing);
}

function anchorAtomForAggregate(atoms) {
  const list = atoms || [];
  return list.find((atom) => atom.userValueSource && atom.userValueSource.path && atom.userValueSource.value) ||
    list.find((atom) => atom.userValueSource && atom.userValueSource.path) ||
    list.find((atom) => atom.shapeData && atom.shapeData.length) ||
    list.find((atom) => atom.shapeId) ||
    null;
}

function anchorSnapshot(atom, visualObject = {}) {
  if (!atom) return null;
  return {
    page: atom.page || '',
    shapeId: atom.shapeId || '',
    roleKey: atom.roleKey || '',
    label: atom.label || '',
    kind: atom.kind || '',
    typeKey: atom.typeKey || '',
    userValueSource: atom.userValueSource || null,
    shapeData: atom.shapeData || [],
    visualObject
  };
}

function inspectAggregatesInXml(xml, masterById, pageName, result, context = {}) {
  const rules = typeDetectionRules(context);
  forEachShape(xml, ({ openTag, inner }) => {
    const textInfo = directShapeTextInfo(inner);
    const visibleText = textInfo.value;
    const type = displayShapeType(openTag, masterById, visibleText, {
      ...context,
      rules,
      textExists: textInfo.exists,
      inner
    });
    const shapeId = attrValue(openTag, 'ID') || '';
    const aggregateUserValueSource = userValueSource(pageName, shapeId, textInfo);
    if (type.kind === 'group' || type.kind === 'container') {
      const aggregationPath = (context.aggregationPath || []).concat([aggregationContextFor(type, pageName, shapeId, textInfo)]);
      const atoms = collectAtomicShapes(inner, masterById, pageName, {
        ...context,
        aggregationPath
      });
      if (!atoms.length && textInfo.exists) atoms.push(selfAtomForShape(openTag, inner, type, textInfo, pageName, context));
      if (atoms.length) {
        const visualAnchor = selfAtomForShape(openTag, inner, type, textInfo, pageName, context);
        const anchor = anchorSnapshot(visualAnchor || anchorAtomForAggregate(atoms), {
          page: pageName,
          shapeId,
          kind: type.kind,
          label: type.label,
          userValueSource: aggregateUserValueSource
        });
        const aggregateTypeKey = aggregateTypeKeyFor(type.kind, type.typeKey, atoms);
        addAggregate(result, {
          aggregateTypeKey,
          kind: type.kind,
          label: aggregateLabelFor(atoms, type.label, type),
          typeKey: type.typeKey,
          userValueSource: aggregateUserValueSource,
          atomRoles: atoms.map((atom) => ({
            roleKey: atom.roleKey,
            label: atom.label,
            kind: atom.kind,
            typeKey: atom.typeKey,
            masterId: atom.masterId,
            masterShapeId: atom.masterShapeId,
            anonymous: atom.anonymous,
            userValueSource: atom.userValueSource,
            lastAggregation: atom.lastAggregation,
            shapeNameU: atom.shapeNameU
          }))
        }, {
          page: pageName,
          aggregateShapeId: shapeId,
          label: type.label,
          userValueSource: aggregateUserValueSource,
          anchor,
          atoms
        });
      }
      inspectAggregatesInXml(inner, masterById, pageName, result, {
        ...context,
        insideAggregate: true,
        aggregationPath
      });
      return;
    }
    if (type.kind === 'connector') {
      const atom = connectorAtom(openTag, inner, masterById, pageName, context);
      const aggregateTypeKey = aggregateTypeKeyFor('connector', atom.typeKey, [atom]);
      addAggregate(result, {
        aggregateTypeKey,
        kind: 'connector',
        label: atom.label,
        typeKey: atom.typeKey,
        userValueSource: atom.userValueSource,
        atomRoles: [{
          roleKey: atom.roleKey,
          label: atom.label,
          kind: atom.kind,
          typeKey: atom.typeKey,
          masterId: atom.masterId,
          masterShapeId: atom.masterShapeId,
          anonymous: false,
          userValueSource: atom.userValueSource,
          lastAggregation: atom.lastAggregation,
          shapeNameU: atom.shapeNameU
        }]
      }, {
        page: pageName,
        aggregateShapeId: shapeId,
        label: atom.label,
        userValueSource: atom.userValueSource,
        atoms: [atom]
      });
      return;
    }
    if (context.insideAggregate) return;
    const atoms = collectAtomicShapes(`${openTag}${inner}</Shape>`, masterById, pageName, context);
    if (!atoms.length) return;
    const aggregateTypeKey = aggregateTypeKeyFor('single', atoms[0].typeKey, atoms);
    addAggregate(result, {
      aggregateTypeKey,
      kind: 'single',
      label: atoms[0].label,
      typeKey: atoms[0].typeKey,
      userValueSource: atoms[0].userValueSource,
      atomRoles: atoms.map((atom) => ({
        roleKey: atom.roleKey,
        label: atom.label,
        kind: atom.kind,
        typeKey: atom.typeKey,
        masterId: atom.masterId,
        masterShapeId: atom.masterShapeId,
        anonymous: atom.anonymous,
        userValueSource: atom.userValueSource,
        lastAggregation: atom.lastAggregation,
        shapeNameU: atom.shapeNameU
      }))
    }, {
      page: pageName,
      aggregateShapeId: shapeId,
      label: atoms[0].label,
      userValueSource: atoms[0].userValueSource,
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
  if (/\/>$/.test(openTag)) return block;
  const inner = block.slice(openEnd + 1, -'</Shape>'.length);
  const textInfo = directShapeTextInfo(inner);
  const split = splitLeadingShapeContent(inner);
  const fields = fieldsForShape(openTag, {
    ...options,
    visibleText: textInfo.value,
    textExists: textInfo.exists,
    inner
  });
  const meaningfulBaaUpdate = fields.some((field) =>
    (field.name === 'template_Class' && String(field.value || '').trim()) ||
    (field.name === '_baa_MappingKey' && String(field.value || '').trim()) ||
    (field.name === '_baa_ContractVersionId' && String(field.value || '').trim())
  );
  if (!meaningfulBaaUpdate) {
    return `${openTag}${split.leading}${enrichShapes(split.rest, options)}</Shape>`;
  }
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
    const inner = /\/>$/.test(openTag) ? '' : block.slice(openEnd + 1, -'</Shape>'.length);
    const textInfo = directShapeTextInfo(inner);
    const visibleText = textInfo.value;
    const master = masterById[attrValue(openTag, 'Master')] || {};
    const isContainerRoot = Boolean(master.isContainer);
    const parentIsContainerRoot = Boolean(context.insideContainerRoot);
    if (rules.keepDecorativeShapesUnchanged && attrValue(openTag, 'MasterShape') && !textInfo.exists) {
      inspectShapes(inner, masterById, pageName, result, {
        ...context,
        insideContainerRoot: parentIsContainerRoot || isContainerRoot
      });
      cursor = end;
      continue;
    }
    if (rules.keepDecorativeShapesUnchanged && parentIsContainerRoot && attrValue(openTag, 'MasterShape') && !textInfo.exists) {
      inspectShapes(inner, masterById, pageName, result, {
        ...context,
        insideContainerRoot: true
      });
      cursor = end;
      continue;
    }
    if (shapeKind(openTag) === 'object' && !attrValue(openTag, 'Master') && !attrValue(openTag, 'NameU') && !textInfo.exists) {
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
      textExists: textInfo.exists,
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
        textExists: textInfo.exists,
        userValueSource: userValueSource(pageName, attrValue(openTag, 'ID'), textInfo),
        kind: type.kind,
        eligibleForCmdb: type.eligibleForCmdb,
        visualRole: type.visualRole,
        contextPath: shapeContextPath,
        connection,
        shapeData: directPropertyRows(inner)
      });
      for (const row of directPropertyRows(inner)) {
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
        shapeIndexById: collectShapeIndex(pageXml, masterById, { rules, pageName: fileName })
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
        const openTag = openEnd === -1 ? block : block.slice(0, openEnd + 1);
        const shapeId = attrValue(openTag, 'ID') || '';
        const inner = /\/>$/.test(openTag) ? '' : block.slice(openEnd + 1, -'</Shape>'.length);
        for (const row of directPropertyRows(inner)) {
          if ((row.name === '_baa_ContractVersionId' || row.name === 'BAA_ContractVersionId') && row.value) metadata.contractVersionId = row.value;
          if ((row.name === '_baa_ContractVersionCode' || row.name === 'BAA_ContractVersionCode') && row.value) metadata.contractVersionCode = row.value;
          if ((row.name === '_baa_ContractVersionChecksum' || row.name === 'BAA_ContractVersionChecksum') && row.value) metadata.contractVersionChecksum = row.value;
          if ((row.name === '_baa_ContractObject' || row.name === 'BAA_ContractObject') && row.value) metadata.contractObject = row.value;
          if ((row.name === '_baa_PreparedAt' || row.name === 'BAA_PreparedAt') && row.value) metadata.preparedAt = row.value;
        }
        if (metadata.contractVersionId || metadata.contractVersionCode || metadata.contractVersionChecksum) {
          metadata.contractPage = fileName;
          metadata.contractShapeId = shapeId;
          metadata.contractPageShapeKey = shapeId ? `${fileName}:${shapeId}` : '';
          return metadata;
        }
        cursor = end;
      }
    }
    return metadata;
  });
}

function rowsByName(rows) {
  const result = {};
  for (const row of rows || []) result[row.name] = row;
  return result;
}

function rowValue(byName, ...names) {
  for (const name of names) {
    if (byName[name] && byName[name].value) return byName[name].value;
  }
  return '';
}

function uniqueList(values) {
  const result = [];
  const seen = new Set();
  for (const value of values || []) {
    const normalized = String(value || '').trim();
    if (!normalized || seen.has(normalized)) continue;
    seen.add(normalized);
    result.push(normalized);
  }
  return result;
}

function classNamesFromValue(value) {
  return uniqueList(String(value || '').split(','));
}

function classNamesWithRows(rows) {
  const result = [];
  for (const row of rows || []) {
    const templateMatch = String(row.name || '').match(/^template_([^_]+)_/);
    const ruleMatch = String(row.name || '').match(/^_baa_AttributeRule_([^_]+)_/);
    const legacyRuleMatch = String(row.name || '').match(/^BAA_AttributeRule_([^_]+)_/);
    const className = templateMatch && templateMatch[1] || ruleMatch && ruleMatch[1] || legacyRuleMatch && legacyRuleMatch[1] || '';
    if (className) result.push(className);
  }
  return uniqueList(result);
}

function directCellValue(block, name) {
  const match = block.match(new RegExp(`<Cell\\b[^>]*N=['"]${name}['"][^>]*/?>`));
  return match ? decodeXmlAttr(attrValue(match[0], 'V')) : '';
}

function numericCellValue(block, name) {
  const raw = directCellValue(block, name);
  if (!String(raw || '').trim()) return null;
  const value = Number(raw);
  return Number.isFinite(value) ? value : null;
}

function shapeGeometry(block) {
  return {
    pinX: numericCellValue(block, 'PinX'),
    pinY: numericCellValue(block, 'PinY'),
    width: numericCellValue(block, 'Width'),
    height: numericCellValue(block, 'Height'),
    beginX: numericCellValue(block, 'BeginX'),
    beginY: numericCellValue(block, 'BeginY'),
    endX: numericCellValue(block, 'EndX'),
    endY: numericCellValue(block, 'EndY')
  };
}

function shapeIdsInXml(xml) {
  const result = [];
  let cursor = 0;
  while (cursor < xml.length) {
    const start = xml.indexOf('<Shape ', cursor);
    if (start === -1) break;
    const end = findShapeEnd(xml, start);
    if (end === -1) break;
    const block = xml.slice(start, end);
    const openEnd = block.indexOf('>');
    const openTag = openEnd === -1 ? block : block.slice(0, openEnd + 1);
    const shapeId = attrValue(openTag, 'ID') || '';
    if (shapeId) result.push(shapeId);
    cursor = end;
  }
  return result;
}

function extractBaaObjectsInXml(xml, pageName, result, pageConnections = {}) {
  let cursor = 0;
  while (cursor < xml.length) {
    const start = xml.indexOf('<Shape ', cursor);
    if (start === -1) break;
    const end = findShapeEnd(xml, start);
    if (end === -1) break;
    const block = xml.slice(start, end);
    const openEnd = block.indexOf('>');
    const openTag = openEnd === -1 ? block : block.slice(0, openEnd + 1);
    const inner = /\/>$/.test(openTag) ? '' : block.slice(openEnd + 1, -'</Shape>'.length);
    const rows = directPropertyRows(inner);
    const byName = rowsByName(rows);
    const cmdbClass = rowValue(byName, 'template_Class', 'CMDB_Class');
    const relationType = rowValue(byName, 'template_RelationType', 'CMDB_RelationType');
    const mappingKey = rowValue(byName, '_baa_MappingKey', 'BAA_MappingKey');
    if (cmdbClass || relationType || mappingKey) {
      const objectType = rowValue(byName, '_baa_ObjectType', 'BAA_ObjectType');
      const explicitClasses = classNamesFromValue(cmdbClass);
      const rowClasses = classNamesWithRows(rows);
      const cmdbClasses = objectType === 'Relation' && rowClasses.length
        ? explicitClasses.filter((className) => rowClasses.includes(className))
        : explicitClasses;
      const shapeId = attrValue(openTag, 'ID') || '';
      const currentConnection = pageConnections[shapeId] || {};
      const sourceShapeId = currentConnection.sourceShapeId || rowValue(byName, '_baa_SourceShapeId', 'BAA_SourceShapeId');
      const destinationShapeId = currentConnection.destinationShapeId || rowValue(byName, '_baa_DestinationShapeId', 'BAA_DestinationShapeId');
      const attributeRules = rows
        .filter((row) => /^_baa_AttributeRule_/.test(row.name) || /^BAA_AttributeRule_/.test(row.name))
        .map((row) => {
          try {
            return {
              rowName: row.name,
              label: row.label,
              rule: JSON.parse(row.value || '{}')
            };
          } catch (err) {
            return {
              rowName: row.name,
              label: row.label,
              parseError: err && err.message || 'invalid JSON',
              raw: row.value || ''
            };
          }
        });
      const unexpectedTechnicalRows = rows
        .filter((row) => /^baa_/i.test(row.name || ''))
        .map((row) => ({
          name: row.name,
          label: row.label,
          value: row.value
        }));
      result.push({
        page: pageName,
        shapeId,
        pageShapeKey: `${pageName}:${shapeId}`,
        geometry: shapeGeometry(block),
        containedShapeIds: shapeIdsInXml(inner).filter((id) => id !== shapeId),
        mappingKey,
        typeKey: rowValue(byName, '_baa_TypeKey', 'BAA_TypeKey'),
        roleKey: rowValue(byName, '_baa_RoleKey', 'BAA_RoleKey'),
        visualObjectId: rowValue(byName, '_baa_VisualObjectId', 'BAA_VisualObjectId'),
        anchorShapeId: rowValue(byName, '_baa_AnchorShapeId', 'BAA_AnchorShapeId'),
        aggregationKind: rowValue(byName, '_baa_AggregationKind', 'BAA_AggregationKind'),
        decomposed: rowValue(byName, '_baa_Decomposed', 'BAA_Decomposed'),
        cmdbClass,
        cmdbClasses,
        action: rowValue(byName, '_baa_Action', 'BAA_Action'),
        objectId: rowValue(byName, '_baa_ObjectId', 'BAA_ObjectId'),
        objectType,
        relationType: relationType || (sourceShapeId || destinationShapeId ? cmdbClass : ''),
        sourceShapeId,
        sourceKind: rowValue(byName, '_baa_SourceKind', 'BAA_SourceKind'),
        sourceText: rowValue(byName, '_baa_SourceText', 'BAA_SourceText'),
        sourceObjectType: rowValue(byName, '_baa_SourceObjectType', 'BAA_SourceObjectType'),
        destinationShapeId,
        destinationKind: rowValue(byName, '_baa_DestinationKind', 'BAA_DestinationKind'),
        destinationText: rowValue(byName, '_baa_DestinationText', 'BAA_DestinationText'),
        destinationObjectType: rowValue(byName, '_baa_DestinationObjectType', 'BAA_DestinationObjectType'),
        relationBindingStatus: rowValue(byName, '_baa_RelationBindingStatus', 'BAA_RelationBindingStatus'),
        relationBindingIssue: rowValue(byName, '_baa_ValidationIssue', 'BAA_ValidationIssue'),
        attributeRules,
        unexpectedTechnicalRows,
        values: rows.filter((row) =>
          (/^template_/.test(row.name) && row.name !== 'template_Class') ||
          (/^CMDB_/.test(row.name) && row.name !== 'CMDB_Class')
        ).map((row) => ({
          name: row.name,
          label: row.label,
          value: row.value,
          type: row.type,
          format: row.format
        }))
      });
    }
    extractBaaObjectsInXml(inner, pageName, result, pageConnections);
    cursor = end;
  }
}

function extractBaaObjectsFromVsdx(inputFile) {
  return withUnpackedVsdx(inputFile, (workRoot) => {
    const pagesDir = path.join(workRoot, 'visio', 'pages');
    const objects = [];
    for (const fileName of pageFilesIn(workRoot)) {
      const xml = fs.readFileSync(path.join(pagesDir, fileName), 'utf8');
      extractBaaObjectsInXml(xml, fileName, objects, parsePageConnections(xml));
    }
    return {
      contractMetadata: inspectVsdxContractMetadata(inputFile),
      objects
    };
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
        metadataByPageShapeId: options.metadataByPageShapeId || {},
        rules,
        connectionsByShapeId: parsePageConnections(original),
        shapeIndexById: collectShapeIndex(original, masterById, { rules, pageName: fileName }),
        contractVersion: options.contractVersion || null,
        contractPageShapeKey: options.contractPageShapeKey || '',
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
  inspectVsdxContractMetadata,
  extractBaaObjectsFromVsdx
};
