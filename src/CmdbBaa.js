function cmdbBaaParseParams(query) {
    var params = {};
    var text = (query || '').replace(/^\?/, '');
    var parts = text ? text.split('&') : [];
    for (var index = 0; index < parts.length; index += 1) {
        var part = parts[index];
        if (!part) continue;
        var separator = part.indexOf('=');
        var rawKey = separator === -1 ? part : part.slice(0, separator);
        var rawValue = separator === -1 ? '' : part.slice(separator + 1);
        var key = decodeURIComponent(rawKey.replace(/\+/g, ' '));
        if (!key) continue;
        params[key] = decodeURIComponent(rawValue.replace(/\+/g, ' '));
    }
    return params;
}

function cmdbBaaEscapeHtml(value) {
    return String(value === undefined || value === null ? '' : value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function cmdbBaaReadHashRoute() {
    var hash = window.location.hash || '';
    var marker = 'custompages/CmdbBaa';
    var markerIndex = hash.indexOf(marker);
    if (markerIndex === -1) return '';
    return hash.slice(markerIndex + marker.length).replace(/^\/+/, '').split(/[/?#]/)[0] || '';
}

function cmdbBaaNormalizeSection(value) {
    var section = String(value || '').trim().toLowerCase();
    if (section === 'schema' || section === 'cmdb-schema') return 'schema';
    if (section === 'contracts' || section === 'contract' || section === 'conversion-contracts') return 'contracts';
    if (section === 'settings' || section === 'config' || section === 'configuration') return 'settings';
    if (section === 'types' || section === 'type-settings' || section === 'visio-types') return 'types';
    if (section === 'verify' || section === 'verification') return 'verify';
    if (section === 'create-objects' || section === 'create' || section === 'objects') return 'create-objects';
    return 'prepare-template';
}

function cmdbBaaBuildTargetUrl() {
    var queryParams = cmdbBaaParseParams(window.location.search || '');
    var section = cmdbBaaNormalizeSection(queryParams.baSection || queryParams.section || cmdbBaaReadHashRoute());
    return '/cmdbuild/baa/ui/' + encodeURIComponent(section);
}

function cmdbBaaClientLog(stage, message) {
    try {
        var image = new Image();
        image.src = '/cmdbuild/baa/api/client-log?stage=' + encodeURIComponent(stage || '') +
            '&message=' + encodeURIComponent(message || '') +
            '&href=' + encodeURIComponent(window.location.href || '') +
            '&_=' + String(new Date().getTime());
    } catch (error) {
    }
}

function cmdbBaaOpenExternalUi() {
    var target = cmdbBaaBuildTargetUrl();
    try {
        if (window.sessionStorage) window.sessionStorage.setItem('cmdbaa.pendingTarget', target);
    } catch (error) {
    }
    cmdbBaaClientLog('launcher-redirect', target);
    window.location.replace(target);
}

cmdbBaaClientLog('script-loaded', 'launcher');

if ((window.location.hash || '').indexOf('custompages/CmdbBaa') !== -1 || cmdbBaaParseParams(window.location.search || '').baSection) {
    window.setTimeout(cmdbBaaOpenExternalUi, 0);
}

Ext.define('CMDBuildUI.view.custompages.CmdbBaa.CmdbBaa', {
    extend: 'Ext.panel.Panel',
    alias: 'widget.cmdb-baa',
    mixins: ['CMDBuildUI.mixins.CustomPage'],

    bodyPadding: 16,
    scrollable: true,
    title: 'CMDB BAA',

    initComponent: function () {
        var target = cmdbBaaBuildTargetUrl();
        cmdbBaaClientLog('initComponent', target);
        this.html = [
            '<div style="font-family:Arial,sans-serif;line-height:1.45">',
            '<h2 style="font-size:20px;margin:0 0 8px">CMDB BAA</h2>',
            '<p style="margin:0 0 12px;color:#52606d">Открывается рабочий интерфейс...</p>',
            '<p style="margin:0"><a style="display:inline-block;background:#236c91;color:#fff;padding:8px 12px;border-radius:4px;text-decoration:none;font-weight:600" href="' + cmdbBaaEscapeHtml(target) + '">Открыть</a></p>',
            '</div>'
        ].join('');
        this.callParent(arguments);
        this.on('afterrender', function () {
            cmdbBaaClientLog('afterrender', 'launcher');
            window.setTimeout(cmdbBaaOpenExternalUi, 0);
        }, this, { single: true });
    }
});
