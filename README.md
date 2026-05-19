# cmdbaa

CMDBuild custom page launcher and same-origin reverse proxy for BAA workflows.

## Routes

All application routes live under `/cmdbuild` so the browser sends the CMDBuild
`HttpOnly` session cookie to the proxy:

```text
/cmdbuild/baa/ui/prepare-template
/cmdbuild/baa/ui/verify
/cmdbuild/baa/ui/create-objects
/cmdbuild/baa/ui/schema
/cmdbuild/baa/ui/contracts
/cmdbuild/baa/ui/settings
/cmdbuild/baa/api/session
/cmdbuild/baa/api/csrf
```

The frontend never reads `CMDBuild-Authorization`. The proxy reads it from the
incoming cookie, validates `/cmdbuild/services/rest/v3/sessions/current`, and
uses the token server-side for future CMDBuild REST calls.

## Development

```bash
npm run proxy:dev
```

Prepare the current Visio spike file:

```bash
npm run vsdx:enrich
```

This reads `1.vsdx` and writes `1.enriched.vsdx` with BAA/CMDB Shape Data on
objects, connectors, groups, and nested group shapes. The current spike embeds a
small demo location list in Visio fields: `MSK;SPB;NOC`.

The `Подготовить шаблон` UI can upload a `.vsdx`, inspect shape types, map each
type to a CMDB class, and download the enriched `.vsdx`. A shape type is defined
by the Visio shape object plus its display name: equal names, including empty
names, are one type; different names are different types.
Checksum verification uses a sidecar file named `<filename.ext>.<sumextension>`.
The left menu is grouped into two levels. `Работа с шаблонами` contains
`Контракты` and `Подготовить шаблон`; `Настройки` is placed at the bottom and
contains `Общие`, `Типы`, and `Схема`. `Общие` controls `sumextension` and
whether checksum verification is performed during template preparation. `Типы`
controls only Visio type recognition rules, keeping them separate from the
contract data model. The global `CMDB BAA` header shows the file status in red
or green and the selected contract version. If no version is available, it shows
`Версия не выбрана`.

The `Схема` UI bootstraps CMDBuild classes under the `BAA` superclass:
`BAAConversionContract` and `BAAConversionContractVersion`. These are the CMDB
objects that will hold conversion contracts and their versions.
The `Контракты` UI lists and creates `BAAConversionContract` cards with code,
name, description, and status. Contract versions are read-only for the user:
BAA creates `BAAConversionContractVersion` cards automatically during VSDX
enrichment. The version stores contract id/code, version, status, rules JSON,
checksum, active flag, author, timestamp, and the accumulated Visio type
snapshot.
`Подготовить шаблон` asks the user to select a contract, not a version. If the
uploaded VSDX already contains BAA contract metadata, the backend can resolve
the contract from the file. When enrichment sees only known types, it reuses the
latest contract version; when the template introduces new Visio types, it
creates the next version automatically. Removing types from a template does not
invalidate enrichment.
During enrichment, BAA writes contract metadata into VSDX Shape Data:
`BAA_TemplatePrepared`, `BAA_ContractVersionId`, `BAA_ContractVersionCode`,
`BAA_ContractVersionChecksum`, `BAA_PreparedAt`, and `BAA_PreparedBy`.
Visio groups are treated as visual context only: enrichment does not write
working `CMDB_*` fields to groups, and inspection marks them with
`eligibleForCmdb=false`.
Visio containers are detected separately from groups. When the selected contract
allows containers as types, enrichment writes the normal working `CMDB_*` fields
to the container; when that rule is disabled, the container remains visible in
inspection as visual context with `eligibleForCmdb=false`.
Connectors are enriched as CMDB relations. BAA records source/destination Visio
shape ids and a relation binding status; unconnected connectors or connectors
attached to non-CMDB visual context are marked with `BAA_ValidationIssue` so
validation can stop before object creation.

Open through the proxy:

```text
http://127.0.0.1:8094/cmdbuild/ui/?baSection=prepare-template#custompages/CmdbBaa
```

Direct same-origin URLs:

```text
http://127.0.0.1:8094/cmdbuild/baa/ui/prepare-template
http://127.0.0.1:8094/cmdbuild/baa/ui/schema
http://127.0.0.1:8094/cmdbuild/baa/ui/contracts
http://127.0.0.1:8094/cmdbuild/baa/ui/settings
http://127.0.0.1:8094/cmdbuild/baa/ui/types
http://127.0.0.1:8094/cmdbuild/baa/ui/verify
http://127.0.0.1:8094/cmdbuild/baa/ui/create-objects
```

Settings:

```text
PROXY_HOST=127.0.0.1
PROXY_PORT=8094
CMDBUILD_ORIGIN=http://127.0.0.1:8090
CMDBBAA_CSRF_SECRET=<random-secret>
CMDBBAA_PROXY_COOKIE_SAMESITE=
CMDBBAA_PROXY_COOKIE_SECURE=false
```
