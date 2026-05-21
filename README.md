# cmdbaa

CMDBuild custom page launcher and same-origin reverse proxy for BAA workflows.

## Routes

All application routes live under `/cmdbuild` so the browser sends the CMDBuild
`HttpOnly` session cookie to the proxy:

```text
/cmdbuild/baa/ui/prepare-template
/cmdbuild/baa/ui/check-template
/cmdbuild/baa/ui/prepare-objects
/cmdbuild/baa/ui/verify
/cmdbuild/baa/ui/create-objects
/cmdbuild/baa/ui/schema
/cmdbuild/baa/ui/contracts
/cmdbuild/baa/ui/settings
/cmdbuild/baa/ui/help
/cmdbuild/baa/ui/about
/cmdbuild/baa/api/session
/cmdbuild/baa/api/csrf
```

The frontend never reads `CMDBuild-Authorization`. The proxy reads it from the
incoming cookie, validates `/cmdbuild/services/rest/v3/sessions/current`, and
uses the token server-side for future CMDBuild REST calls.

## Documentation

User and operator documentation lives in `docs/`:

- `docs/user-help.md` - user help, workflow blocks, contracts, template
  enrichment, dangling links, object creation, and mapping-object terminology.
- `docs/admin-guide.md` - administrator guide for proxy settings, schema
  bootstrap, checksum validation, CMDB validators, and operational agreements.
- `docs/verification-contracts.md` - naming, storage classes, schemas, and
  exchange order for BAA verification contracts and `cmdbcustompages`.
- `docs/cmdbcustompage-verification-exchange.md` - formal request/response
  contract to provide to the `cmdbcustompage` side.
- `docs/e2e-verification-scenario.md` - manual E2E scenario and future
  smoke-test checklist for verification.
- `docs/architecture/` - architecture artifacts prepared according to
  `../aa.txt`: business processes, information model, deployment, OpenAPI
  outline, HealthCheck map, secrets map, and event log map.

When changing contract behavior, template enrichment, verification, object
creation, reverse proxy routes, ports, or CMDBuild schema assumptions, update the
corresponding documentation in the same change.

## Development

```bash
npm run proxy:dev
```

Prepare the current Visio spike file:

```bash
npm run vsdx:enrich
```

This reads `1.vsdx` and writes `1.enriched.vsdx` with `_baa_`/`template_` Shape Data on
objects, connectors, groups, and nested group shapes. The current spike embeds a
small demo location list in Visio fields: `MSK;SPB;NOC`.

The `Подготовить шаблон` UI can upload a `.vsdx`, inspect shape types, map each
type to a CMDB class, and download the enriched `.vsdx`. A shape type is defined
by the Visio shape object plus its display name: equal names, including empty
names, are one type; different names are different types.
Checksum verification uses a sidecar file named `<filename.ext>.<sumextension>`.
The left menu is grouped into two levels. `Работа с шаблонами` contains
`Контракты` and `Подготовить шаблон`; top-level workflow entries then continue
with `Проверить шаблон`, `Подготовить объекты`, `Верификация`, and
`Создать объекты`. `Настройки`
is placed at the bottom and contains `Общие`, `Типы`, and `Схема`. `Общие` controls `sumextension` and
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
The rules JSON also contains `contractParams`: named contract-level variables
that are independent from a specific Visio figure. They are versioned with the
contract and are intended for expressions such as `${contractparam.name}` in
later object assembly steps. A parameter has `name`, `description`, `type`,
`required`, `defaultValue`, `listMode`, `values`, and optional `help`. During
enrichment the backend preserves existing parameters and creates a new contract
version when the submitted parameter set adds or changes a parameter.
`Подготовить шаблон` has a `Параметры контракта` tab where the editor declares
these parameters before finishing enrichment. The tab writes only contract
metadata; it does not create Visio fields for object instances yet.
`Подготовить шаблон` asks the user to select a contract, not a version. If the
uploaded VSDX already contains BAA contract metadata, the backend can resolve
the contract from the file. When enrichment sees only known types, it reuses the
latest contract version; when the template introduces new Visio types, it
creates the next version automatically. Removing types from a template does not
invalidate enrichment.
During enrichment, BAA writes contract metadata into VSDX Shape Data with the
technical `_baa_` prefix:
`_baa_TemplatePrepared`, `_baa_ContractVersionId`, `_baa_ContractVersionCode`,
`_baa_ContractVersionChecksum`, `_baa_PreparedAt`, and `_baa_PreparedBy`.
User-editable template fields use the `template_` prefix. Fields without these
prefixes are treated as foreign Shape Data and are not renamed or rewritten.
Visio groups are treated as visual context only: enrichment does not write
working `template_*` fields to groups, and inspection marks them with
`eligibleForCmdb=false`.
Visio containers are detected separately from groups. When the selected contract
allows containers as types, enrichment writes the normal working `template_*` fields
to the container; when that rule is disabled, the container remains visible in
inspection as visual context with `eligibleForCmdb=false`.
Connectors are enriched as CMDB relations. BAA records source/destination Visio
shape ids and a relation binding status. Unconnected or partially connected
connectors are reported by validation. Group endpoints remain valid visual
anchors, but validation warns that the endpoint must be resolved by the object
assembly logic.

`Проверить шаблон` is a technical check for a filled or partially filled VSDX.
It verifies assumptions that belong to BAA itself: the file contains a contract
object, the referenced contract version exists in CMDBuild, the rules checksum
matches, BAA technical fields are readable, there are no visible lowercase
`baa_*` fields, figures have `_baa_MappingKey` and `template_Class`, and
connector binding statuses are known. This page does not validate business
data completeness and does not decide whether CMDB objects can be created.
That is the responsibility of `Верификация` and the object plan in
`Подготовить объекты`.

## Инструкция: маппинг объектов и связей

BAA использует одну общую модель наполнения шаблона: пользователь выбирает
визуальный тип, назначает CMDB-класс и отмечает атрибуты, которые нужны для
создания экземпляра этого класса.

Для обычных фигур действует простое правило:

```text
target.attr = self.attr
```

То есть все выбранные атрибуты класса записываются в Shape Data той же фигуры.
При создании CMDB-объекта сборщик берет значения с этой фигуры. Если атрибут
должен вводиться пользователем, он остается полем в Visio. Если атрибут является
lookup/reference, при подготовке шаблона можно выбрать, наполнять ли список и
каким способом: постоянным или переменным.

Для соединительных линий используется более общий подход. Линия может создавать
не только саму связь, но и отдельный CMDB-экземпляр, значения которого
собираются из трех участников контекста:

```text
source object + connection + destination object
```

Для каждого атрибута создаваемого класса контракт должен хранить правило
заполнения:

```text
targetClass.targetAttribute = sourceRole.sourceAttribute
```

`sourceRole` может быть:

- `self` - значение берется с текущей фигуры или линии;
- `source` - значение берется с объекта на source-конце линии;
- `destination` - значение берется с объекта на destination-конце линии;
- `manual` - поле отдается пользователю на заполнение в Visio;
- `constant` - значение задается контрактом;
- `default` - значение задается по умолчанию и может быть переопределено;
- `override` - значение на линии переопределяет значение из endpoint-объекта.

Правило также может использовать выражения. Поддерживаемые ссылки:

```text
${contractparam.name}
${visioparam.name}
${source.visioparam.name}
${destination.visioparam.name}
${relation.visioparam.name}
```

`contractparam` берется из параметров версии контракта. `visioparam` читает
пользовательские поля текущей фигуры: точное имя, `template_<name>` или
единственное поле с суффиксом `_<name>`. Для связи `source` и `destination`
обращаются к endpoint-объектам, а `relation` - к самой линии. Выражение может
быть всем значением или частью строки; если ссылка не разрешилась, в составной
строке она заменяется пустым значением.

Пример для ACL как частного случая общего маппинга:

```text
ACL.SourceIp   = source.ipaddress
ACL.TargetIp   = destination.ipaddress
ACL.SourcePort = self.SourcePort
ACL.TargetPort = self.TargetPort
ACL.Protocol   = self.Protocol
```

В этом сценарии IP-адрес хранится один раз на объекте источника или назначения.
На линии пользователь заполняет только параметры конкретной связанности:
порты, протокол и возможные исключения. Если требуется NAT, alias или ручная
коррекция, на линии можно использовать override-поля.

При подготовке шаблона это означает:

1. Для endpoint-объектов назначаются классы и атрибуты, которые нужны самим
   объектам и другим связям, например `ipaddress`.
2. Для соединительной линии назначается класс создаваемого контекстного
   экземпляра, например `ACL`.
3. На вкладке `Отразить на связь` для типа соединительной линии задается,
   какие атрибуты класса связи должны заполняться из внешнего endpoint-источника
   и какие пары `endpoint class + endpoint attribute` могут быть источником.
   Сторона `source/destination` при этом не дублируется в mapping: для сетевых
   N:N сценариев это резко уменьшает ручной ввод, а пригодность конкретной
   пары проверяется при сборке объектов.
4. Для атрибутов класса связи выбирается источник значения: сама линия,
   source-объект, destination-объект, ручной ввод или константа.
5. В VSDX записываются поля, которые пользователь должен заполнить вручную или
   на линии. Значения, которые копируются из source/destination, не нужно
   дублировать на линии как обязательные поля.

При верификации шаблона сборщик должен проверить:

- у линии определены source и destination;
- endpoint-объекты привязаны к CMDB-назначениям;
- endpoint-объекты привязаны к CMDB-назначениям; точное соответствие атрибута
  связи и endpoint-атрибута проверяется на этапе сборки объектов;
- поля `self`, `manual` и `override` заполнены там, где они обязательны;
- направление связи определено. Проверка гипотезы по направлению стрелки
  выполняется на этапе реализации сборки объектов.

Группы Visio допустимы как endpoint связи. Они не делают связь невалидной сами
по себе, потому что пользовательские "атомарные" объекты Visio часто являются
группами. При разборе связи BAA сохраняет тип endpoint (`object`, `group`,
`container`), пользовательский текст endpoint и статус привязки. Неполные связи
всегда выводятся в валидации: если не привязан один конец, статус будет
`partial`; если не привязаны оба конца, статус будет `unbound`. Автоматическое
восстановление endpoint по геометрии пока не выполняется.

При создании объектов порядок выбора значения должен быть таким:

```text
override на линии -> endpoint/source/destination -> self/manual/constant -> ошибка верификации
```

На странице `Подготовить объекты` файл сначала проходит техническую проверку
шаблона. Бизнес-верификация не блокирует построение плана: если обязательные
атрибуты CMDB еще не заполнены, BAA показывает их как недозаполненные поля в
dry-run плане. Реальное выполнение создания в CMDBuild блокируется, пока в
плане есть незаполненные обязательные атрибуты или ошибки бизнес-верификации.
Недостающие обязательные значения можно временно дозаполнить на странице
`Подготовить объекты`: после загрузки файла BAA показывает поля ввода рядом с
`missingAttributes`, пользователь вводит значения, нажимает `Перестроить план`,
и эти значения попадают в payload как `ui_override`. Это не изменяет VSDX и
предназначено только для ручного завершения конкретного запуска создания.
Кнопка `Сформировать план` строит dry-run план:

- `kind=object` означает обычный CMDB-экземпляр с одной фигуры;
- `kind=context` означает экземпляр, собранный из линии, source-объекта и
  destination-объекта;
- `payload` показывает значения, которые будут отправлены в CMDBuild;
- `endpoints` показывает привязанные source/destination фигуры и их классы;
- `attributeSources` показывает для каждого атрибута класс, имя атрибута,
  роль источника, фигуру-источник, обязательность и наличие значения;
- `missingAttributes` показывает обязательные атрибуты, для которых значение
  не найдено после применения Visio-полей, параметров контракта, выражений и
  правил source/destination/relation.
- `canExecute=false` означает, что реальная запись в CMDBuild будет заблокирована
  до устранения недостающих значений или блокирующих ошибок.

Отдельный пункт меню `Создать объекты` отправляет в CMDBuild payload из
последнего подготовленного плана. Исполнитель выбирает полноту запуска: режим
`Выбрать классы` создает все объекты выбранных классов, режим `Выбрать объекты`
создает только отмеченные строки плана. Обязательность и блокирующие ошибки
считаются для выбранной части. При отсутствии файла контрольной суммы или при
ошибке проверки checksum создание не выполняется. Результат создания сохраняет
тот же контекст: индекс плана, тип элемента `object/context`, endpoint-ы,
payload и источники атрибутов.
Это нужно, чтобы ошибка CMDBuild разбиралась по конкретному экземпляру и было
видно, из какой части Visio-схемы взялось каждое значение.

Такой маппинг не является специальной ACL-логикой. ACL используется только как
пример. Та же модель подходит для маршрутов, firewall rules, зависимостей
приложений, размещения сервиса на сервере, связей с БД и любых сценариев, где
создаваемый CMDB-экземпляр определяется комбинацией source, destination и
соединительной линии.

Open through the proxy:

```text
http://127.0.0.1:8094/cmdbuild/ui/?baSection=prepare-template#custompages/CmdbBaa
```

Direct same-origin URLs:

```text
http://127.0.0.1:8094/cmdbuild/baa/ui/prepare-template
http://127.0.0.1:8094/cmdbuild/baa/ui/check-template
http://127.0.0.1:8094/cmdbuild/baa/ui/prepare-objects
http://127.0.0.1:8094/cmdbuild/baa/ui/schema
http://127.0.0.1:8094/cmdbuild/baa/ui/contracts
http://127.0.0.1:8094/cmdbuild/baa/ui/settings
http://127.0.0.1:8094/cmdbuild/baa/ui/types
http://127.0.0.1:8094/cmdbuild/baa/ui/verify
http://127.0.0.1:8094/cmdbuild/baa/ui/create-objects
http://127.0.0.1:8094/cmdbuild/baa/ui/help
http://127.0.0.1:8094/cmdbuild/baa/ui/about
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
