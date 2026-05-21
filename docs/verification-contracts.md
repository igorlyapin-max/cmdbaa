# Verification contracts

## Назначение

BAA не строит бизнес-логику проверки динамически из данных. BAA публикует
договор о данных, которые может передать, а `cmdbcustompages` заранее реализует
endpoint проверки под этот договор.

## Управляемые пользователем классы

Имена классов, где BAA ищет и создает contracts, задаются в `Настройки / Общие`:

- `Класс input contracts` - по умолчанию `BAAVerificationInputContract`.
- `Класс output contracts` - по умолчанию `BAAVerificationOutputContract`.
- `Класс endpoint definitions` - по умолчанию `BAAVerificationEndpoint`.

Администратор может заменить эти имена на классы заказчика, если они имеют те же
поля и доступны через CMDBuild REST API. Bootstrap BAA создает только
дефолтные классы.

## Input contract

Input contract описывает данные, которые BAA может отправить во внешнюю
верификацию после подготовки плана:

- версия BAA-контракта;
- CMDB-классы;
- доступные атрибуты классов;
- обязательность, тип, inherited-признак;
- relations как контекст `source / destination / relation`;
- параметры контракта `contractparam.*`.

В UI `Подготовить правила верификации` параметры контракта показываются
отдельной таблицей при `Сформировать по готовым объектам`. При запуске внешней
верификации тот же нормализованный список передается в POST body в поле
`contractParams`.

Input contract сохраняется в CMDBuild как объект выбранного класса input
contracts. Значимое поле:

```text
SchemaJson
```

Для контроля версии рассчитывается:

```text
SchemaChecksum = sha256(SchemaJson)
```

## Output contract

Output contract описывает формат ответа, который BAA ожидает от
`cmdbcustompages`. `cmdbcustompage` возвращает найденные данные, а не verdict
`валидно/невалидно`. Решение о том, что означает наличие или отсутствие строк,
BAA принимает по `ResultInterpretationJson` в endpoint definition.

Предпочтительная минимальная структура ответа:

```json
{
  "success": true,
  "status": "completed",
  "title": "Destination networks",
  "summary": {
    "rows": 1
  },
  "tables": [
    {
      "code": "destination_networks",
      "title": "Destination является сетью",
      "columns": [
        { "name": "aclCode", "title": "ACL", "type": "string" },
        { "name": "destination", "title": "Destination", "type": "string" }
      ],
      "rows": [
        {
          "aclCode": "ACL-001",
          "destination": "10.0.0.0/24"
        }
      ]
    }
  ],
  "items": [],
  "data": {}
}
```

BAA валидирует только базовый договор:

- `success` должен быть boolean;
- должен быть массив `tables` или массив `items`;
- каждая таблица должна иметь `code`, `columns`, `rows`;
- каждая строка `rows[]` должна быть object, но набор колонок расширяемый;
- каждый item должен иметь `level`, `code`, `message`, если массив `items`
  используется;
- `level` принимает `error`, `warning`, `info`.

Старый формат ответа с `items` без `tables` поддерживается на переходный
период.

## Endpoint definition

Endpoint definition хранится в выбранном классе endpoint definitions.

Основные поля:

- `InputContractCode`
- `InputContractVersion`
- `OutputContractCode`
- `OutputContractVersion`
- `EndpointUrl`
- `EndpointMethod`, сейчас поддерживается только `POST`
- `ParamsJson`
- `ResultInterpretationJson`
- `EndpointStatus`

`EndpointUrl` может быть абсолютным URL или относительным путем внутри
CMDBuild/reverse-proxy origin, например:

```text
/cmdbuild/custompage/api/verify/network-acl
```

`ParamsJson` поддерживает подстановки:

```text
${contractparam.name}
${session.username}
${session.requestId}
```

BAA показывает сохраненные endpoint definitions в меню `Верификация`. Объект
можно сохранить из этого меню, после чего список обновляется и endpoint можно
выбрать повторно. Для запуска принимаются только endpoint definitions со
статусом `Active`; `Draft` и `Archived` остаются доступными для хранения и
администрирования, но не выполняются.

`ResultInterpretationJson` задает, как BAA трактует найденные строки:

```json
{
  "mode": "rows_present_is_error",
  "target": {
    "scope": "all_tables",
    "tableCode": ""
  },
  "severity": "error",
  "messageIfMatched": "Найдены данные, требующие внимания",
  "messageIfNotMatched": "Данные не найдены",
  "showTablesOnMatched": true,
  "showTablesOnNotMatched": false
}
```

Поддерживаются режимы `rows_present_is_error`, `rows_absent_is_error`,
`rows_present_is_warning`, `rows_absent_is_warning`, `manual_review` и
`technical_only`.

## Порядок взаимодействия

1. В BAA создается и наполняется BAA conversion contract.
2. Редактор готовит VSDX и строит план в `Подготовить объекты`.
3. В `Подготовить правила верификации / Контракты верификации` BAA формирует
   input/output contracts по готовым объектам плана.
4. BAA публикует input/output contracts по готовым объектам в CMDBuild.
5. Администратор `cmdbcustompages` читает опубликованные contracts из CMDBuild.
6. Администратор `cmdbcustompages` реализует endpoint проверки под input/output
   contracts.
7. В BAA в меню `Подготовить правила верификации` указываются endpoint URL,
   versions, параметры и `ResultInterpretationJson`. Input/output contracts
   выбираются из опубликованных Active contracts. Endpoint definition
   сохраняется в CMDBuild.
8. В меню `Верификация` пользователь выбирает сохраненный Active endpoint.
9. BAA вызывает endpoint POST JSON.
10. Перед вызовом BAA сверяет текущий план с выбранным input contract.
11. BAA валидирует ответ по выбранному output contract.
12. BAA применяет `ResultInterpretationJson`, показывает итог интерпретации и
    таблицы результата, если это разрешено настройкой.
13. При интерпретации `failed` или `technical_error` меню `Создать объекты`
    блокирует создание до успешной повторной внешней верификации. Если план
    перестроен, результат предыдущей проверки сбрасывается.

## Ответственность

- BAA отвечает за подготовку данных, публикацию contracts, вызов endpoint,
  интерпретацию наличия/отсутствия строк и отображение результата.
- CMDBuild хранит published contracts и endpoint definitions.
- `cmdbcustompages` отвечает за бизнес-логику выборки и компоновку данных из
  CMDB, но не принимает решение о прохождении проверки.

Формальное описание обмена для стороны `cmdbcustompage` находится в
`docs/cmdbcustompage-verification-exchange.md`.

Ручной E2E-сценарий проверки публикации contracts, сохранения endpoint
definition и будущей внешней верификации находится в
`docs/e2e-verification-scenario.md`.
