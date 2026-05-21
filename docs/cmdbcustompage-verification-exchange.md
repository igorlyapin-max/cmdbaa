# BAA and cmdbcustompage verification exchange

## Назначение

Документ описывает формальный порядок обмена между CMDB BAA и внешним
`cmdbcustompage` endpoint для бизнес-проверок. `cmdbcustompage` возвращает
найденные данные, а не решение о прохождении проверки. BAA интерпретирует факт
наличия или отсутствия строк по настройке endpoint definition.

## Ответственность

- BAA формирует план объектов, публикует input/output contracts, вызывает
  endpoint и интерпретирует результат.
- CMDBuild хранит `BAAVerificationInputContract`,
  `BAAVerificationOutputContract` и `BAAVerificationEndpoint`.
- `cmdbcustompage` читает опубликованные contracts, реализует endpoint и
  возвращает проверочную выборку в табличном формате.

## Endpoint

BAA вызывает endpoint методом `POST`. `EndpointUrl` хранится в
`BAAVerificationEndpoint` и может быть абсолютным URL или относительным путем
same-origin внутри `/cmdbuild`.

BAA передает текущий CMDBuild authorization token в header:

```text
CMDBuild-Authorization: <session token>
Content-Type: application/json
Accept: application/json
```

## Request body

```json
{
  "source": "CMDB BAA",
  "inputContract": {
    "code": "contract-verification-input-v1",
    "version": "1",
    "checksum": "sha256..."
  },
  "contractParams": [
    {
      "name": "environment",
      "description": "Execution environment",
      "type": "string",
      "required": true,
      "defaultValue": "prod",
      "listMode": "fixed",
      "values": ["prod", "test"],
      "help": ""
    }
  ],
  "endpoint": {
    "code": "network-acl-check",
    "params": {
      "environment": "prod"
    }
  },
  "plan": {
    "objects": [
      {
        "planIndex": 0,
        "kind": "context",
        "className": "ACL",
        "pageShapeKey": "visio/pages/page1.xml:12",
        "mappingKey": "connector:acl",
        "relationBindingStatus": "bound",
        "endpoints": {},
        "payload": {
          "Code": "ACL-001",
          "destinationAddress": "10.0.0.0/24"
        },
        "attributeSources": []
      }
    ],
    "missingAttributes": [],
    "skipped": []
  }
}
```

`cmdbcustompage` не должен полагаться на визуальный порядок объектов. Для
обратной ссылки используется `planIndex`, `className`, `pageShapeKey` и поля
`payload`. Переменные версии контракта передаются отдельно в
`contractParams`; это тот же набор, который описан в input contract как
`contractparam.*`.

## Response body

Технически успешный запрос возвращает `success: true`. Это означает только то,
что endpoint выполнил запрос и вернул данные. Это не означает, что бизнес-
проверка пройдена.

```json
{
  "success": true,
  "status": "completed",
  "title": "Destination networks",
  "message": "",
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

`tables[].rows[]` является расширяемым объектом. BAA валидирует оболочку,
`columns` и `rows`, но не требует заранее известного набора колонок. Это
позволяет `cmdbcustompage` возвращать дополнительные данные из CMDB для ручного
анализа.

## Техническая ошибка

Если endpoint не смог выполнить запрос, он возвращает `success: false` и
машинно-читаемые `items`.

```json
{
  "success": false,
  "status": "error",
  "message": "Недостаточно прав для чтения класса Network",
  "summary": {
    "rows": 0
  },
  "items": [
    {
      "level": "error",
      "code": "CMDB_PERMISSION_DENIED",
      "message": "Недостаточно прав для чтения класса Network"
    }
  ],
  "tables": []
}
```

## Интерпретация в BAA

BAA хранит правило интерпретации в
`BAAVerificationEndpoint.ResultInterpretationJson`:

```json
{
  "mode": "rows_present_is_error",
  "target": {
    "scope": "table",
    "tableCode": "destination_networks"
  },
  "severity": "error",
  "messageIfMatched": "Найдены destination, являющиеся сетями",
  "messageIfNotMatched": "Destination-сети не найдены",
  "showTablesOnMatched": true,
  "showTablesOnNotMatched": false
}
```

Поддерживаемые режимы:

- `rows_present_is_error` - строки есть, значит проверка не пройдена.
- `rows_absent_is_error` - строк нет, значит проверка не пройдена.
- `rows_present_is_warning` - строки есть, значит предупреждение.
- `rows_absent_is_warning` - строк нет, значит предупреждение.
- `manual_review` - данные показываются для ручного анализа.
- `technical_only` - учитывается только технический успех endpoint.

Создание объектов блокируется только для интерпретаций `failed` и
`technical_error`. `warning` и `manual_review` не блокируют создание, но
выводятся оператору.

## Совместимость

На переходный период BAA принимает старый ответ с `items` без `tables`. В этом
случае BAA показывает `items` как раньше. Новый табличный формат предпочтителен
для бизнес-проверок и ручного анализа.
