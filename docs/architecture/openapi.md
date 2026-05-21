# OpenAPI-контур

Формальная OAS спецификация пока не выделена в отдельный YAML. Ниже зафиксирован
перечень HTTP операций, которые должны быть отражены в OpenAPI при стабилизации
API.

| Method | Path | Назначение |
|---|---|---|
| GET | `/cmdbuild/baa/api/session` | Проверка CMDBuild session |
| GET | `/cmdbuild/baa/api/csrf` | Получение CSRF token |
| GET/POST | `/cmdbuild/baa/api/contracts` | Список и создание контрактов |
| GET | `/cmdbuild/baa/api/contract-versions` | Список версий контрактов |
| POST | `/cmdbuild/baa/api/schema/preview` | Предпросмотр схемы BAA |
| POST | `/cmdbuild/baa/api/schema/bootstrap` | Создание схемы BAA |
| GET | `/cmdbuild/baa/api/cmdb/classes` | Список классов CMDB |
| GET | `/cmdbuild/baa/api/cmdb/classes/{className}/attributes` | Атрибуты класса |
| POST | `/cmdbuild/baa/api/vsdx/inspect` | Разбор VSDX |
| POST | `/cmdbuild/baa/api/vsdx/enrich` | Сохранение контракта/шаблона |
| POST | `/cmdbuild/baa/api/vsdx/check-template` | Техническая проверка шаблона |
| POST | `/cmdbuild/baa/api/vsdx/verify` | Бизнес-верификация |
| POST | `/cmdbuild/baa/api/vsdx/create-objects` | Планирование/создание объектов |
| POST | `/cmdbuild/baa/api/verification/contracts/generate` | Генерация verification input/output contracts |
| POST | `/cmdbuild/baa/api/verification/contracts/publish` | Публикация verification contracts в CMDBuild |
| GET/POST | `/cmdbuild/baa/api/verification/endpoints` | Список/создание endpoint definitions |
| POST | `/cmdbuild/baa/api/verification/endpoints/list` | Список endpoint definitions с учетом настроенного класса |
| POST | `/cmdbuild/baa/api/verification/run` | Вызов внешнего endpoint cmdbcustompages, validation output contract, интерпретация tables/items |

Все операции выполняются same-origin через `/cmdbuild`. Авторизация основана на
CMDBuild HttpOnly cookie.
