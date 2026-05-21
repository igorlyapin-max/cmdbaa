# Карта HealthCheck

| ID | Проверка | Источник | Назначение |
|---|---|---|---|
| HC-01 | `/cmdbuild/baa/api/session` | Browser | Проверить, что cookie CMDBuild передан proxy |
| HC-02 | CMDBuild `/sessions/current` | CMDB BAA reverse proxy | Проверить валидность сессии |
| HC-03 | UI route `/cmdbuild/baa/ui/*` | Browser / monitoring | Проверить доступность custom page |
| HC-04 | CMDB classes list | CMDB BAA reverse proxy | Проверить доступность REST catalog |

Идентификаторы `HC-*` должны использоваться в эксплуатационных схемах и карте
регистрации событий.
