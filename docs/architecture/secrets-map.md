# Карта секретов

| ID | Секрет | Где используется | Ротация |
|---|---|---|---|
| SEC-01 | CMDBuild session cookie | Browser -> proxy -> CMDBuild REST | По политике CMDBuild session |
| SEC-02 | `CMDBBAA_CSRF_SECRET` | CMDB BAA reverse proxy | При установке и при компрометации |
| SEC-03 | TLS private key reverse proxy | Внешний HTTPS endpoint | По политике контура |

BAA frontend не читает `CMDBuild-Authorization`. Токен используется только
server-side reverse proxy.
