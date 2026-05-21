# CMDB BAA: инструкция администратора

## Назначение администратора

Администратор отвечает за развертывание reverse proxy, доступ к CMDBuild,
создание технической схемы BAA и эксплуатационные настройки.

## Reverse proxy и маршруты

BAA работает под `/cmdbuild`, чтобы браузер отправлял HttpOnly cookie CMDBuild
на тот же origin. Frontend не читает `CMDBuild-Authorization`; proxy читает
сессионный cookie и использует токен только на серверной стороне.

Основные маршруты:

```text
/cmdbuild/baa/ui/prepare-template
/cmdbuild/baa/ui/check-template
/cmdbuild/baa/ui/prepare-objects
/cmdbuild/baa/ui/prepare-verification
/cmdbuild/baa/ui/verify
/cmdbuild/baa/ui/create-objects
/cmdbuild/baa/ui/contracts
/cmdbuild/baa/ui/settings
/cmdbuild/baa/ui/types
/cmdbuild/baa/ui/schema
/cmdbuild/baa/ui/about
/cmdbuild/baa/api/*
```

Локальный dev URL:

```text
http://127.0.0.1:8094/cmdbuild/ui/?baSection=prepare-template#custompages/CmdbBaa
```

Порт `8094` в текущем контуре не меняется при перезапуске.

## Настройки окружения

```text
PROXY_HOST=127.0.0.1
PROXY_PORT=8094
CMDBUILD_ORIGIN=http://127.0.0.1:8090
CMDBBAA_CSRF_SECRET=<random-secret>
CMDBBAA_PROXY_COOKIE_SAMESITE=
CMDBBAA_PROXY_COOKIE_SECURE=false
```

## Схема CMDBuild

Схема создается только по явной кнопке пользователя в меню `Настройки / Схема`.
Автоматический bootstrap при входе в интерфейс запрещен.

Администратор выбирает:

- имя технического суперкласса BAA;
- родительский суперкласс или режим без родителя;
- описание технического суперкласса.

BAA создает и проверяет:

- технический superclass BAA;
- `BAAConversionContract`;
- `BAAConversionContractVersion`;
- `BAAVerificationInputContract`;
- `BAAVerificationOutputContract`;
- `BAAVerificationEndpoint`.

`Code` и `Description` являются обязательными системными атрибутами CMDBuild и
учитываются как обязательные при создании объектов.

Сохранение обогащенного VSDX и фиксация новой версии контракта требуют только
технический superclass BAA, `BAAConversionContract` и
`BAAConversionContractVersion`. Классы внешней верификации нужны для
`Подготовить правила верификации` и `Верификация`; их отсутствие не должно
блокировать `Сохранить шаблон`.

## Контрольные суммы

Расширение файла суммы задается в `Настройки / Общие`. BAA ищет файл вида:

```text
<filename.ext>.<sumextension>
```

Проверка контрольной суммы при подготовке шаблона включается отдельной галкой.
Статус показывается в верхней панели:

- красный - сумма не проверялась или проверка не прошла;
- зеленый - сумма проверена успешно.

Реальное создание объектов в CMDBuild дополнительно требует загруженный файл
контрольной суммы. Если файл суммы отсутствует или не совпадает с текущим VSDX,
endpoint создания возвращает ошибку и не отправляет карточки в CMDBuild.

## Валидаторы CMDBuild

Настройка `Проверить валидатором CMDB внутри системы` включена по умолчанию.
Если тестовая модель CMDBuild не повторяет модель заказчика и валидатор дает
ложные ошибки, настройку можно отключить. При отключении BAA показывает красное
предупреждение у атрибутов, где CMDB validation существует, но локально не
проверяется.

## Внешняя верификация

В `Настройки / Общие` задаются классы, где BAA ищет и создает input/output
contracts и endpoint definitions для внешней верификации. По умолчанию
используются технические классы BAA:

- `BAAVerificationInputContract`;
- `BAAVerificationOutputContract`;
- `BAAVerificationEndpoint`.

Порядок обмена с `cmdbcustompages` описан в `docs/verification-contracts.md`.
Формальное описание request/response для передачи команде `cmdbcustompage`
находится в `docs/cmdbcustompage-verification-exchange.md`.
BAA публикует contracts в CMDBuild, после чего администратор `cmdbcustompages`
реализует endpoint проверки. В меню `Подготовить правила верификации`
указываются endpoint URL, версии contracts, `ParamsJson` и правило
`ResultInterpretationJson`; там же сохраняется endpoint definition. В меню
`Верификация` пользователь выбирает сохраненный `Active` endpoint и запускает
проверку. Перед вызовом endpoint BAA сверяет текущий план с выбранным input
contract, а ответ endpoint валидирует по выбранному output contract.
`cmdbcustompage` возвращает найденные данные, а BAA интерпретирует наличие или
отсутствие строк. Создание объектов блокируется только при интерпретации
`failed` или `technical_error`.

Минимальный ручной E2E-сценарий эксплуатации описан в
`docs/e2e-verification-scenario.md`. Автоматический smoke-level тест внешней
верификации добавляется после готовности тестового endpoint.

## Эксплуатационные договоренности

- Пользовательские данные в VSDX пишет редактор шаблона.
- BAA пишет только `_baa_` и `template_` Shape Data.
- Чужие Shape Data не трогаются.
- Удаление версии контракта делает невозможной проверку и конвертацию
  шаблонов, которые на нее ссылаются.
- Удаление объекта контракта делает невозможной дальнейшую валидацию и
  конвертацию связанных шаблонов.

## Проверки после доработок

Минимальный набор локальных проверок:

```bash
npm run check
node -e 'const fs=require("fs"); const s=fs.readFileSync("scripts/dev-proxy-server.mjs","utf8"); const start=s.indexOf("function clientScript() {"); const end=s.indexOf("\n\nasync function handleUi", start); const fnSrc=s.slice(start,end); const clientScript=(0,eval)("("+fnSrc+")"); const js=clientScript(); new Function(js); console.log("evaluated client script syntax ok");'
git --git-dir=/tmp/cmdbaa.git --work-tree=/home/lsk/projects/cmdbaa diff --check
```

После изменения UI proxy перезапускается на том же `127.0.0.1:8094`.
