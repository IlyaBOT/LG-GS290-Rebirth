# LG GS290 V10C SEA — статический аудит Java/Flash/браузера

**2026-10-21.** Исследован заводской пакет V10C, **не** дамп установленного у пользователя V10k CIS. Только офлайновый анализ; USB/телефон не трогали. Вердикты: CONFIRMED — факт из проверенного кода/ресурса; LIKELY — подозреваемый дефект; HYPOTHESIS — без подтверждения. **Работающее RCE, повышение прав или запуск альтернативной ОС не продемонстрированы.**

## Доказательная база

Codex восстановил KDZ → CAB → RC4/MD5 WDB → Infineon FLS/FLB → два сегмента ARM + FAT16 DFAT. Ключ строится из размера `Inf_WebDnld.dll` (163840), а не WDB: `bgfpha`, MD5 `0699aac1e4995258df035de6edfb0e68`.

Файлы из пользовательского `firmware.zip` независимо проверены:
- `MPEH_segment0_46c00000.bin`, 11184688 байт, SHA-256 `0f9338bb6e6a80205ebd4a1d726a46eb039bbec9409b47e3138b079cffc3fa3c`.
- `MPEH_segment1_47800000.bin`, 17272832 байта, SHA-256 `f34f69dacfe5b570fafaa9e102196ebfa8fbeb9b01c5459cc0424661e67387a4`.
- `COOKIE2_ESA_COMMON_OPEN-CUST.dfat.segment0.bin`, 141777408 байт, FAT16. Манифест Codex: 2286 файлов, 258 директорий. Для данного аудита выборочно извлечены и проверены SHA-256 **510 файлов**. Смещения `source_extents` относятся к исходному Infineon контейнеру: для обращения к raw payload следует вычесть `0xCF8`.

ВНИМАНИЕ: `SEA` в имени скачивания не совпадает с найденной ранее внутренней строкой версии `GS290AT-00-V10c-AME-XXX-AUG-09-2010+0`. Карта download/runtime адресов уточняется. Старый `V10D_00.kdz` оказался образом LG GU297/Qualcomm — не использовать как свидетельство о GS290.

## F-01 — возможный перепуск стека в DEFLATE Java/JAR (LIKELY)

Код `MPEH_segment1_47800000.bin` с VA `0x47876D0C` (смещение `0x76D0C`) связан с DEFLATE code-length decoding в Java VM. Независимо прочитаны реальные ARM-байты и дизассемблирована ветка:

| VA | Наблюдаемая семантика |
|---|---|
| `0x47876E1C–28` | инициализирует **320-байтовый** буфер от `sp+12` |
| `0x47876E30–40` | вычисляет `logical_end = sp+12+HLIT+HDIST` |
| `0x47876F14` | `add r0,r7,r1` — адрес после повтора |
| `0x47876F24` | `cmp r0,r1` — сравнение с `logical_end` |
| `0x47876F28` | `bls 0x47876F5C` |
| `0x47876F2C–58` | на превышении **только условный диагностический путь**, далее fall-through; обязательного отказа нет |
| `0x47877020–2C` | чтение предыдущей длины, передача `dst=r7`, `count=[sp+4]` в `0x46D94800` |
| `0x46D94800–0C` | helper формирует повторяемый байт и передаёт управление fill-подпрограмме `0x46D80324` |

Максимальные допустимые `HLIT+HDIST` — 318; repeat-16 допускает 3–6 значений. Арифметическая модель: позиция 317 + 6 записей = 323, что выходит за 320-байтовый буфер на 3 байта. **Это не тест готового сжатого потока**: неизвестны достижимость всей последовательности, проверка вызывающих функций и возможное отклонение JAR раньше. Требуется CPU-only эмуляция с защитными областями памяти и call graph от `0x47877B00`/JAR reader. Нельзя утверждать эксплуатацию или RCE на V10k.

## F-02 — HTTP XML → JSON-like string → storage → eval в Obigo Weather (CONFIRMED dataflow)

SHA-256-верифицированный ресурс: `LGAPP/Obigo/wga/widgets/Weather/data/weather.js`.

1. `req.open("GET", "http://lgelc.accu-weather.com/widget/lgelc/weather-data.asp?location=" + ...)` — транспорт нешифрованный.
2. `validateData()` берёт `req.responseXML` / `nodeValue` в поля `today` и `forecast`.
3. `toJsonStr()` конкатенирует значения в кавычках **без экранирования JSON/JS**.
4. `printData()` сохраняет строки через `widget.setPreferenceForKey`.
5. `printLastData()` использует `eval('(' + td + ')')` и аналогично для `fd[i]`.

При контролируемом HTTP-ответе вероятно возможно исполнение скрипта в **контексте виджета**. Проверка работы на устройстве, обработка схемы XML и привилегии widget bridge отсутствуют. Это **не** доказанный native ARM RCE, и обычный браузер может иметь другие ограничения. В `config.xml`: `AccuWeather 1.0`, `netaccess=yes`.

## F-03 — модель разрешений Java (CONFIRMED policy)

`LGAPP/Media/Java_Original/cert/opn.pol`: домены `untrusted`, `Operator Protection Domain`, `Manufacturer Protection Domain`, `Identified Third Party Protection Domain`. У untrusted на файловые read/write доступны `oneshot`-разрешения; у operator/manufacturer — `allow`. В конце политики явный комментарий, что перечисленные ниже developer certificates не должны быть в официальном выпуске, но там же включён operator alias `C=KR;O=LGE;CN=LGE JAVA`. В `sys/cert.ini` `001. lge-java.crt` отмечен как operator/invisible; сертификат самоподписанный RSA-1024 с подписью MD5-with-RSA. В ini есть ссылка на `003. ca-lge (developer).crt`, который не обнаружен среди десяти присутствующих сертификатов. **Приватный ключ не найден, обход подписи не доказан.**

## F-04 — SWF/Flash (CONFIRMED surface, no bug confirmed)

13 `LGAPP/DMF/Game/*.swf`: у **12** — `CWS` на смещении 8 (v7/v8) и `78 9c` на смещении 16. Все 12 **не** распаковываются стандартным `zlib.decompress(file[16:])`; у `main.swf` есть оболочка `DMF`. Это нестандартная упаковка/трансформация, а **не обычные проверенные SWF**. В нативной прошивке присутствуют строки `ASVM VERSION`, `_GJLibPlayer_LaunchFlash`, `MMAPI_VG_CheckSWFDataBufferValidity`, `DigitalAria.%d.Multipart`. Название версии и происхождение декодера пока не установлены; desktop Adobe Flash CVE не переносить автоматически.

## F-05 — Obigo/browser (CONFIRMED assets, core HYPOTHESIS)

В манифесте 473 файла под `LGAPP/Obigo`, включая HTML/CSS/JS локального Weather-виджета; `LGAPP/Pxo/Internet.pxo` всего 2731 байт с `PXO4`-маркером. Browser-core ещё не локализован. Встроенный Weather использует DOM, XMLHttpRequest, eval и `widget.*` API. Нет доказательств, что обычные внешние веб-страницы наследуют полномочия встроенного виджета или имеют путь к нативной записи памяти.

## Приоритет исследований

1. Подтвердить достижимость F-01 от загрузки недоверенного JAR и поведение нативного заполнения **в CPU-эмуляции с redzone**.
2. Изучить изоляцию `widget`-API, сетевые источники и границы контекста в Obigo.
3. Восстановить DMF/CWS-трансформацию и проверить обработку длин в native Flash loader.
4. Только после подтверждения оригинального **V10k CIS** сравнивать бинарники. Не подключать телефон/не менять загрузчик.

Офлайн-проверки для указанной пары сегментов: `tools/check_v10c_evidence.py`. Функция проверяет SHA и реальные опкоды, но **не имитирует готовую эксплойт-цепь**.
