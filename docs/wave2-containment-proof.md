# Доказательство macOS browser containment

outcome: ready

reason: proof_valid

browser_state: ready

backend: pf_uid_anchor_guardproxy

reboot_verified: true

negative_control: red

## Вердикт

Владелец выбрал ветку `templates applied and rebooted; verify`. Разрешённый генератор от root
записал runtime receipt со `status: ready`, `reason: containment_ready`,
`reboot_verified: true`, `canary.status: passed` и пустым `detected_channels`. Receipt остаётся в
`.lynceuz/security/macos-containment-receipt-v1.json` и в git не добавляется.

Read-only gate вернул `status: passed`, `containment_state: ready`, `reason: proof_valid` и backend
`pf_uid_anchor_guardproxy`. Negative control завершился ненулевым кодом с
`reason: containment_removed_channels_reachable`, `canary.status: red` и
`detected_channels: ["direct_tcp", "udp", "quic"]`.

## Reboot-bound доказательство

После перезагрузки PF включён с загрузки. Главный набор содержит
`anchor "com.lynceuz/browser" all`, а внутри anchor загружены три правила:

- TCP от uid 401 к `127.0.0.1:48191` разрешён.
- Остальной IPv4 egress uid 401 блокируется.
- Остальной IPv6 egress uid 401 блокируется.

Живой стенд подтвердил действие правил. Пользователь uid 501 дошёл до обеих TCP-мишеней.
`_lynceuz` uid 401 дошёл до GuardProxy за 0 секунд, а соединение с не-loopback адресом получило
`block drop` и завершилось через 76 секунд. Закрытый порт отдельно дал отказ за 0 секунд. Значит,
долгое ожидание вызвал молчаливый PF drop, а разрешённый путь через GuardProxy сохранился.

До установки PF был выключен. Launchd включает его машинно через `pfctl -E`, поэтому containment
меняет общее состояние хоста; область изменения шире uid 401. Остаточный риск совета:
разведка может не обнаружить динамического потребителя PF. UTM и WireGuard установлены;
WireGuard при запуске может менять PF динамически.

## Почему receipt привязан к перезагрузке

Исторический замер поймал опасный ложноположительный случай. До перезагрузки файлы были
установлены, PF включён, а правила загружены внутрь anchor. Но сам anchor был заполнен, но не
подключён к главному набору. uid 401 тогда свободно дошёл до не-loopback TCP за 0 секунд.

Наличие файлов и вывод `pfctl -a com.lynceuz/browser -sr` выглядели исправно, хотя containment не
работал. После загрузки ссылка на anchor появилась в главном наборе без ручного `pfctl -f`, а
канарейка подтвердила блокировку. Поэтому `ready` требует `reboot_verified: true` и живой positive
контроль, а не проверку установленных артефактов.

## Контракт канарейки

Канарейка проверяет каждый канал отдельно и засчитывает только подтверждённый ответ:

- `proxy_tcp`: ответ `LYNCEUZ_PROXY_TCP_OK` обязателен; иначе разрешённый путь GuardProxy сломан.
- `direct_tcp` (TCP): при containment ответа `LYNCEUZ_DIRECT_TCP_LEAK` быть не должно.
- `udp` (UDP): при containment ответа `LYNCEUZ_UDP_LEAK` быть не должно.
- `quic` (QUIC): при containment ответа `LYNCEUZ_QUIC_RETRY_LEAK` быть не должно.

Positive контроль проходит, когда GuardProxy отвечает, а TCP, UDP и QUIC не отвечают. Negative
control запускается со снятым containment. Все три прямых канала обязаны ответить,
`detected_channels` обязан содержать `direct_tcp`, `udp`, `quic`, `canary.status` обязан стать
`red`, а процесс завершиться ненулевым кодом. Если хотя бы один ответ не подтверждён, результат
равен `invalid_negative_control`, а не красному контролю. При снятом containment канарейка обязана
краснеть.

## Дефект стенда: TIME_WAIT на 48191

Генератор receipt сначала запускает свою канарейку. После неё `127.0.0.1:48191` может остаться в
состоянии `TIME_WAIT`, а следующий стенд обязан занять ровно `48191`: PF разрешает contained uid
только этот порт. Немедленный запуск gate тогда дважды воспроизводимо падал с
`listen EADDRINUSE ... 127.0.0.1:48191`.

Голый `catch {}` в `positiveCanary` скрывает `EADDRINUSE` за общей причиной
`containment_canary_failed`. Получается отказ прибора, похожий на отказ containment. Безопасный
порядок проверки: сгенерировать receipt, дождаться освобождения `48191`, затем запускать gate.
Receipt живёт 5 минут, `TIME_WAIT` занимает десятки секунд; `check_cmd` ждёт освобождения порта.
