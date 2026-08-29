# Roadmap

Версия 2.0 фиксирует базовую продуктовую модель: Windows desktop управляет
Ubuntu через SSH, а на сервере нет постоянного агента. Следующие платформы
добавляются после стабилизации этой пары.

## 2.1 — эксплуатация Windows + Ubuntu

1. Подписанный Windows installer (MSIX или WiX), проверка WebView2 и корректное
   per-user обновление без admin elevation.
2. Подписанный release manifest: SHA-256, embedded public key, временный
   self-test и атомарная замена с сохранением предыдущей версии.
3. Планировщик на ПК администратора через Windows Task Scheduler: периодический
   `audit-all`, уведомления только о новых critical/high findings, без daemon на
   Ubuntu.
4. Полный GUI lifecycle SSH-ключей: fingerprints, двухфазная ротация, проверка
   отдельным соединением и точечный отзыв одной строки `authorized_keys`.
5. Hash-chain локальной истории и подписанный export bundle без секретов.
6. Проверяемый XHTTP update/uninstall plan с сохранением пользовательского
   экспорта и сертификатов по умолчанию.

## 2.2 — качество и восстановление

1. E2E-матрица настоящих Ubuntu 22.04/24.04 amd64/arm64 VM: первый root login,
   host-key replacement, install rollback, SSH/UFW recovery и reset.
2. Подписанный receipt тестового восстановления backup: время, backup ID,
   объекты и оператор без содержимого данных.
3. Canary apply для группы серверов и pause после каждого успешного узла.
4. Read-only advisory inventory по подписанному offline Ubuntu security feed.
5. Экспорт диагностического bundle с автоматической редактировкой адресов,
   usernames и путей.

## 3.0 — новые ОС через адаптеры

Порядок расширения:

1. Windows arm64 admin build.
2. macOS admin shell с тем же `internal/desktop` и SSH core.
3. Linux admin shell.
4. Debian server adapter после отдельной E2E-матрицы.
5. RHEL-compatible server adapter с отдельными package/firewall/service
   controls, без имитации Ubuntu-команд.

Registry, reports и snapshots останутся общими. Platform-specific shell и
server controls должны находиться за интерфейсами/сборочными границами; ветки
`if runtime.GOOS` внутри domain workflows не принимаются как готовая
архитектура.

## Осознанно не планируется

- постоянно доступный root-agent или собственный сетевой протокол;
- хранение SSH/sudo-паролей, passphrase, panel credentials или private UUID;
- автоматическое удаление неизвестных пользователей, пакетов, service data и
  firewall-правил;
- применение security policy без отдельного plan и точного подтверждения;
- обещание compliance или восстановимости backup без независимой проверки.
