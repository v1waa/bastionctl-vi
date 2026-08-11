# Secure Linux Wizard — русская инструкция

Версия комплекта: `2026.08.10-2`

Этот комплект помогает безопасно настроить личный Linux-сервер и компьютер администратора. При запуске можно выбрать:

1. `Server` — защита сервера;
2. `Admin's PC` — создание SSH-ключа и профиля на Linux, macOS или WSL;
3. `Audit` — подробная проверка сервера без изменения конфигурации.

Для Windows есть отдельный помощник `secure-linux-admin.ps1` с выбором `Admin's PC`, загрузкой серверного мастера и проверкой подключения.

## Главное о безопасности

Скрипт не может гарантировать «абсолютную безопасность». Безопасность зависит от приложений, данных, модели угроз, провайдера, резервных копий и регулярного обслуживания. Мастер создаёт разумную, проверяемую и обратимую базу.

Перед запуском обязательно:

- сделайте snapshot VPS или полную резервную копию;
- проверьте аварийную консоль/VNC у провайдера;
- не закрывайте текущую SSH-сессию до второго успешного входа;
- выпишите порты всех реально нужных сайтов, VPN и приложений;
- убедитесь, что приложения и базы данных имеют отдельные резервные копии.

Не запускайте скрипт через случайную конструкцию `curl ... | sudo bash`. Сначала скачайте комплект, проверьте контрольные суммы и прочитайте эту инструкцию.

## На чём основан комплект

Архитектура и набор проверок основаны на руководстве [How To Secure A Linux Server](https://github.com/imthenachoman/How-To-Secure-A-Linux-Server) Анчала Нигама, изученном 10 августа 2026 года. Исходное руководство распространяется по лицензии [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/).

Из руководства сохранены ключевые принципы:

- сначала определить модель угроз;
- до SSH-изменений открыть второй терминал;
- делать резервную копию каждого конфигурационного файла;
- использовать ключи SSH и ограничивать доступ;
- применять deny-by-default firewall;
- включить security-обновления, Fail2Ban, журналирование и аудит;
- считать настройки ядра и отключение root опасными операциями;
- проверять результат, а не только выполнять команды.

Мастер намеренно не копирует устаревающие списки шифров OpenSSH из руководства: современные дистрибутивы безопаснее обновляют криптографические значения по умолчанию. Он также не применяет вслепую весь раздел `Danger Zone`.

Подробная атрибуция находится в `THIRD_PARTY_NOTICES.md`.

## Состав комплекта

- `secure-linux-wizard.sh` — основной двуязычный Bash-мастер;
- `secure-linux-wizard-ru.sh` — запуск Bash-мастера сразу на русском;
- `secure-linux-wizard-en.sh` — запуск сразу на английском;
- `secure-linux-admin.ps1` — помощник для Windows PowerShell;
- `README_RU.md` — эта инструкция;
- `README_EN.md` — английская инструкция;
- `THIRD_PARTY_NOTICES.md` — источники, отличия и атрибуция;
- `LICENSE.txt` — лицензия;
- `SHA256SUMS.txt` — контрольные суммы файлов.
- `.github/workflows/ci.yml` — автоматические проверки Bash и PowerShell;
- `tests/smoke.sh` — локальные безопасные smoke-тесты;
- `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md` — файлы проекта для GitHub.

## Поддерживаемые системы

Сервер:

- Ubuntu Server 22.04/24.04 и Debian 12/13 — основной поддерживаемый путь;
- Fedora и RHEL-подобные системы с `dnf`, `firewalld` и `systemd` — базовая поддержка; для Fail2Ban/Lynis может потребоваться дополнительный репозиторий;
- необходим OpenSSH Server и `systemd`;
- выбранный администратор должен иметь обычный домашний каталог `/home/ИМЯ`, не являющийся символической ссылкой и не доступный для записи группе/всем;
- контейнеры Docker и VPN обнаруживаются, но их сетевые правила не переписываются автоматически.

ПК администратора:

- Windows 10/11 с Windows PowerShell 5.1+ и компонентом OpenSSH Client;
- Linux, macOS или WSL с `bash`, `ssh`, `ssh-keygen`;
- на macOS мастер использует Keychain, на Windows — службу `ssh-agent`, на Linux/WSL — пользовательский `ssh-agent`.

Другие дистрибутивы лучше сначала запускать только с `--dry-run` и адаптировать вручную.

## Что именно настраивается

### В режиме Server

- создаётся или используется отдельный администратор с `sudo`/`wheel`;
- устанавливается его открытый SSH-ключ;
- OpenSSH получает отдельный drop-in-файл, проверяемый через `sshd -t`;
- password/root-вход отключается только после подтверждённого входа по ключу из второго терминала;
- UFW или firewalld гарантированно разрешает SSH и выбранные публичные порты; уже существующие разрешения сохраняются, чтобы не сломать сервисы, и показываются в аудите;
- Fail2Ban защищает SSH от перебора;
- security-обновления включаются без автоматической перезагрузки;
- `journald` хранит сжатый постоянный журнал;
- применяются совместимые `sysctl`-параметры защиты;
- включается синхронизация времени;
- усиливаются правила будущих локальных паролей и базовые настройки `sudo`;
- устанавливаются `auditd` и Lynis, если они доступны;
- создаётся подробный журнал и точка восстановления;
- в конце выполняется контроль служб и конфигурации.

Мастер не изменяет автоматически:

- `ip_forward`, IPv6 forwarding, `rp_filter`, NAT и Docker Compose;
- дисковое шифрование, GRUB и пароль root;
- AppArmor/SELinux-политики приложений;
- правила CrowdSec/PSAD, AIDE-базу, антивирус или rootkit-сканеры;
- конфигурацию Nginx/Apache и самих веб-приложений;
- данные PostgreSQL и прикладные резервные копии;
- текущие Docker-сети и привилегии контейнеров;
- перезагрузку сервера.

Эти области зависят от назначения сервера и требуют отдельного тестирования.

### В режиме Admin's PC

- создаётся Ed25519-ключ с усиленным KDF (`-a 100`);
- кодовая фраза задаётся интерактивно и никогда не записывается скриптом;
- настраивается `ssh-agent`/Keychain;
- создаётся отдельный SSH-профиль с `IdentitiesOnly yes`;
- открытый `.pub`-ключ можно скопировать на сервер;
- вход по ключу проверяется автоматически.

`ssh-agent` — правильный способ не вводить кодовую фразу при каждом подключении. Удалять кодовую фразу из приватного ключа не рекомендуется.

## Рекомендуемый порядок: Windows + VPS

### 1. Распакуйте комплект

Распакуйте ZIP в отдельную папку, например:

```powershell
cd "$env:USERPROFILE\Downloads\secure-linux-wizard"
Get-ChildItem
```

Проверьте хэш основного скрипта и сравните его со строкой в `SHA256SUMS.txt`:

```powershell
Get-FileHash .\secure-linux-wizard.sh -Algorithm SHA256
Get-Content .\SHA256SUMS.txt
```

### 2. Настройте Admin's PC

Откройте обычный PowerShell в папке комплекта:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\secure-linux-admin.ps1 -Language ru
```

Выберите `Admin's PC` и укажите:

- короткое имя, например `myvps`;
- IP/домен сервера;
- существующего SSH-пользователя;
- текущий SSH-порт;
- путь ключа или предложенный путь по умолчанию.

При создании ключа задайте длинную уникальную кодовую фразу. Когда `ssh-add` попросит её, введите один раз. Скрипт не видит и не сохраняет эту фразу.

Если включение Windows `ssh-agent` требует прав администратора, откройте отдельный PowerShell от имени администратора и выполните:

```powershell
Set-Service ssh-agent -StartupType Automatic
Start-Service ssh-agent
ssh-add "$env:USERPROFILE\.ssh\myvps_ed25519"
```

Вернитесь в обычный PowerShell и проверьте:

```powershell
ssh-add -l
ssh myvps
```

### 3. Загрузите серверный мастер

Снова запустите PowerShell-помощник и выберите `Server`, либо вручную:

```powershell
scp .\secure-linux-wizard.sh myvps:/tmp/secure-linux-wizard.sh
ssh -t myvps "sudo bash /tmp/secure-linux-wizard.sh"
```

Если профиль ещё не создан, используйте явный ключ:

```powershell
ssh -i "$env:USERPROFILE\.ssh\myvps_ed25519" -o IdentitiesOnly=yes USER@SERVER_IP
```

### 4. Ответьте на главные вопросы Server-мастера

Мастер спросит только решения, которые нельзя безопасно угадать:

1. имя администратора;
2. список пользователей SSH;
3. порт SSH;
4. публичные TCP/UDP-порты;
5. доверенные IP/CIDR для Fail2Ban;
6. нужны ли SSH-туннели;
7. какие защитные модули включить.

По умолчанию список портов берётся из уже работающих публичных слушателей, чтобы не сломать сервисы. Для максимальной защиты удалите из списка всё ненужное. Порт SSH добавляется отдельно.

Примеры:

- обычный сайт: TCP `22,80,443`, UDP пусто;
- сайт + WireGuard: TCP `22,80,443`, UDP `51820`;
- нестандартный VPN: укажите реальные порты из `ss -lntup` и конфигурации VPN.

Не открывайте PostgreSQL `5432`, Redis `6379`, панели администратора и внутренние Node/Python-порты всему интернету. Они должны слушать `127.0.0.1`, приватную VPN-сеть или иметь строгое IP-ограничение.

### 5. Проверьте второй вход до блокировки SSH

Когда мастер остановится на проверке, не закрывайте первое окно. В новом PowerShell выполните:

```powershell
ssh myvps
whoami
sudo -v
```

Только если вход и `sudo` работают, ответьте мастеру `Да`. Тогда он применит:

```text
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
AllowUsers ...
```

Если ответить `Нет`, сервер останется доступен по старому способу, а завершить блокировку можно позже:

```bash
sudo secure-linux-wizard --finalize-ssh --lang ru
```

### 6. Выполните аудит

```bash
sudo secure-linux-wizard --audit --lang ru
```

Аудит показывает:

- эффективные параметры SSH;
- отпечатки открытых ключей;
- firewall и Fail2Ban;
- все слушающие порты;
- критичные службы;
- состояние автоматических обновлений;
- параметры ядра и MAC;
- Docker-контейнеры и опубликованные порты;
- файлы секретов, доступные всем на чтение, без показа содержимого;
- последние входы и требование перезагрузки.

### 7. Перезагрузите планово

Мастер никогда не перезагружает сервер автоматически. Если он сообщил о необходимости перезагрузки, сначала убедитесь, что второй SSH-вход работает, затем:

```bash
sudo reboot
```

Через минуту:

```powershell
ssh myvps
```

И повторите аудит.

## Linux/macOS/WSL как Admin's PC

```bash
chmod +x secure-linux-wizard.sh
bash secure-linux-wizard.sh --role admin --lang ru
```

Для запуска на сервере:

```bash
scp secure-linux-wizard.sh myvps:/tmp/
ssh -t myvps 'sudo bash /tmp/secure-linux-wizard.sh --role server --lang ru'
```

На Linux мастер создаёт файл окружения агента в `~/.local/state/secure-linux-wizard/ssh-agent.env`. Для нового терминала выполните показанную команду `source ...`. На macOS используется `UseKeychain yes`.

## Проверка без изменений

Перед реальной настройкой:

```bash
sudo bash secure-linux-wizard.sh --role server --lang ru --dry-run
```

`--dry-run` показывает планируемые команды и файлы, но не устанавливает пакеты и не меняет конфигурацию. На редкой или сильно изменённой системе сначала используйте только этот режим.

## Неинтерактивные безопасные значения

```bash
sudo bash secure-linux-wizard.sh --role server --lang ru --yes --snapshot-confirmed
```

`--yes` принимает совместимые значения по умолчанию, но требует явный флаг `--snapshot-confirmed`: этим вы подтверждаете наличие внешнего snapshot и аварийной консоли. Он никогда автоматически не отключает парольный/root-вход. Финализация SSH всё равно требует отдельной команды и проверки ключа.

## Журналы и резервные точки

На сервере:

```text
/var/log/secure-linux-wizard/*.log
/root/secure-linux-wizard-backups/YYYYmmddTHHMMSSZ/
```

На Windows:

```text
%LOCALAPPDATA%\SecureLinuxWizard\Logs\
```

На Linux/macOS/WSL:

```text
~/.local/state/secure-linux-wizard/
```

Журналы не включают приватные ключи, кодовые фразы или содержимое `.env`. Открытые ключи устанавливаются, но их приватная часть никогда не передаётся на сервер.

## Откат

В конце мастер печатает точную команду. Общий вид:

```bash
sudo secure-linux-wizard --rollback /root/secure-linux-wizard-backups/YYYYmmddTHHMMSSZ --lang ru
```

Откат восстанавливает только конфигурационные файлы, которые изменил мастер. Он не удаляет установленные пакеты, пользовательские данные и приложения. После отката обязательно проверьте:

```bash
sudo sshd -t
sudo systemctl reload ssh 2>/dev/null || sudo systemctl reload sshd
sudo ufw status verbose 2>/dev/null || sudo firewall-cmd --list-all
sudo systemctl --failed
```

При полной потере SSH используйте аварийную консоль провайдера и выполните откат там.

## Docker и VPN

UFW сам по себе не гарантирует фильтрацию опубликованных Docker-портов: Docker создаёт собственные правила netfilter. Поэтому мастер:

- не сбрасывает iptables/nftables;
- не меняет `ip_forward`, NAT, Docker bridge и VPN-маршруты;
- предупреждает о Docker;
- показывает опубликованные порты в аудите.

Для каждого контейнера проверьте `ports:`/`-p`. Внутренние приложения публикуйте на loopback, например:

```yaml
ports:
  - "127.0.0.1:3000:3000"
```

VPN-порты оставляйте публичными только если они действительно используются. После изменения firewall проверяйте VPN с внешнего устройства.

## Частые проблемы

### `Permission denied (publickey)`

На Windows явно укажите ключ:

```powershell
ssh-keygen -lf "$env:USERPROFILE\.ssh\myvps_ed25519.pub"
ssh -vv -i "$env:USERPROFILE\.ssh\myvps_ed25519" -o IdentitiesOnly=yes USER@SERVER
```

На сервере из старой/аварийной сессии:

```bash
sudo ls -ld /home/USER /home/USER/.ssh
sudo ls -l /home/USER/.ssh/authorized_keys
sudo ssh-keygen -lf /home/USER/.ssh/authorized_keys
sudo sshd -T | grep -E '^(port|allowusers|pubkeyauthentication|passwordauthentication|permitrootlogin) '
```

Ожидаемые права: `.ssh` — `700`, `authorized_keys` — `600`, владелец — сам пользователь.

### Fail2Ban не запускается

```bash
sudo fail2ban-client -t
sudo systemctl status fail2ban --no-pager -l
sudo journalctl -u fail2ban -n 150 --no-pager
sudo tail -n 150 /var/log/fail2ban.log
```

Мастер использует только числовые значения времени и не записывает выражения вида `10*60`, которые старые версии Fail2Ban могут отвергать.

### Сайт перестал открываться

```bash
sudo ss -lntup
sudo nginx -t 2>/dev/null || true
sudo ufw status numbered 2>/dev/null || sudo firewall-cmd --list-all
```

Если процесс слушает только `127.0.0.1`, к нему должен вести Nginx/Apache reverse proxy. Если сервис должен быть публичным, добавьте его реальный порт в firewall, но сначала убедитесь, что это безопасно.

### VPN перестал подключаться

Сверьте UDP/TCP-порты с конфигурацией и Docker:

```bash
sudo ss -lntup
sudo docker ps --format 'table {{.Names}}\t{{.Ports}}\t{{.Status}}'
sudo ufw status verbose 2>/dev/null || sudo firewall-cmd --list-all
```

Мастер не отключает forwarding, но неверно выбранный входящий порт всё равно заблокирует VPN.

## Регулярное обслуживание

Еженедельно:

```bash
sudo systemctl --failed
sudo fail2ban-client status sshd
sudo journalctl -p warning --since '7 days ago'
```

Ежемесячно:

```bash
sudo apt update && apt list --upgradable       # Debian/Ubuntu
sudo dnf check-update                          # Fedora/RHEL
sudo lynis audit system
sudo secure-linux-wizard --audit --lang ru
```

Также регулярно проверяйте восстановление резервных копий, обновляйте приложения/контейнеры, удаляйте старые ключи, пересматривайте открытые порты и следите за уведомлениями вашего дистрибутива.
