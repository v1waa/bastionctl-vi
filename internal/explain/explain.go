package explain

import "sort"

type Entry struct {
	Control  string `json:"control"`
	Purpose  string `json:"purpose"`
	Risk     string `json:"risk"`
	Check    string `json:"check"`
	Rollback string `json:"rollback"`
}

var entries = map[string]Entry{
	"platform":          {"platform", "Проверяет поддерживаемую Debian/Ubuntu, apt и systemd.", "На другой системе команды и пути могут иметь иной смысл.", "cat /etc/os-release; command -v apt-get systemctl", "Изменений не выполняет."},
	"packages":          {"packages", "Устанавливает компоненты базовой защиты из доверенных репозиториев дистрибутива.", "Установка пакета может включить сервис или добавить зависимости.", "dpkg-query -W openssh-server ufw fail2ban auditd apparmor chrony", "Пакеты автоматически не удаляются; удаляйте только после ручной проверки зависимостей."},
	"automatic-updates": {"automatic-updates", "Включает регулярную установку обновлений безопасности.", "Обновление иногда меняет поведение сервиса; автоматический reboot выключен по умолчанию.", "apt-config dump; systemctl status unattended-upgrades", "Восстановить backup файла 52bastionctl-unattended-upgrades и перезапустить сервис."},
	"sysctl":            {"sysctl", "Усиливает безопасные kernel/network параметры без отключения IPv6 и forwarding.", "rp_filter=1 может нарушить асимметричную маршрутизацию; по умолчанию используется 2.", "sysctl --system", "Восстановить /etc/sysctl.d/99-bastionctl.conf из backup и снова выполнить sysctl --system."},
	"journald":          {"journald", "Сохраняет системные журналы между перезагрузками и ограничивает их размер.", "Постоянный журнал использует дисковое пространство.", "journalctl --disk-usage; systemctl status systemd-journald", "Восстановить journald drop-in и перезапустить systemd-journald."},
	"auditd":            {"auditd", "Журналирует изменения учётных данных, sudo и SSH-конфигурации.", "Большой поток событий может увеличить журнал.", "augenrules --check; auditctl -l", "Восстановить rules-файл и выполнить augenrules --load."},
	"apparmor":          {"apparmor", "Включает обязательные профили ограничения приложений.", "Сторонний профиль может блокировать нестандартное поведение приложения.", "aa-status", "Перевести конкретный профиль в complain mode; не отключать AppArmor целиком без расследования."},
	"time-sync":         {"time-sync", "Синхронизирует время для журналов, TLS и расследований.", "Конфликт нескольких time-сервисов может вызвать нестабильность.", "chronyc tracking", "Вернуть ранее использовавшийся time-сервис после проверки его конфигурации."},
	"permissions":       {"permissions", "Исправляет владельца и права чувствительных файлов.", "Нестандартный сервис может ожидать более широкое чтение.", "stat -c '%U:%G %a %n' /etc/shadow /etc/sudoers /etc/ssh/sshd_config", "Вернуть прежние mode/owner из отчёта или backup метаданных."},
	"ssh":               {"ssh", "Оставляет вход по публичному ключу и запрещает root/password login.", "Ошибочная политика может закрыть удалённый доступ.", "sshd -t; sshd -T", "Drop-in автоматически восстанавливается при ошибке; вручную используйте rescue-консоль и backup."},
	"fail2ban":          {"fail2ban", "Временно блокирует источники повторных неудачных SSH-входов.", "Слишком строгий лимит может заблокировать адрес администратора.", "fail2ban-client status sshd", "Остановить jail или выполнить fail2ban-client set sshd unbanip ADDRESS."},
	"accounts":          {"accounts", "Находит дополнительные UID 0 и интерактивные учётные записи.", "Неизвестная учётная запись может означать компрометацию.", "getent passwd", "Автоматических изменений нет; сначала расследовать владельца и активные процессы."},
	"exposure":          {"exposure", "Показывает wildcard listeners и Docker published ports.", "Лишний listener расширяет поверхность атаки, даже если UFW его блокирует.", "ss -lntup; docker ps --format '{{.Ports}}'", "Остановить или перепривязать конкретный сервис после проверки зависимостей."},
	"backup":            {"backup", "Проверяет возраст marker-файлов, обновляемых успешным backup job.", "Свежий marker не доказывает возможность восстановления.", "stat BACKUP_MARKER; отдельно выполнить тестовое восстановление.", "Проверка read-only; исправить backup job, а не marker вручную."},
	"firewall":          {"firewall", "Запрещает входящие соединения, кроме SSH и выбранных сервисов.", "Ошибочный SSH CIDR или порт может закрыть доступ.", "ufw status numbered; проверить вторую SSH-сессию.", "Использовать rescue-консоль; существующие правила не удаляются автоматически."},
	"operations":        {"operations", "Напоминает о внешних мерах: backup restore, MFA, rescue и cloud firewall.", "Эти меры нельзя доказать с одного сервера.", "Проверить панели провайдера и журнал тестов восстановления.", "Изменений не выполняет."},
	"reset":             {"reset", "Удаляет только маркированную политику bastionctl и помеченные UFW-правила.", "Оставшаяся системная политика может разрешать более широкий доступ; runtime sysctl без другого источника окончательно сбрасывается после reboot.", "Сначала reset-plan; затем проверить отчёт, sshd -T и ufw status numbered.", "Каждый управляемый файл сохраняется в backup; пользовательские файлы, аккаунты и ключи не удаляются."},
	"user-add":          {"user-add", "Создаёт key-only SSH-пользователя по публичному Ed25519-ключу другого ПК.", "Неверно выданная sudo-роль повышает привилегии; CIDR firewall может не пропустить новый ПК.", "Сверить SHA-256 fingerprint, getent passwd USER, ssh-keygen -lf authorized_keys и вход во второй сессии.", "Удалять только конкретный ключ по fingerprint после проверки второго доступа; аккаунт/home автоматически не удаляются."},
}

func Get(control string) (Entry, bool) {
	value, ok := entries[control]
	return value, ok
}

func List() []Entry {
	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]Entry, 0, len(keys))
	for _, key := range keys {
		result = append(result, entries[key])
	}
	return result
}
