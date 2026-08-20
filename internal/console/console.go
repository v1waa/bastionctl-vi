package console

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"bastionctl/internal/admin"
	"bastionctl/internal/controller"
	"bastionctl/internal/explain"
	"bastionctl/internal/inventory"
	"bastionctl/internal/profile"
	"bastionctl/internal/report"
	"bastionctl/internal/state"
)

var errInputClosed = errors.New("ввод закрыт")

type UI struct {
	ctx      context.Context
	control  *controller.Controller
	input    io.Reader
	reader   *bufio.Reader
	out      io.Writer
	errOut   io.Writer
	selected string
}

func Run(ctx context.Context, control *controller.Controller, input io.Reader, output, errorOutput io.Writer) int {
	ui := &UI{ctx: ctx, control: control, input: input, reader: bufio.NewReader(input), out: output, errOut: errorOutput}
	if err := ui.loop(); err != nil && !errors.Is(err, errInputClosed) && !errors.Is(err, context.Canceled) {
		_, _ = fmt.Fprintln(errorOutput, "Ошибка консоли:", err)
		return 70
	}
	if ctx.Err() != nil {
		return 130
	}
	return 0
}

func (ui *UI) loop() error {
	_, _ = fmt.Fprintf(ui.out, "\nbastionctl %s — консоль администратора\n", ui.control.Version)
	_, _ = fmt.Fprintln(ui.out, "Локальные данные защищаются правами каталога; соединения выполняются через OpenSSH.")
	servers, err := ui.control.List()
	if err != nil {
		return err
	}
	if len(servers) > 0 {
		ui.selected = servers[0].ID
	} else {
		_, _ = fmt.Fprintln(ui.out, "\nВ реестре пока нет серверов. Выберите «Добавить сервер».")
	}
	for {
		if err := ui.ctx.Err(); err != nil {
			return err
		}
		ui.menu()
		choice, err := ui.prompt("Команда", "")
		if err != nil {
			return err
		}
		switch strings.ToLower(choice) {
		case "0", "q", "quit", "exit":
			return nil
		case "1", "servers", "select":
			ui.runSafely(ui.selectServer)
		case "2", "add":
			ui.runSafely(ui.addServer)
		case "3", "install":
			ui.runWithServer(ui.install)
		case "4", "audit":
			ui.runWithServer(func(item state.ManagedServer) error { return ui.action(item, "audit") })
		case "5", "plan":
			ui.runWithServer(func(item state.ManagedServer) error { return ui.action(item, "plan") })
		case "6", "apply":
			ui.runWithServer(ui.apply)
		case "7", "snapshot", "drift":
			ui.runWithServer(ui.snapshot)
		case "8", "configure", "config":
			ui.runWithServer(ui.configure)
		case "9", "history":
			ui.runWithServer(ui.history)
		case "10", "all":
			ui.runSafely(ui.auditAll)
		case "11", "explain":
			ui.runSafely(ui.explain)
		case "12", "remove":
			ui.runWithServer(ui.remove)
		case "13", "bootstrap":
			ui.runWithServer(ui.bootstrap)
		case "14", "user", "user-add":
			ui.runWithServer(ui.createUser)
		case "15", "reset":
			ui.runWithServer(ui.resetPolicy)
		case "":
			continue
		default:
			_, _ = fmt.Fprintln(ui.errOut, "Неизвестная команда. Выберите номер 0–15.")
		}
	}
}

func (ui *UI) menu() {
	selected := "не выбран"
	if ui.selected != "" {
		selected = ui.selected
	}
	_, _ = fmt.Fprintf(ui.out, `
Выбранный сервер: %s
  1. Список и выбор сервера     7. Снимок и поиск drift
  2. Добавить сервер            8. Настроить политику
  3. Установить/обновить        9. История отчётов
  4. Аудит                     10. Аудит всех серверов
  5. План                      11. Объяснить контроль
  6. Применить                 12. Удалить из реестра
 13. Первичный SSH-вход        14. Создать SSH-пользователя
 15. Сбросить политику
  0. Выход
`, selected)
}

func (ui *UI) runSafely(operation func() error) {
	if err := operation(); err != nil && !errors.Is(err, errInputClosed) {
		_, _ = fmt.Fprintln(ui.errOut, "Ошибка:", err)
	}
}

func (ui *UI) runWithServer(operation func(state.ManagedServer) error) {
	if ui.selected == "" {
		_, _ = fmt.Fprintln(ui.errOut, "Сначала добавьте или выберите сервер.")
		return
	}
	item, err := ui.control.Store.Server(ui.selected)
	if err != nil {
		_, _ = fmt.Fprintln(ui.errOut, "Ошибка:", err)
		return
	}
	ui.runSafely(func() error { return operation(item) })
}

func (ui *UI) selectServer() error {
	servers, err := ui.control.List()
	if err != nil {
		return err
	}
	if len(servers) == 0 {
		_, _ = fmt.Fprintln(ui.out, "Реестр пуст.")
		return nil
	}
	printServers(ui.out, servers)
	id, err := ui.prompt("ID сервера", ui.selected)
	if err != nil {
		return err
	}
	for _, item := range servers {
		if item.ID == id {
			ui.selected = id
			return nil
		}
	}
	return fmt.Errorf("сервер %q не найден", id)
}

func (ui *UI) addServer() error {
	_, _ = fmt.Fprintln(ui.out, "\nДобавление сервера. Пароль никогда не сохраняется: при необходимости его запросит OpenSSH.")
	id, err := ui.prompt("Короткий ID (a-z, 0-9, _-)", "")
	if err != nil {
		return err
	}
	name, err := ui.prompt("Отображаемое имя", id)
	if err != nil {
		return err
	}
	passwordBootstrap, err := ui.promptBool("Первый вход по IP и паролю", true)
	if err != nil {
		return err
	}
	target := ""
	bootstrapAdmin := ""
	identity := ""
	acceptNew := false
	if passwordBootstrap {
		host, promptErr := ui.prompt("IP или DNS-имя сервера", "")
		if promptErr != nil {
			return promptErr
		}
		loginUser, promptErr := ui.prompt("Пользователь первого входа", "root")
		if promptErr != nil {
			return promptErr
		}
		if loginUser == "root" {
			bootstrapAdmin, promptErr = ui.prompt("Новый непривилегированный администратор", "bastion")
			if promptErr != nil {
				return promptErr
			}
		}
		target = formatTarget(loginUser, host)
		acceptNew = true
		_, _ = fmt.Fprintln(ui.out, "Будет создан отдельный Ed25519-ключ. OpenSSH покажет fingerprint: сверьте его независимым каналом до ответа yes и ввода пароля.")
	} else {
		target, err = ui.prompt("SSH-цель user@host", "")
		if err != nil {
			return err
		}
		identity, err = ui.prompt("Путь к закрытому ключу (пусто = SSH agent)", "")
		if err != nil {
			return err
		}
	}
	portRaw, err := ui.prompt("SSH-порт", "22")
	if err != nil {
		return err
	}
	port, err := parsePort(portRaw)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(ui.out, "Профили:")
	for _, item := range profile.List() {
		_, _ = fmt.Fprintf(ui.out, "  %-12s %s — %s\n", item.Name, item.Title, item.Description)
	}
	profileName, err := ui.prompt("Профиль", "minimal")
	if err != nil {
		return err
	}
	cidrs, err := ui.prompt("CIDR, которым разрешён SSH (через запятую; пусто = любой адрес)", "")
	if err != nil {
		return err
	}
	tcpRaw, err := ui.prompt("Дополнительные TCP-порты (через запятую)", "")
	if err != nil {
		return err
	}
	tcpPorts, err := parsePorts(tcpRaw)
	if err != nil {
		return err
	}
	udpRaw, err := ui.prompt("Дополнительные UDP-порты (через запятую)", "")
	if err != nil {
		return err
	}
	udpPorts, err := parsePorts(udpRaw)
	if err != nil {
		return err
	}
	markersRaw, err := ui.prompt("Backup marker-файлы на сервере (через запятую)", "")
	if err != nil {
		return err
	}
	backupRequired, err := ui.promptBool("Считать отсутствие свежего backup ошибкой", false)
	if err != nil {
		return err
	}
	if !passwordBootstrap {
		acceptNew, err = ui.promptBool("Автоматически принять новый SSH host key при первом соединении", false)
		if err != nil {
			return err
		}
		if acceptNew {
			_, _ = fmt.Fprintln(ui.out, "Важно: после первого подключения сверьте fingerprint независимым каналом; затем приложение вернёт строгий режим.")
		}
	}
	binary, err := ui.prompt("Linux-бинарник для установки (пусто = найти рядом автоматически)", "")
	if err != nil {
		return err
	}
	item, err := ui.control.AddServer(controller.AddOptions{
		ID: id, Name: name, Target: target, Port: port, Identity: identity, Profile: profileName,
		SSHAllowedCIDRs: splitCSV(cidrs), AdditionalTCPPorts: tcpPorts, AdditionalUDPPorts: udpPorts,
		BackupMarkers: splitCSV(markersRaw), BackupRequired: backupRequired, ServerBinary: binary,
		AcceptNewHostKey: acceptNew, PasswordBootstrap: passwordBootstrap, BootstrapAdminUser: bootstrapAdmin,
	})
	if err != nil {
		return err
	}
	ui.selected = item.ID
	_, _ = fmt.Fprintf(ui.out, "Сервер %s добавлен. Конфигурация: %s\n", item.ID, item.ConfigPath)
	if item.BootstrapPending {
		_, _ = fmt.Fprintf(ui.out, "Локальный ключ: %s\n", item.Identity)
		now, promptErr := ui.promptBool("Выполнить первичный SSH-вход сейчас", true)
		if promptErr != nil {
			return promptErr
		}
		if now {
			return ui.bootstrap(item)
		}
	}
	return nil
}

func (ui *UI) bootstrap(item state.ManagedServer) error {
	if !item.BootstrapPending {
		_, _ = fmt.Fprintln(ui.out, "Первичный SSH-вход уже завершён; используется ключевой доступ.")
		return nil
	}
	_, _ = fmt.Fprintln(ui.out, "Сначала сверьте показанный OpenSSH fingerprint независимым каналом; только затем ответьте yes и введите пароль. Приложение пароль не читает и не сохраняет.")
	if strings.HasPrefix(item.BootstrapTarget, "root@") {
		_, _ = fmt.Fprintln(ui.out, "Для нового администратора может потребоваться дважды задать отдельный sudo-пароль.")
	}
	updated, err := ui.control.BootstrapAccess(ui.ctx, item.ID, ui.input, ui.out)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(ui.out, "Ключевой вход проверен: %s. Дальнейшая проверка host key — строгая.\n", updated.Target)
	return nil
}

func (ui *UI) install(item state.ManagedServer) error {
	cfg, err := ui.control.Config(item.ID)
	if err != nil {
		return err
	}
	doctor := admin.Doctor(ui.ctx, cfg.Admin, ui.control.Version, item.Identity)
	if err := report.WriteText(ui.out, doctor); err != nil {
		return err
	}
	if doctor.HasFailures() {
		return errors.New("установка остановлена: локальная диагностика содержит ошибки")
	}
	path, err := ui.prompt("Linux-бинарник (пусто = автоматический поиск)", item.ServerBinary)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(ui.out, "Проверяю архитектуру, загружаю файлы и валидирую sudo-политику…")
	if item.InteractiveSudo {
		_, _ = fmt.Fprintln(ui.out, "sudo может запросить пароль прямо в удалённом терминале; bastionctl его не сохраняет.")
	}
	result, err := ui.control.Install(ui.ctx, item.ID, path, ui.input, ui.out, item.InteractiveSudo)
	if err != nil {
		return err
	}
	return ui.printOperation(result)
}

func (ui *UI) action(item state.ManagedServer, action string) error {
	_, _ = fmt.Fprintf(ui.out, "Выполняю %s для %s…\n", action, item.ID)
	result, err := ui.control.RunAction(ui.ctx, item.ID, action, false)
	if err != nil {
		return err
	}
	return ui.printOperation(result)
}

func (ui *UI) apply(item state.ManagedServer) error {
	_, _ = fmt.Fprintln(ui.out, "Сначала выполняется обязательный plan; он ничего не меняет.")
	plan, err := ui.control.RunAction(ui.ctx, item.ID, "plan", false)
	if err != nil {
		return err
	}
	if err := ui.printOperation(plan); err != nil {
		return err
	}
	if plan.Report.HasFailures() {
		return errors.New("apply заблокирован: plan содержит ошибки")
	}
	expected := "APPLY " + item.ID
	confirmation, err := ui.prompt("Для применения введите "+expected, "")
	if err != nil {
		return err
	}
	if confirmation != expected {
		_, _ = fmt.Fprintln(ui.out, "Отменено: подтверждение не совпало.")
		return nil
	}
	result, err := ui.control.RunAction(ui.ctx, item.ID, "apply", true)
	if err != nil {
		return err
	}
	return ui.printOperation(result)
}

func (ui *UI) createUser(item state.ManagedServer) error {
	_, _ = fmt.Fprintln(ui.out, "\nНовый пользователь получит key-only SSH-вход. Закрытый ключ не передаётся на сервер и не хранится bastionctl.")
	_, _ = fmt.Fprintln(ui.out, "На другом ПК выполните: ssh-keygen -t ed25519, затем скопируйте сюда только строку из файла с расширением .pub.")
	username, err := ui.prompt("Имя Linux-пользователя", "")
	if err != nil {
		return err
	}
	keyInput, err := ui.prompt("Публичный ключ Ed25519 или @путь-к-файлу.pub", "")
	if err != nil {
		return err
	}
	publicKey := ""
	fingerprint := ""
	if strings.HasPrefix(keyInput, "@") {
		path := admin.ExpandIdentity(strings.TrimSpace(strings.TrimPrefix(keyInput, "@")))
		publicKey, err = admin.ReadPublicKey(path)
		if err == nil {
			_, fingerprint, err = admin.NormalizePublicKey(publicKey)
		}
	} else {
		publicKey, fingerprint, err = admin.NormalizePublicKey(keyInput)
	}
	if err != nil {
		return err
	}
	grantSudo, err := ui.promptBool("Добавить пользователя в группу sudo", false)
	if err != nil {
		return err
	}
	cfg, err := ui.control.Config(item.ID)
	if err != nil {
		return err
	}
	role := "обычный пользователь без sudo"
	if grantSudo {
		role = "администратор sudo; после создания потребуется отдельный пароль"
	}
	allowedSources := "любой адрес, разрешённый внешним firewall"
	if len(cfg.Server.SSHAllowedCIDRs) > 0 {
		allowedSources = strings.Join(cfg.Server.SSHAllowedCIDRs, ", ")
	}
	_, _ = fmt.Fprintf(ui.out, "Пользователь: %s\nРоль: %s\nКлюч: %s\nРазрешённые источники SSH: %s\n", username, role, fingerprint, allowedSources)
	expected := "CREATE " + username
	confirmation, err := ui.prompt("Для создания введите "+expected, "")
	if err != nil {
		return err
	}
	if confirmation != expected {
		_, _ = fmt.Fprintln(ui.out, "Отменено: подтверждение не совпало.")
		return nil
	}
	result, err := ui.control.CreateUser(ui.ctx, item.ID, username, publicKey, grantSudo)
	if err != nil {
		return err
	}
	if err := ui.printOperation(result); err != nil {
		return err
	}
	if result.Report.HasFailures() {
		return errors.New("создание пользователя завершилось с ошибками; проверьте отчёт и не повторяйте вслепую")
	}
	if grantSudo {
		setNow, promptErr := ui.promptBool("Задать sudo-пароль сейчас в защищённом удалённом терминале", true)
		if promptErr != nil {
			return promptErr
		}
		if setNow {
			_, _ = fmt.Fprintln(ui.out, "sudo может сначала запросить пароль текущего администратора, затем дважды новый пароль. bastionctl эти значения не читает и не сохраняет.")
			if err := ui.control.SetUserPassword(ui.ctx, item.ID, username, ui.input, ui.out); err != nil {
				return err
			}
		}
	}
	_, host := splitTargetForDisplay(item.Target)
	_, _ = fmt.Fprintf(ui.out, "Вход с другого ПК: ssh -p %d %s@%s\n", item.Port, username, host)
	return nil
}

func (ui *UI) resetPolicy(item state.ManagedServer) error {
	_, _ = fmt.Fprintln(ui.out, "\nСначала строится read-only план сброса. Он удалит только файлы с маркером bastionctl и правила UFW с комментариями bastionctl-*. ")
	plan, err := ui.control.RunAction(ui.ctx, item.ID, "reset-plan", false)
	if err != nil {
		return err
	}
	if err := ui.printOperation(plan); err != nil {
		return err
	}
	if plan.Report.HasFailures() {
		return errors.New("сброс заблокирован: reset-plan содержит ошибки")
	}
	_, _ = fmt.Fprintln(ui.out, "Не удаляются: пользовательские файлы, домашние каталоги, аккаунты, authorized_keys, пакеты, сторонние firewall-правила и локальная история.")
	expected := "RESET " + item.ID
	confirmation, err := ui.prompt("Для полного сброса политики bastionctl введите "+expected, "")
	if err != nil {
		return err
	}
	if confirmation != expected {
		_, _ = fmt.Fprintln(ui.out, "Отменено: подтверждение не совпало.")
		return nil
	}
	result, err := ui.control.RunAction(ui.ctx, item.ID, "reset", true)
	if err != nil {
		return err
	}
	return ui.printOperation(result)
}

func (ui *UI) snapshot(item state.ManagedServer) error {
	_, _ = fmt.Fprintln(ui.out, "Собираю инвентарный снимок без содержимого секретных файлов…")
	result, err := ui.control.CaptureSnapshot(ui.ctx, item.ID, false)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(ui.out, "Snapshot: host=%s packages=%d services=%d accounts=%d listeners=%d files=%d\n",
		result.Snapshot.Host.Hostname, len(result.Snapshot.Packages), len(result.Snapshot.Services),
		len(result.Snapshot.Accounts), len(result.Snapshot.Listeners), len(result.Snapshot.Files))
	for _, warning := range result.Snapshot.Warnings {
		_, _ = fmt.Fprintln(ui.out, "WARNING ", warning)
	}
	if result.BaselineCreated {
		_, _ = fmt.Fprintln(ui.out, "Первый подписанный снимок сохранён как baseline.")
		return nil
	}
	if result.Diff != nil {
		printDiff(ui.out, *result.Diff)
	}
	return nil
}

func (ui *UI) configure(item state.ManagedServer) error {
	cfg, err := ui.control.Config(item.ID)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(ui.out, "Пустой ввод сохраняет показанное значение.")
	name, err := ui.prompt("Отображаемое имя", item.Name)
	if err != nil {
		return err
	}
	target, err := ui.prompt("SSH-цель user@host", item.Target)
	if err != nil {
		return err
	}
	portRaw, err := ui.prompt("SSH-порт", strconv.Itoa(item.Port))
	if err != nil {
		return err
	}
	port, err := parsePort(portRaw)
	if err != nil {
		return err
	}
	identity, err := ui.prompt("Закрытый ключ ('-' = SSH agent)", item.Identity)
	if err != nil {
		return err
	}
	if identity == "-" {
		identity = ""
	}
	binary, err := ui.prompt("Linux-бинарник ('-' = автоматический поиск)", item.ServerBinary)
	if err != nil {
		return err
	}
	if binary == "-" {
		binary = ""
	}
	profileName, err := ui.prompt("Профиль", cfg.Server.Profile)
	if err != nil {
		return err
	}
	if profileName != cfg.Server.Profile {
		selected, ok := profile.Get(profileName)
		if !ok {
			return fmt.Errorf("неизвестный профиль %q", profileName)
		}
		cfg.Server.Profile = selected.Name
		cfg.Server.AllowedTCPPorts = append([]int(nil), selected.TCPPorts...)
		cfg.Server.AllowedUDPPorts = append([]int(nil), selected.UDPPorts...)
	}
	cidrs, err := ui.prompt("SSH CIDR", strings.Join(cfg.Server.SSHAllowedCIDRs, ","))
	if err != nil {
		return err
	}
	cfg.Server.SSHAllowedCIDRs = splitCSV(cidrs)
	tcpRaw, err := ui.prompt("Разрешённые TCP-порты", joinPorts(cfg.Server.AllowedTCPPorts))
	if err != nil {
		return err
	}
	cfg.Server.AllowedTCPPorts, err = parsePorts(tcpRaw)
	if err != nil {
		return err
	}
	udpRaw, err := ui.prompt("Разрешённые UDP-порты", joinPorts(cfg.Server.AllowedUDPPorts))
	if err != nil {
		return err
	}
	cfg.Server.AllowedUDPPorts, err = parsePorts(udpRaw)
	if err != nil {
		return err
	}
	markers, err := ui.prompt("Backup marker-файлы", strings.Join(cfg.Server.BackupMarkers, ","))
	if err != nil {
		return err
	}
	cfg.Server.BackupMarkers = splitCSV(markers)
	age, err := ui.prompt("Максимальный возраст backup, часов", strconv.Itoa(cfg.Server.BackupMaxAgeHours))
	if err != nil {
		return err
	}
	cfg.Server.BackupMaxAgeHours, err = strconv.Atoi(age)
	if err != nil {
		return errors.New("возраст backup должен быть целым числом")
	}
	cfg.Server.BackupRequired, err = ui.promptBool("Требовать свежий backup", cfg.Server.BackupRequired)
	if err != nil {
		return err
	}
	cfg.Admin.StrictHostKeyChecking, err = ui.promptBool("Строго проверять SSH host key", cfg.Admin.StrictHostKeyChecking)
	if err != nil {
		return err
	}
	if err := ui.control.SaveConfig(item.ID, cfg); err != nil {
		return err
	}
	updated, err := ui.control.UpdateServer(controller.UpdateOptions{
		ID: item.ID, Name: name, Target: target, Port: port, Identity: identity, ServerBinary: binary,
	})
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(ui.out, "Политика сохранена: %s\n", updated.ConfigPath)
	_, _ = fmt.Fprintln(ui.out, "Чтобы передать обновлённую конфигурацию на сервер, выполните пункт 3.")
	return nil
}

func (ui *UI) history(item state.ManagedServer) error {
	entries, err := ui.control.Store.History(item.ID, 20)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		_, _ = fmt.Fprintln(ui.out, "История пуста.")
		return nil
	}
	for _, entry := range entries {
		status := "ok"
		if entry.HasFails {
			status = "fail"
		}
		_, _ = fmt.Fprintf(ui.out, "%s  %-8s %-4s %s\n", entry.Timestamp.Local().Format("2006-01-02 15:04:05"), entry.Action, status, entry.Path)
	}
	return nil
}

func (ui *UI) auditAll() error {
	_, _ = fmt.Fprintln(ui.out, "Последовательно проверяю все серверы…")
	results, err := ui.control.AuditAll(ui.ctx)
	if err != nil {
		return err
	}
	if len(results) == 0 {
		_, _ = fmt.Fprintln(ui.out, "Реестр пуст.")
		return nil
	}
	for _, result := range results {
		if result.Error != "" {
			_, _ = fmt.Fprintf(ui.out, "%-20s ERROR %s\n", result.Server.ID, result.Error)
			continue
		}
		status := "OK"
		if result.Operation.Report.HasFailures() {
			status = "FAIL"
		}
		_, _ = fmt.Fprintf(ui.out, "%-20s %-4s fail=%d warn=%d new=%d\n", result.Server.ID, status,
			result.Operation.Report.Summary.Fail, result.Operation.Report.Summary.Warn, len(result.Operation.NewFindings))
	}
	return nil
}

func (ui *UI) explain() error {
	controls := explain.List()
	_, _ = fmt.Fprintln(ui.out, "Контроли:")
	for _, item := range controls {
		_, _ = fmt.Fprint(ui.out, item.Control, " ")
	}
	_, _ = fmt.Fprintln(ui.out)
	name, err := ui.prompt("Контроль", "ssh")
	if err != nil {
		return err
	}
	item, ok := explain.Get(name)
	if !ok {
		return fmt.Errorf("контроль %q не найден", name)
	}
	_, _ = fmt.Fprintf(ui.out, "\n%s\n  Назначение: %s\n  Риск: %s\n  Проверка: %s\n  Откат: %s\n", item.Control, item.Purpose, item.Risk, item.Check, item.Rollback)
	return nil
}

func (ui *UI) remove(item state.ManagedServer) error {
	expected := "REMOVE " + item.ID
	confirmation, err := ui.prompt("Удаляется только запись реестра; данные истории сохранятся. Введите "+expected, "")
	if err != nil {
		return err
	}
	if confirmation != expected {
		_, _ = fmt.Fprintln(ui.out, "Отменено.")
		return nil
	}
	if err := ui.control.RemoveServer(item.ID); err != nil {
		return err
	}
	ui.selected = ""
	servers, listErr := ui.control.List()
	if listErr == nil && len(servers) > 0 {
		ui.selected = servers[0].ID
	}
	_, _ = fmt.Fprintln(ui.out, "Запись удалена; удалённый сервер не изменялся.")
	return nil
}

func (ui *UI) printOperation(result *controller.OperationResult) error {
	if err := report.WriteText(ui.out, result.Report); err != nil {
		return err
	}
	if len(result.NewFindings) > 0 {
		_, _ = fmt.Fprintln(ui.out, "Новые ошибки относительно прошлого отчёта:", strings.Join(result.NewFindings, ", "))
	}
	_, _ = fmt.Fprintln(ui.out, "Отчёт сохранён:", result.HistoryPath)
	return nil
}

func (ui *UI) prompt(label, defaultValue string) (string, error) {
	if defaultValue == "" {
		_, _ = fmt.Fprintf(ui.out, "%s: ", label)
	} else {
		_, _ = fmt.Fprintf(ui.out, "%s [%s]: ", label, defaultValue)
	}
	line, err := ui.reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	value := strings.TrimSpace(line)
	if value == "" {
		value = defaultValue
	}
	if errors.Is(err, io.EOF) {
		if line == "" {
			return "", errInputClosed
		}
	}
	return value, nil
}

func (ui *UI) promptBool(label string, defaultValue bool) (bool, error) {
	defaultText := "нет"
	if defaultValue {
		defaultText = "да"
	}
	value, err := ui.prompt(label+" (да/нет)", defaultText)
	if err != nil {
		return false, err
	}
	switch strings.ToLower(value) {
	case "да", "д", "yes", "y", "true", "1":
		return true, nil
	case "нет", "н", "no", "n", "false", "0":
		return false, nil
	default:
		return false, fmt.Errorf("ожидается да или нет, получено %q", value)
	}
}

func printServers(writer io.Writer, servers []state.ManagedServer) {
	_, _ = fmt.Fprintln(writer, "ID                   TARGET                         PROFILE       STATUS       LAST SEEN")
	for _, item := range servers {
		seen := "—"
		if !item.LastSeenAt.IsZero() {
			seen = item.LastSeenAt.Local().Format("2006-01-02 15:04")
		}
		status := item.LastStatus
		if status == "" {
			status = "new"
		}
		if item.BootstrapPending {
			status = "bootstrap"
		}
		_, _ = fmt.Fprintf(writer, "%-20s %-30s %-13s %-12s %s\n", item.ID, item.Target, item.Profile, status, seen)
	}
}

func printDiff(writer io.Writer, diff inventory.Diff) {
	if len(diff.Changes) == 0 {
		_, _ = fmt.Fprintln(writer, "Drift не обнаружен: состояние совпадает с baseline.")
		return
	}
	_, _ = fmt.Fprintf(writer, "Обнаружено изменений: %d\n", len(diff.Changes))
	for _, change := range diff.Changes {
		_, _ = fmt.Fprintf(writer, "%-8s %-13s %-28s %s", strings.ToUpper(change.Kind), change.Category, change.Key, change.Severity)
		if change.Before != "" || change.After != "" {
			_, _ = fmt.Fprintf(writer, "  %s -> %s", change.Before, change.After)
		}
		_, _ = fmt.Fprintln(writer)
	}
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return []string{}
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			result = append(result, part)
		}
	}
	return result
}

func formatTarget(username, host string) string {
	username = strings.TrimSpace(username)
	host = strings.TrimSpace(host)
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return username + "@" + host
}

func splitTargetForDisplay(target string) (string, string) {
	index := strings.LastIndex(target, "@")
	if index <= 0 || index == len(target)-1 {
		return "", target
	}
	return target[:index], target[index+1:]
}

func parsePort(value string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("порт должен быть числом 1..65535")
	}
	return port, nil
}

func parsePorts(value string) ([]int, error) {
	parts := splitCSV(value)
	ports := make([]int, 0, len(parts))
	for _, part := range parts {
		port, err := parsePort(part)
		if err != nil {
			return nil, fmt.Errorf("порт %q: %w", part, err)
		}
		ports = append(ports, port)
	}
	return ports, nil
}

func joinPorts(ports []int) string {
	parts := make([]string, len(ports))
	for index, port := range ports {
		parts[index] = strconv.Itoa(port)
	}
	return strings.Join(parts, ",")
}
