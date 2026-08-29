package console

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"bastionctl/internal/report"
	"bastionctl/internal/state"
	"bastionctl/internal/tui"
	"bastionctl/internal/workload"
)

const xhttpLocalTunnelPort = 18080

func (ui *UI) xhttpWizard(item state.ManagedServer) error {
	setup, err := ui.control.LoadXHTTPConfig(item.ID)
	if os.IsNotExist(err) {
		setup, err = ui.editXHTTPConfig(item, nil)
	}
	if err != nil {
		return err
	}
	for {
		action, err := ui.chooseXHTTPAction(item, setup)
		if err != nil {
			return err
		}
		switch action {
		case 0:
			return nil
		case 1:
			if err := ui.verifyXHTTP(item, setup); err != nil {
				_, _ = fmt.Fprintln(ui.errOut, "Ошибка проверки:", err)
			}
		case 2:
			if err := ui.continueXHTTP(item, setup); err != nil {
				_, _ = fmt.Fprintln(ui.errOut, "Мастер остановлен:", err)
			}
		case 3:
			ui.printXHTTPGuide(item, setup)
		case 4:
			updated, editErr := ui.editXHTTPConfig(item, &setup)
			if editErr != nil {
				_, _ = fmt.Fprintln(ui.errOut, "Ошибка:", editErr)
				continue
			}
			setup = updated
		}
	}
}

func (ui *UI) chooseXHTTPAction(item state.ManagedServer, setup workload.XHTTPConfig) (int, error) {
	options := []tui.Option{
		{ID: 1, Label: "Проверить установленное", Group: "VLESS / XHTTP"},
		{ID: 2, Label: "Продолжить настройку", Group: "VLESS / XHTTP"},
		{ID: 3, Label: "Показать ручные шаги", Group: "VLESS / XHTTP"},
		{ID: 4, Label: "Изменить параметры", Group: "VLESS / XHTTP"},
		{ID: 0, Label: "Назад"},
	}
	selected, interactive, err := tui.Select(
		ui.reader, ui.input, ui.out,
		"Мастер VLESS + TLS + XHTTP",
		fmt.Sprintf("%s · %s → %s · 3x-ui %s", item.ID, setup.Domain, setup.ServerIP, setup.Release),
		options, 2,
	)
	if err != nil {
		return 0, err
	}
	if interactive {
		return selected, nil
	}
	_, _ = fmt.Fprintf(ui.out, "\nVLESS + TLS + XHTTP: %s → %s, панель 127.0.0.1:%d, 3x-ui %s\n%s\n",
		setup.Domain, setup.ServerIP, setup.PanelPort, setup.Release, tui.RenderPlain(options, 100))
	value, err := ui.prompt("Действие", "2")
	if err != nil {
		return 0, err
	}
	selected, err = strconv.Atoi(value)
	if err != nil || selected < 0 || selected > 4 {
		return 0, errors.New("выберите действие 0..4")
	}
	return selected, nil
}

func (ui *UI) editXHTTPConfig(item state.ManagedServer, current *workload.XHTTPConfig) (workload.XHTTPConfig, error) {
	_, targetHost := splitTargetForDisplay(item.Target)
	targetHost = strings.Trim(targetHost, "[]")
	defaultIP := ""
	if net.ParseIP(targetHost) != nil {
		defaultIP = targetHost
	}
	domainDefault := ""
	emailDefault := ""
	panelDefault := "0"
	if current != nil {
		domainDefault = current.Domain
		emailDefault = current.Email
		defaultIP = current.ServerIP
		panelDefault = strconv.Itoa(current.PanelPort)
	}
	_, _ = fmt.Fprintln(ui.out, "\nПараметры не содержат паролей. Панель будет слушать только 127.0.0.1 и открываться через SSH-туннель.")
	domain, err := ui.prompt("Домен для VLESS/TLS", domainDefault)
	if err != nil {
		return workload.XHTTPConfig{}, err
	}
	email, err := ui.prompt("Email для Let's Encrypt", emailDefault)
	if err != nil {
		return workload.XHTTPConfig{}, err
	}
	serverIP, err := ui.prompt("Публичный IPv4 сервера", defaultIP)
	if err != nil {
		return workload.XHTTPConfig{}, err
	}
	panelRaw, err := ui.prompt("Локальный порт панели (0 = выбрать безопасный случайный)", panelDefault)
	if err != nil {
		return workload.XHTTPConfig{}, err
	}
	panelPort, err := strconv.Atoi(panelRaw)
	if err != nil || panelPort < 0 || panelPort > 65535 {
		return workload.XHTTPConfig{}, errors.New("порт панели должен быть 0..65535")
	}
	var value workload.XHTTPConfig
	if current == nil {
		value, err = workload.NewXHTTPConfig(domain, email, serverIP, panelPort)
	} else {
		value = *current
		value.Domain = strings.ToLower(strings.TrimSpace(domain))
		value.Email = strings.TrimSpace(email)
		value.ServerIP = strings.TrimSpace(serverIP)
		if panelPort == 0 {
			fresh, freshErr := workload.NewXHTTPConfig(value.Domain, value.Email, value.ServerIP, 0)
			if freshErr != nil {
				return workload.XHTTPConfig{}, freshErr
			}
			value.PanelPort = fresh.PanelPort
		} else {
			value.PanelPort = panelPort
		}
		err = value.Validate()
	}
	if err != nil {
		return workload.XHTTPConfig{}, err
	}
	path, policyChanged, err := ui.control.ConfigureXHTTP(item.ID, value)
	if err != nil {
		return workload.XHTTPConfig{}, err
	}
	_, _ = fmt.Fprintln(ui.out, "Параметры мастера сохранены:", path)
	if policyChanged {
		_, _ = fmt.Fprintln(ui.out, "Желаемая политика дополнена TCP 80/443 и узким SSH local-forward только к loopback-панели.")
	}
	return value, nil
}

func (ui *UI) continueXHTTP(item state.ManagedServer, setup workload.XHTTPConfig) error {
	_, _ = fmt.Fprintf(ui.out, "\nМастер установит 3x-ui %s из официального release asset после проверки SHA-256.\n", workload.XHTTPRelease)
	ui.printManualSteps(workload.ManualGuide(setup, item.Target, item.Identity, item.Port, xhttpLocalTunnelPort)[:1])
	ready, err := ui.promptBool("Домен уже указывает на сервер, а TCP 80/443 разрешены у провайдера", false)
	if err != nil {
		return err
	}
	if !ready {
		return errors.New("выполните показанные ручные шаги; параметры сохранены, поэтому мастер можно продолжить позже")
	}

	_, _ = fmt.Fprintln(ui.out, "Серверный config и sudoers должны быть обновлены перед plan: панельный SSH-туннель разрешается только администратору и только к назначенному loopback-порту.")
	updateNow, err := ui.promptBool("Установить/обновить серверный компонент сейчас", true)
	if err != nil {
		return err
	}
	if !updateNow {
		return errors.New("сначала выполните «Установить/обновить», затем вернитесь в мастер")
	}
	if err := ui.install(item); err != nil {
		return err
	}
	item, err = ui.control.Store.Server(item.ID)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(ui.out, "Проверяю полный план базовой политики перед установкой сервиса…")
	plan, planErr := ui.control.RunAction(ui.ctx, item.ID, "plan", false)
	if planErr != nil {
		return planErr
	}
	if err := ui.printOperation(plan); err != nil {
		return err
	}
	if plan.Report.HasFailures() {
		return errors.New("базовый plan содержит ошибки; порты не открыты")
	}
	if reportHasPlanned(plan.Report) {
		expected := "APPLY PORTS " + item.ID
		confirmation, err := ui.prompt("Чтобы применить весь показанный план и открыть 80/443, введите "+expected, "")
		if err != nil {
			return err
		}
		if confirmation != expected {
			return errors.New("применение политики отменено")
		}
		applied, applyErr := ui.control.RunAction(ui.ctx, item.ID, "apply", true)
		if applyErr != nil {
			return applyErr
		}
		if err := ui.printOperation(applied); err != nil {
			return err
		}
		if applied.Report.HasFailures() {
			return errors.New("базовая политика применена с ошибками; установка сервиса остановлена")
		}
	} else {
		_, _ = fmt.Fprintln(ui.out, "Базовая политика уже соответствует желаемому состоянию; повторный apply не требуется.")
	}

	_, _ = fmt.Fprintln(ui.out, "Выполняю read-only preflight 3x-ui, DNS, ресурсов, listeners и firewall…")
	workloadPlan, err := ui.control.RunWorkload(ui.ctx, item.ID, workload.XHTTPModule, "plan", setup, false)
	if err != nil {
		return err
	}
	if err := ui.printOperation(workloadPlan); err != nil {
		return err
	}
	if workloadPlan.Report.HasFailures() {
		return errors.New("XHTTP preflight содержит ошибки; сервер не изменён")
	}
	expected := "INSTALL XHTTP " + item.ID
	confirmation, err := ui.prompt("Для установки введите "+expected, "")
	if err != nil {
		return err
	}
	if confirmation != expected {
		return errors.New("установка отменена")
	}
	installed, err := ui.control.RunWorkload(ui.ctx, item.ID, workload.XHTTPModule, "apply", setup, true)
	if err != nil {
		return err
	}
	if err := ui.printOperation(installed); err != nil {
		return err
	}
	if installed.Report.HasFailures() {
		return errors.New("установка завершилась с ошибками; проверьте отчёт и путь backup")
	}
	ui.printXHTTPGuide(item, setup)
	return nil
}

func reportHasPlanned(value *report.Report) bool {
	if value == nil {
		return false
	}
	for _, result := range value.Results {
		if result.Status == report.Planned {
			return true
		}
	}
	return false
}

func (ui *UI) verifyXHTTP(item state.ManagedServer, setup workload.XHTTPConfig) error {
	_, _ = fmt.Fprintln(ui.out, "Проверяю marker, версию, systemd, loopback-панель, TLS, UFW и listener 443…")
	result, err := ui.control.RunWorkload(ui.ctx, item.ID, workload.XHTTPModule, "verify", setup, false)
	if err != nil {
		return err
	}
	return ui.printOperation(result)
}

func (ui *UI) printXHTTPGuide(item state.ManagedServer, setup workload.XHTTPConfig) {
	_, _ = fmt.Fprintln(ui.out, "\nЧто пользователь выполняет самостоятельно:")
	ui.printManualSteps(workload.ManualGuide(setup, item.Target, item.Identity, item.Port, xhttpLocalTunnelPort))
	_, _ = fmt.Fprintln(ui.out, "Панельный порт намеренно не публикуется. Не добавляйте его в UFW или firewall провайдера.")
}

func (ui *UI) printManualSteps(steps []workload.ManualStep) {
	for index, step := range steps {
		_, _ = fmt.Fprintf(ui.out, "\n%d. %s\n", index+1, step.Title)
		for _, detail := range step.Details {
			_, _ = fmt.Fprintln(ui.out, "   -", detail)
		}
	}
}
