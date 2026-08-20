package console

import (
	"fmt"
	"strconv"
	"strings"

	"bastionctl/internal/state"
	"bastionctl/internal/tui"
)

type menuCommand struct {
	id      int
	label   string
	group   string
	aliases []string
	run     func()
}

func (ui *UI) menuCommands() []menuCommand {
	return []menuCommand{
		{id: 1, label: "Список и выбор сервера", group: "СЕРВЕРЫ", aliases: []string{"servers", "select"}, run: func() { ui.runSafely(ui.selectServer) }},
		{id: 2, label: "Добавить сервер", group: "СЕРВЕРЫ", aliases: []string{"add"}, run: func() { ui.runSafely(ui.addServer) }},
		{id: 3, label: "Установить/обновить", group: "СЕРВЕРЫ", aliases: []string{"install"}, run: func() { ui.runWithServer(ui.install) }},
		{id: 13, label: "Первичный SSH-вход", group: "СЕРВЕРЫ", aliases: []string{"bootstrap"}, run: func() { ui.runWithServer(ui.bootstrap) }},

		{id: 4, label: "Аудит", group: "ЗАЩИТА", aliases: []string{"audit"}, run: func() { ui.runWithServer(func(item state.ManagedServer) error { return ui.action(item, "audit") }) }},
		{id: 5, label: "План изменений", group: "ЗАЩИТА", aliases: []string{"plan"}, run: func() { ui.runWithServer(func(item state.ManagedServer) error { return ui.action(item, "plan") }) }},
		{id: 6, label: "Применить защиту", group: "ЗАЩИТА", aliases: []string{"apply"}, run: func() { ui.runWithServer(ui.apply) }},
		{id: 7, label: "Снимок и поиск drift", group: "ЗАЩИТА", aliases: []string{"snapshot", "drift"}, run: func() { ui.runWithServer(ui.snapshot) }},
		{id: 15, label: "Сбросить политику", group: "ЗАЩИТА", aliases: []string{"reset"}, run: func() { ui.runWithServer(ui.resetPolicy) }},

		{id: 8, label: "Настроить политику", group: "УПРАВЛЕНИЕ", aliases: []string{"configure", "config"}, run: func() { ui.runWithServer(ui.configure) }},
		{id: 9, label: "История отчётов", group: "УПРАВЛЕНИЕ", aliases: []string{"history"}, run: func() { ui.runWithServer(ui.history) }},
		{id: 10, label: "Аудит всех серверов", group: "УПРАВЛЕНИЕ", aliases: []string{"all"}, run: func() { ui.runSafely(ui.auditAll) }},
		{id: 11, label: "Объяснить контроль", group: "УПРАВЛЕНИЕ", aliases: []string{"explain"}, run: func() { ui.runSafely(ui.explain) }},
		{id: 12, label: "Удалить из реестра", group: "УПРАВЛЕНИЕ", aliases: []string{"remove"}, run: func() { ui.runWithServer(ui.remove) }},
		{id: 14, label: "Создать SSH-пользователя", group: "УПРАВЛЕНИЕ", aliases: []string{"user", "user-add"}, run: func() { ui.runWithServer(ui.createUser) }},

		{id: 0, label: "Выход", aliases: []string{"q", "quit", "exit"}},
	}
}

func (ui *UI) chooseCommand(commands []menuCommand) (menuCommand, bool, error) {
	options := make([]tui.Option, len(commands))
	for index, command := range commands {
		options[index] = tui.Option{ID: command.id, Label: command.label, Group: command.group}
	}
	selected := "не выбран"
	if ui.selected != "" {
		selected = ui.selected
	}
	id, interactive, err := tui.Select(
		ui.reader,
		ui.input,
		ui.out,
		fmt.Sprintf("bastionctl %s — панель администратора", ui.control.Version),
		"Выбранный сервер: "+selected,
		options,
		ui.menuFocus,
	)
	if err != nil {
		return menuCommand{}, false, err
	}
	if interactive {
		ui.menuFocus = id
		command, ok := findMenuCommand(commands, strconv.Itoa(id))
		if !ok {
			return menuCommand{}, false, fmt.Errorf("TUI вернул неизвестную команду %d", id)
		}
		return command, true, nil
	}

	_, _ = fmt.Fprintf(ui.out, "\nВыбранный сервер: %s\n%s\n", selected, tui.RenderPlain(options, 110))
	choice, err := ui.prompt("Команда", "")
	if err != nil {
		return menuCommand{}, false, err
	}
	command, ok := findMenuCommand(commands, choice)
	if !ok && strings.TrimSpace(choice) != "" {
		_, _ = fmt.Fprintf(ui.errOut, "Неизвестная команда %q; выберите номер 0–15.\n", strings.TrimSpace(choice))
	}
	return command, ok, nil
}

func findMenuCommand(commands []menuCommand, value string) (menuCommand, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return menuCommand{}, false
	}
	for _, command := range commands {
		if value == strconv.Itoa(command.id) {
			return command, true
		}
		for _, alias := range command.aliases {
			if value == alias {
				return command, true
			}
		}
	}
	return menuCommand{}, false
}
