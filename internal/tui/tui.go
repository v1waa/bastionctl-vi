package tui

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// Option is one selectable console command. Group is used to build stable,
// responsive columns without coupling terminal rendering to application logic.
type Option struct {
	ID    int
	Label string
	Group string
}

type platformState interface {
	Restore() error
}

type session struct {
	output io.Writer
	state  platformState
	width  int
	height int
	closed bool
}

type eventKind int

const (
	eventNone eventKind = iota
	eventDigit
	eventEnter
	eventBackspace
	eventPrevious
	eventNext
	eventClick
	eventQuit
)

type event struct {
	kind  eventKind
	digit byte
	x     int
	y     int
}

type hitbox struct {
	id     int
	x1, x2 int
	y      int
}

type menuGroup struct {
	name    string
	options []Option
}

type cell struct {
	text string
	id   int
	item bool
}

const enterScreen = "\x1b[?1049h\x1b[2J\x1b[H\x1b[?25l\x1b[?1000h\x1b[?1006h"
const leaveScreen = "\x1b[?1006l\x1b[?1000l\x1b[?25h\x1b[?1049l"

// Select opens a temporary full-screen menu when input and output are real
// terminals. The bool result is false when the caller should use its line-mode
// fallback. Mouse, arrows plus Enter, and a number plus Enter are equivalent.
func Select(reader *bufio.Reader, input io.Reader, output io.Writer, title, subtitle string, options []Option, initialID int) (selectedID int, interactive bool, resultErr error) {
	inputFile, inputOK := input.(*os.File)
	outputFile, outputOK := output.(*os.File)
	if !inputOK || !outputOK || len(options) == 0 {
		return 0, false, nil
	}
	state, width, height, err := openPlatform(inputFile, outputFile)
	if err != nil {
		return 0, false, nil
	}
	s := &session{output: output, state: state, width: width, height: height}
	if _, err := io.WriteString(output, enterScreen); err != nil {
		return 0, true, errors.Join(err, state.Restore())
	}
	defer func() {
		resultErr = errors.Join(resultErr, s.Close())
	}()

	selected := optionIndex(options, initialID)
	if selected < 0 {
		selected = firstNonExit(options)
	}
	digits := ""
	for {
		boxes, err := renderScreen(output, title, subtitle, options, options[selected].ID, digits, width, height)
		if err != nil {
			return 0, true, err
		}
		inputEvent, err := readEvent(reader)
		if err != nil {
			return 0, true, err
		}
		switch inputEvent.kind {
		case eventDigit:
			if len(digits) < 3 {
				digits += string(inputEvent.digit)
			}
		case eventBackspace:
			if len(digits) > 0 {
				digits = digits[:len(digits)-1]
			}
		case eventPrevious:
			digits = ""
			selected = (selected - 1 + len(options)) % len(options)
		case eventNext:
			digits = ""
			selected = (selected + 1) % len(options)
		case eventEnter:
			if digits != "" {
				value, convertErr := strconv.Atoi(digits)
				if convertErr == nil && optionIndex(options, value) >= 0 {
					return value, true, nil
				}
				digits = ""
				continue
			}
			return options[selected].ID, true, nil
		case eventClick:
			if id, ok := clickedOption(boxes, inputEvent.x, inputEvent.y); ok {
				return id, true, nil
			}
		case eventQuit:
			if optionIndex(options, 0) >= 0 {
				return 0, true, nil
			}
			return options[selected].ID, true, nil
		}
	}
}

// RenderPlain uses the same grouping and column allocation as the mouse UI,
// keeping redirected input and terminals without mouse reporting fully usable.
func RenderPlain(options []Option, width int) string {
	lines, _, _ := renderGrid(options, width, 1, -1, false)
	return strings.Join(lines, "\n")
}

func (s *session) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	_, writeErr := io.WriteString(s.output, leaveScreen)
	restoreErr := s.state.Restore()
	return errors.Join(writeErr, restoreErr)
}

func renderScreen(output io.Writer, title, subtitle string, options []Option, selectedID int, digits string, width, height int) ([]hitbox, error) {
	if width < 20 {
		width = 20
	}
	inputValue := "—"
	if digits != "" {
		inputValue = digits
	}
	header := []string{
		fit(title, width),
		fit(subtitle, width),
		fit("Мышь: нажмите пункт · Клавиатура: ↑/↓ и Enter · Номер: цифры и Enter · q: выход", width),
		fit("Ввод номера: "+inputValue, width),
		strings.Repeat("─", width),
	}
	lines, boxes, gridHeight := renderGrid(options, width, 6, selectedID, true)
	var screen strings.Builder
	screen.WriteString("\x1b[H\x1b[2J")
	for _, line := range header {
		screen.WriteString(line)
		screen.WriteByte('\n')
	}
	for _, line := range lines {
		screen.WriteString(line)
		screen.WriteByte('\n')
	}
	if 6+gridHeight < height {
		screen.WriteString(fit("Выберите действие. После выбора обычный терминальный режим будет восстановлен.", width))
		screen.WriteByte('\n')
	}
	_, err := io.WriteString(output, screen.String())
	return boxes, err
}

func renderGrid(options []Option, width, startY, selectedID int, ansi bool) ([]string, []hitbox, int) {
	if width < 20 {
		width = 20
	}
	groups, exit, hasExit := splitGroups(options)
	columnsCount := menuColumns(width, len(groups))
	columns := allocateGroups(groups, columnsCount)
	gap := 2
	margin := 2
	usable := width - margin - gap*(columnsCount-1)
	if usable < columnsCount {
		usable = columnsCount
	}
	columnWidth := usable / columnsCount
	maxRows := 0
	for _, column := range columns {
		if len(column) > maxRows {
			maxRows = len(column)
		}
	}
	lines := make([]string, 0, maxRows+2)
	boxes := make([]hitbox, 0, len(options))
	for row := 0; row < maxRows; row++ {
		var line strings.Builder
		line.WriteString(strings.Repeat(" ", margin))
		for columnIndex := 0; columnIndex < columnsCount; columnIndex++ {
			current := cell{}
			if row < len(columns[columnIndex]) {
				current = columns[columnIndex][row]
			}
			plain := fit(current.text, columnWidth)
			if current.item {
				x1 := margin + columnIndex*(columnWidth+gap) + 1
				boxes = append(boxes, hitbox{id: current.id, x1: x1, x2: x1 + columnWidth - 1, y: startY + row})
				if ansi && current.id == selectedID {
					line.WriteString("\x1b[7m")
					line.WriteString(plain)
					line.WriteString("\x1b[0m")
				} else {
					line.WriteString(plain)
				}
			} else if ansi && strings.TrimSpace(plain) != "" {
				line.WriteString("\x1b[1m")
				line.WriteString(plain)
				line.WriteString("\x1b[0m")
			} else {
				line.WriteString(plain)
			}
			if columnIndex+1 < columnsCount {
				line.WriteString(strings.Repeat(" ", gap))
			}
		}
		lines = append(lines, strings.TrimRight(line.String(), " "))
	}
	if hasExit {
		lines = append(lines, "")
		exitY := startY + len(lines)
		text := fit(optionText(exit), width-margin)
		plain := strings.Repeat(" ", margin) + text
		if ansi && exit.ID == selectedID {
			plain = strings.Repeat(" ", margin) + "\x1b[7m" + text + "\x1b[0m"
		}
		lines = append(lines, strings.TrimRight(plain, " "))
		boxes = append(boxes, hitbox{id: exit.ID, x1: margin + 1, x2: width, y: exitY})
	}
	return lines, boxes, len(lines)
}

func splitGroups(options []Option) ([]menuGroup, Option, bool) {
	groups := make([]menuGroup, 0, 3)
	index := map[string]int{}
	var exit Option
	hasExit := false
	for _, option := range options {
		if option.ID == 0 {
			exit, hasExit = option, true
			continue
		}
		name := option.Group
		if name == "" {
			name = "КОМАНДЫ"
		}
		groupIndex, ok := index[name]
		if !ok {
			groupIndex = len(groups)
			index[name] = groupIndex
			groups = append(groups, menuGroup{name: name})
		}
		groups[groupIndex].options = append(groups[groupIndex].options, option)
	}
	return groups, exit, hasExit
}

func allocateGroups(groups []menuGroup, count int) [][]cell {
	columns := make([][]cell, count)
	for index, group := range groups {
		column := 0
		switch count {
		case 1:
			column = 0
		case 2:
			if len(groups) >= 3 && index >= 2 {
				column = 1
			} else if len(groups) == 2 {
				column = index
			}
		default:
			if index < count {
				column = index
			} else {
				column = count - 1
			}
		}
		if len(columns[column]) > 0 {
			columns[column] = append(columns[column], cell{})
		}
		columns[column] = append(columns[column], cell{text: group.name})
		for _, option := range group.options {
			columns[column] = append(columns[column], cell{text: optionText(option), id: option.ID, item: true})
		}
	}
	return columns
}

func menuColumns(width, groups int) int {
	switch {
	case width >= 104 && groups >= 3:
		return 3
	case width >= 68 && groups >= 2:
		return 2
	default:
		return 1
	}
}

func optionText(option Option) string {
	return fmt.Sprintf("[%2d] %s", option.ID, option.Label)
}

func optionIndex(options []Option, id int) int {
	for index, option := range options {
		if option.ID == id {
			return index
		}
	}
	return -1
}

func firstNonExit(options []Option) int {
	for index, option := range options {
		if option.ID != 0 {
			return index
		}
	}
	return 0
}

func clickedOption(boxes []hitbox, x, y int) (int, bool) {
	for _, box := range boxes {
		if y == box.y && x >= box.x1 && x <= box.x2 {
			return box.id, true
		}
	}
	return 0, false
}

func fit(value string, width int) string {
	if width <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) > width {
		if width == 1 {
			return "…"
		}
		return string(runes[:width-1]) + "…"
	}
	return value + strings.Repeat(" ", width-len(runes))
}

func readEvent(reader *bufio.Reader) (event, error) {
	value, err := reader.ReadByte()
	if err != nil {
		return event{}, err
	}
	switch value {
	case '\r', '\n', ' ':
		return event{kind: eventEnter}, nil
	case 0x03, 'q', 'Q':
		return event{kind: eventQuit}, nil
	case 0x08, 0x7f:
		return event{kind: eventBackspace}, nil
	case 'k', 'K':
		return event{kind: eventPrevious}, nil
	case 'j', 'J', '\t':
		return event{kind: eventNext}, nil
	case 0x1b:
		return readEscapeEvent(reader)
	default:
		if value >= '0' && value <= '9' {
			return event{kind: eventDigit, digit: value}, nil
		}
		return event{kind: eventNone}, nil
	}
}

func readEscapeEvent(reader *bufio.Reader) (event, error) {
	prefix, err := reader.ReadByte()
	if err != nil {
		return event{}, err
	}
	if prefix != '[' && prefix != 'O' {
		return event{kind: eventNone}, nil
	}
	code, err := reader.ReadByte()
	if err != nil {
		return event{}, err
	}
	switch code {
	case 'A', 'D':
		return event{kind: eventPrevious}, nil
	case 'B', 'C':
		return event{kind: eventNext}, nil
	case '<':
		return readMouseEvent(reader)
	default:
		return event{kind: eventNone}, nil
	}
}

func readMouseEvent(reader *bufio.Reader) (event, error) {
	sequence := make([]byte, 0, 24)
	for len(sequence) < 64 {
		value, err := reader.ReadByte()
		if err != nil {
			return event{}, err
		}
		if value == 'M' || value == 'm' {
			if value == 'm' {
				return event{kind: eventNone}, nil
			}
			parts := strings.Split(string(sequence), ";")
			if len(parts) != 3 {
				return event{kind: eventNone}, nil
			}
			button, buttonErr := strconv.Atoi(parts[0])
			x, xErr := strconv.Atoi(parts[1])
			y, yErr := strconv.Atoi(parts[2])
			if buttonErr != nil || xErr != nil || yErr != nil || x < 1 || y < 1 {
				return event{kind: eventNone}, nil
			}
			if button&64 != 0 {
				if button&1 == 0 {
					return event{kind: eventPrevious}, nil
				}
				return event{kind: eventNext}, nil
			}
			if button&3 == 0 {
				return event{kind: eventClick, x: x, y: y}, nil
			}
			return event{kind: eventNone}, nil
		}
		sequence = append(sequence, value)
	}
	return event{kind: eventNone}, nil
}
