package tui

import (
	"bufio"
	"strings"
	"testing"
)

func testOptions() []Option {
	return []Option{
		{ID: 1, Label: "Список серверов", Group: "СЕРВЕРЫ"},
		{ID: 2, Label: "Добавить сервер", Group: "СЕРВЕРЫ"},
		{ID: 4, Label: "Аудит", Group: "ЗАЩИТА"},
		{ID: 5, Label: "План", Group: "ЗАЩИТА"},
		{ID: 8, Label: "Настроить", Group: "УПРАВЛЕНИЕ"},
		{ID: 9, Label: "История", Group: "УПРАВЛЕНИЕ"},
		{ID: 0, Label: "Выход"},
	}
}

func TestMenuColumnBreakpoints(t *testing.T) {
	if got := menuColumns(120, 3); got != 3 {
		t.Fatalf("wide columns=%d", got)
	}
	if got := menuColumns(80, 3); got != 2 {
		t.Fatalf("medium columns=%d", got)
	}
	if got := menuColumns(50, 3); got != 1 {
		t.Fatalf("narrow columns=%d", got)
	}
}

func TestPlainMenuKeepsGroupsAndExit(t *testing.T) {
	menu := RenderPlain(testOptions(), 120)
	for _, expected := range []string{"СЕРВЕРЫ", "ЗАЩИТА", "УПРАВЛЕНИЕ", "[ 0] Выход"} {
		if !strings.Contains(menu, expected) {
			t.Fatalf("menu lacks %q:\n%s", expected, menu)
		}
	}
}

func TestMouseAndKeyboardEvents(t *testing.T) {
	mouse, err := readEvent(bufio.NewReader(strings.NewReader("\x1b[<0;17;9M")))
	if err != nil || mouse.kind != eventClick || mouse.x != 17 || mouse.y != 9 {
		t.Fatalf("mouse=%+v err=%v", mouse, err)
	}
	up, err := readEvent(bufio.NewReader(strings.NewReader("\x1b[A")))
	if err != nil || up.kind != eventPrevious {
		t.Fatalf("up=%+v err=%v", up, err)
	}
	digit, err := readEvent(bufio.NewReader(strings.NewReader("1")))
	if err != nil || digit.kind != eventDigit || digit.digit != '1' {
		t.Fatalf("digit=%+v err=%v", digit, err)
	}
}

func TestHitboxesUseRenderedCoordinates(t *testing.T) {
	_, boxes, _ := renderGrid(testOptions(), 120, 6, 1, false)
	if len(boxes) != len(testOptions()) {
		t.Fatalf("boxes=%d options=%d", len(boxes), len(testOptions()))
	}
	first := boxes[0]
	if id, ok := clickedOption(boxes, first.x1, first.y); !ok || id != 1 {
		t.Fatalf("clicked id=%d ok=%v", id, ok)
	}
}
