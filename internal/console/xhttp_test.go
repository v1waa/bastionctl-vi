package console

import (
	"bufio"
	"bytes"
	"context"
	"strings"
	"testing"

	"bastionctl/internal/controller"
	"bastionctl/internal/report"
)

func TestXHTTPWizardSavesConfigAndKeepsLineMode(t *testing.T) {
	control, err := controller.New("test", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	item, err := control.AddServer(controller.AddOptions{
		ID: "edge", Name: "Edge", Target: "ops@203.0.113.10", Port: 2222,
	})
	if err != nil {
		t.Fatal(err)
	}
	input := strings.NewReader("vpn.example.com\nadmin@example.com\n203.0.113.10\n24443\n")
	var output bytes.Buffer
	ui := &UI{
		ctx: context.Background(), control: control, input: input,
		reader: bufio.NewReader(input), out: &output, errOut: &output,
	}
	setup, err := ui.editXHTTPConfig(item, nil)
	if err != nil {
		t.Fatal(err)
	}
	if setup.Domain != "vpn.example.com" || setup.PanelPort != 24443 {
		t.Fatalf("unexpected setup: %+v", setup)
	}
	loaded, err := control.LoadXHTTPConfig(item.ID)
	if err != nil || loaded != setup {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
	if !strings.Contains(output.String(), "Панель будет слушать только 127.0.0.1") {
		t.Fatalf("safety guidance missing:\n%s", output.String())
	}

	menuInput := strings.NewReader("3\n")
	ui.input = menuInput
	ui.reader = bufio.NewReader(menuInput)
	choice, err := ui.chooseXHTTPAction(item, setup)
	if err != nil || choice != 3 {
		t.Fatalf("choice=%d err=%v", choice, err)
	}
}

func TestReportHasPlanned(t *testing.T) {
	value := report.New("test", "server", "plan", "localhost")
	if reportHasPlanned(value) {
		t.Fatal("empty report has planned changes")
	}
	value.Add(report.Result{Control: "firewall", Status: report.Planned})
	if !reportHasPlanned(value) {
		t.Fatal("planned firewall change was ignored")
	}
}
