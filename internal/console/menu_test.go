package console

import "testing"

func TestMenuRegistryHasOneCommandPerID(t *testing.T) {
	commands := (&UI{}).menuCommands()
	seen := map[int]bool{}
	for _, command := range commands {
		if seen[command.id] {
			t.Fatalf("duplicate command id %d", command.id)
		}
		seen[command.id] = true
		if command.label == "" {
			t.Fatalf("command %d has no label", command.id)
		}
		if command.id != 0 && (command.group == "" || command.run == nil) {
			t.Fatalf("command %d lacks group or handler", command.id)
		}
	}
	for id := 0; id <= 16; id++ {
		if !seen[id] {
			t.Fatalf("command id %d is missing", id)
		}
	}
}

func TestMenuRegistryKeepsNumbersAndAliasesEquivalent(t *testing.T) {
	commands := (&UI{}).menuCommands()
	byNumber, ok := findMenuCommand(commands, "14")
	if !ok {
		t.Fatal("command 14 not found")
	}
	byAlias, ok := findMenuCommand(commands, "user-add")
	if !ok || byAlias.id != byNumber.id {
		t.Fatalf("number=%d alias=%d ok=%v", byNumber.id, byAlias.id, ok)
	}
	xhttp, ok := findMenuCommand(commands, "3x-ui")
	if !ok || xhttp.id != 16 {
		t.Fatalf("xhttp=%d ok=%v", xhttp.id, ok)
	}
	exit, ok := findMenuCommand(commands, "q")
	if !ok || exit.id != 0 {
		t.Fatalf("exit=%d ok=%v", exit.id, ok)
	}
}
