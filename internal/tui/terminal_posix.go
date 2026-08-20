//go:build linux || darwin

package tui

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

type posixState struct {
	input    *os.File
	original string
}

func openPlatform(input, output *os.File) (platformState, int, int, error) {
	if !characterDevice(input) || !characterDevice(output) {
		return nil, 0, 0, errors.New("stdin/stdout не являются терминалом")
	}
	original, err := sttyOutput(input, "-g")
	if err != nil || strings.TrimSpace(original) == "" {
		return nil, 0, 0, errors.New("не удалось прочитать режим терминала")
	}
	rows, columns := 24, 80
	if size, sizeErr := sttyOutput(input, "size"); sizeErr == nil {
		_, _ = fmt.Sscanf(size, "%d %d", &rows, &columns)
	}
	if columns < 20 {
		columns = 80
	}
	if rows < 10 {
		rows = 24
	}
	if err := runStty(input, "raw", "-echo"); err != nil {
		return nil, 0, 0, err
	}
	return &posixState{input: input, original: strings.TrimSpace(original)}, columns, rows, nil
}

func (s *posixState) Restore() error {
	if s.original == "" {
		return nil
	}
	err := runStty(s.input, s.original)
	s.original = ""
	return err
}

func characterDevice(file *os.File) bool {
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func sttyOutput(input *os.File, args ...string) (string, error) {
	command := exec.Command("stty", args...)
	command.Stdin = input
	command.Stderr = io.Discard
	data, err := command.Output()
	return strings.TrimSpace(string(data)), err
}

func runStty(input *os.File, args ...string) error {
	command := exec.Command("stty", args...)
	command.Stdin = input
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	return command.Run()
}
