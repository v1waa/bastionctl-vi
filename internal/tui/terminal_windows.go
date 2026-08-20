//go:build windows

package tui

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

const (
	enableProcessedInput            = 0x0001
	enableLineInput                 = 0x0002
	enableEchoInput                 = 0x0004
	enableWindowInput               = 0x0008
	enableMouseInput                = 0x0010
	enableQuickEditMode             = 0x0040
	enableExtendedFlags             = 0x0080
	enableVirtualTerminalInput      = 0x0200
	enableProcessedOutput           = 0x0001
	enableVirtualTerminalProcessing = 0x0004
)

var kernel32 = syscall.NewLazyDLL("kernel32.dll")
var getConsoleMode = kernel32.NewProc("GetConsoleMode")
var setConsoleMode = kernel32.NewProc("SetConsoleMode")
var getConsoleScreenBufferInfo = kernel32.NewProc("GetConsoleScreenBufferInfo")

type windowsState struct {
	input      syscall.Handle
	output     syscall.Handle
	inputMode  uint32
	outputMode uint32
	restored   bool
}

type coordinate struct {
	X int16
	Y int16
}

type smallRectangle struct {
	Left   int16
	Top    int16
	Right  int16
	Bottom int16
}

type consoleScreenBufferInfo struct {
	Size              coordinate
	CursorPosition    coordinate
	Attributes        uint16
	Window            smallRectangle
	MaximumWindowSize coordinate
}

func openPlatform(input, output *os.File) (platformState, int, int, error) {
	inputHandle := syscall.Handle(input.Fd())
	outputHandle := syscall.Handle(output.Fd())
	inputMode, err := consoleMode(inputHandle)
	if err != nil {
		return nil, 0, 0, err
	}
	outputMode, err := consoleMode(outputHandle)
	if err != nil {
		return nil, 0, 0, err
	}
	newInput := inputMode | enableExtendedFlags | enableWindowInput | enableMouseInput | enableVirtualTerminalInput
	newInput &^= enableProcessedInput | enableLineInput | enableEchoInput | enableQuickEditMode
	if err := setMode(inputHandle, newInput); err != nil {
		return nil, 0, 0, err
	}
	newOutput := outputMode | enableProcessedOutput | enableVirtualTerminalProcessing
	if err := setMode(outputHandle, newOutput); err != nil {
		_ = setMode(inputHandle, inputMode)
		return nil, 0, 0, err
	}
	width, height := consoleSize(outputHandle)
	return &windowsState{input: inputHandle, output: outputHandle, inputMode: inputMode, outputMode: outputMode}, width, height, nil
}

func (s *windowsState) Restore() error {
	if s.restored {
		return nil
	}
	s.restored = true
	inputErr := setMode(s.input, s.inputMode)
	outputErr := setMode(s.output, s.outputMode)
	return errors.Join(inputErr, outputErr)
}

func consoleMode(handle syscall.Handle) (uint32, error) {
	var mode uint32
	result, _, callErr := getConsoleMode.Call(uintptr(handle), uintptr(unsafe.Pointer(&mode)))
	if result == 0 {
		return 0, windowsCallError(callErr)
	}
	return mode, nil
}

func setMode(handle syscall.Handle, mode uint32) error {
	result, _, callErr := setConsoleMode.Call(uintptr(handle), uintptr(mode))
	if result == 0 {
		return windowsCallError(callErr)
	}
	return nil
}

func consoleSize(handle syscall.Handle) (int, int) {
	var info consoleScreenBufferInfo
	result, _, _ := getConsoleScreenBufferInfo.Call(uintptr(handle), uintptr(unsafe.Pointer(&info)))
	if result == 0 {
		return 80, 24
	}
	width := int(info.Window.Right-info.Window.Left) + 1
	height := int(info.Window.Bottom-info.Window.Top) + 1
	if width < 20 {
		width = 80
	}
	if height < 10 {
		height = 24
	}
	return width, height
}

func windowsCallError(err error) error {
	if errno, ok := err.(syscall.Errno); ok && errno == 0 {
		return errors.New("Windows Console API вернул ошибку")
	}
	return err
}
