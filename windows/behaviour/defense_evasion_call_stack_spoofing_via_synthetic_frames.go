//go:build windows
// +build windows

/*
ID: d8c57cb7-bab6-41fa-9063-dcc8793c3955
NAME: Call Stack Spoofing via Synthetic Frames
CREATED: 2024-06-27
scenario: API calls within altered call stack 
*/
package main

import (
	"syscall"
	"time"

	Endpoint "github.com/preludeorg/test/endpoint"
)

var supported = map[string][]string{
	"windows": {"cmd", "/C", "notepad.exe"},
}

/*
execute benign command to mimic behaviour
use `syscall` package to load `kernel32.dll` and call `CreateFileW`
this mimics API call with potentially altered stack
*/
func test() {
	Endpoint.Say("testing call stack spoofing...")

	command := supported[Endpoint.GetOS()]
	_, err := Endpoint.Shell(command)
	if err != nil {
		Endpoint.Say("error executing command: " + err.Error())
		Endpoint.Stop(1)
		return
	}

	// mimic API call
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	createFile := kernel32.NewProc("CreateFileW")
	_, _, err = createFile.Call(0, 0, 0, 0, 0, 0, 0)
	if err != nil && err.Error() != "The operation completed successfully." {
		Endpoint.Say("error calling CreateFileW: " + err.Error())
		Endpoint.Stop(1)
		return
	}
	Endpoint.Say("call stack spoofing completed")
	Endpoint.Stop(101) // unprotected
}

func cleanup() {
	Endpoint.Say("cleaning up...")
	command := supported[Endpoint.GetOS()]
	Endpoint.Shell(command)
}

func main() {
	Endpoint.Start(test, cleanup)
}