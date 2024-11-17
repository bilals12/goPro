//go:build windows
// +build windows

/*
ID: 1e9ac3fe-edb4-d669-71ab-220acc092982
NAME: .NET COM object created in non-standard Windows Script Interpreter
CREATED: 2024-07-02
scenario: creation of a .NET COM object in an unexpected Windows script interpreter. Adversaries may utilise .NET
to call arbitrary Win32 APIs from scripts.
*/
package main

import (
	"fmt"
	"os"
	"os/exec"
	"unsafe"

	Endpoint "github.com/preludeorg/test/endpoint"
	"golang.org/x/sys/windows"
)

var scriptPath = "C:\\Windows\\Temp\\suspiciousScript.vbs"

func main() {
	Endpoint.Say("[+] Starting .NET COM object created in non-standard Windows Script Interpreter VST")
	Endpoint.Start(test, cleanup)
}

func test() {
	// create new VBS script file
	scriptContent := `
	Set obj = CreateObject("WScript.Shell)
	obj.Run "notepad.exe"
	`
	err := os.WriteFile(scriptPath, []byte(scriptContent), 0644)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to create script file: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	Endpoint.Say("[+] VBS script file created")

	// execute VBS script with wscript.exe
	cmd := exec.Command("wscript.exe", scriptPath)
	err = cmd.Start()
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to execute script: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	Endpoint.Say("[+] Script executed successfully")
	// Simulate .NET COM object creation and suspicious API call
	simulateDotNetCOMObjectCreation()

	Endpoint.Stop(101) // UNPROTECTED: Malicious behavior not blocked
}

func simulateDotNetCOMObjectCreation() {
	// Simulate the creation of a .NET COM object in an unexpected script interpreter

	// Allocate executable memory
	kernel32 := windows.NewLazyDLL("kernel32.dll")
	procVirtualAlloc := kernel32.NewProc("VirtualAlloc")
	addr, _, err := procVirtualAlloc.Call(0, uintptr(4096), windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_EXECUTE_READWRITE)
	if addr == 0 {
		Endpoint.Say(fmt.Sprintf("[-] VirtualAlloc failed: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	Endpoint.Say("[+] VirtualAlloc executed successfully")

	// Write shellcode to allocated memory
	shellcode := []byte{0x90, 0x90, 0x90, 0x90} // NOP instructions (for demonstration)
	procWriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	processHandle, err := windows.GetCurrentProcess()
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to get current process handle: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	var written uintptr
	ret, _, err := procWriteProcessMemory.Call(uintptr(processHandle), addr, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), uintptr(unsafe.Pointer(&written)))
	if ret == 0 {
		Endpoint.Say(fmt.Sprintf("[-] WriteProcessMemory failed: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	Endpoint.Say("[+] WriteProcessMemory executed successfully")
}

func cleanup() {
	// Remove the created script file
	err := os.Remove(scriptPath)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to remove script file: %s", err))
		Endpoint.Stop(103) // Cleanup failed
	}
	Endpoint.Say("[+] Script file removed")

	Endpoint.Stop(100) // PROTECTED
}