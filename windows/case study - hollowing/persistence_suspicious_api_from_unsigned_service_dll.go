//go:build windows
// +build windows

/*
ID: 1a16b12e-6719-4f58-8835-84880092f3a0
NAME: Suspicious API from an Unsigned Service DLL
CREATED: 2024-07-02
scenario: execution of a new service via unsigned ServiceDLL subsequently followed by suspicious Windows API calls.
Adversaries may use this technique to maintain persistence or run with System privileges.
*/
package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	Endpoint "github.com/preludeorg/test/endpoint"
	"golang.org/x/sys/windows"
)

var serviceDLLPath = "C:\\Windows\\Temp\\suspicious.dll"

func main() {
	Endpoint.Say("[+] Starting Suspicious API from an Unsigned Service DLL VST")
	Endpoint.Start(test, cleanup)
}

func test() {
	// create new unsigned DLL
	dllContent := []byte("test DLL file")
	err := os.WriteFile(serviceDLLPath, dllContent, 0644)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to create DLL file: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	Endpoint.Say("[+] Unsigned DLL file created")

	// load DLL into svchost.exe
	cmd := exec.Command("rundll32.exe", serviceDLLPath+",ServiceMain")
	err = cmd.Start()
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to load DLL into svchost.exe: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	Endpoint.Say("[+] DLL loaded into svchost.exe")
	time.Sleep(3 * time.Second)
	// Simulate suspicious API calls
	simulateSuspiciousAPICalls()

	Endpoint.Stop(101) // UNPROTECTED: Malicious behavior not blocked
}

func simulateSuspiciousAPICalls() {
	// WriteProcessMemory call
	var kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	var procWriteProcessMemory = kernel32.NewProc("WriteProcessMemory")
	processHandle, err := windows.OpenProcess(windows.PROCESS_ALL_ACCESS, false. uint32(os.Getpid()))
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to open process: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	var written uint32
	buffer := []byte("memorywrite")
	addr := uintptr(0x00000001)
	ret, _, err := procWriteProcessMemory.Call(uintptr(processHandle), addr, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), uintptr(unsafe.Pointer(&written)))
	if ret == 0 {
		Endpoint.Say(fmt.Sprintf("[-] WriteProcessMemory failed: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	Endpoint.Say("[+] WriteProcessMemory executed successfully")

	// Simulate VirtualProtectEx call
	var oldProtect uint32
	addr = uintptr(0x00000001)
	size := uintptr(1024)
	newProtect := uint32(windows.PAGE_EXECUTE_READWRITE)
	ret, _, err = syscall.Syscall6(procWriteProcessMemory.Addr(), 5, uintptr(processHandle), addr, size, uintptr(newProtect), uintptr(unsafe.Pointer(&oldProtect)), 0)
	if ret == 0 {
		Endpoint.Say(fmt.Sprintf("[-] VirtualProtectEx failed: %s", err))
		Endpoint.Stop(1) // ERROR
	}
	Endpoint.Say("[+] VirtualProtectEx executed successfully")
}
func cleanup() {
	// Remove the created DLL file
	err := os.Remove(serviceDLLPath)
	if err != nil {
		Endpoint.Say(fmt.Sprintf("[-] Failed to remove DLL file: %s", err))
		Endpoint.Stop(103) // Cleanup failed
	}
	Endpoint.Say("[+] DLL file removed")

	Endpoint.Stop(100) // PROTECTED
}